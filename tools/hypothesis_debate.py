#!/usr/bin/env python3
"""Hypothesis Debate System for Attack Surface Framework.

Multi-agent debate with hypothesis tracking, validation, and refutation.
Shows the reasoning process of each AI module.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import json


class HypothesisStatus(Enum):
    """Status of a hypothesis."""
    PROPOSED = "proposed"
    UNDER_REVIEW = "under_review"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    VALIDATED = "validated"
    INCONCLUSIVE = "inconclusive"


class AgentRole(Enum):
    """Agent roles in the debate."""
    RECON = "ReconAgent"
    VULN_HUNTER = "VulnHunterAgent"
    EXPLOIT_DEV = "ExploitDevAgent"
    POC_VALIDATOR = "PoCValidatorAgent"
    EVIDENCE = "EvidenceCollectorAgent"
    DEVIL_ADVOCATE = "DevilsAdvocateAgent"  # Challenges hypotheses


@dataclass
class Evidence:
    """Evidence supporting or refuting a hypothesis."""
    type: str  # "http_response", "timing", "error_message", "behavior_change"
    data: dict[str, Any]
    supports_hypothesis: bool
    confidence: float
    source_agent: AgentRole
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Hypothesis:
    """A hypothesis about a vulnerability."""
    id: str
    title: str
    description: str
    proposed_by: AgentRole
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = 0.5
    supporting_evidence: list[Evidence] = field(default_factory=list)
    refuting_evidence: list[Evidence] = field(default_factory=list)
    supporters: list[AgentRole] = field(default_factory=list)
    refuters: list[AgentRole] = field(default_factory=list)
    chain_potential: list[str] = field(default_factory=list)  # IDs of hypotheses this can chain with
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    resolved_at: Optional[str] = None
    
    def add_support(self, evidence: Evidence, agent: AgentRole):
        """Add supporting evidence."""
        self.supporting_evidence.append(evidence)
        if agent not in self.supporters:
            self.supporters.append(agent)
        self._recalculate_confidence()
        
    def add_refutation(self, evidence: Evidence, agent: AgentRole):
        """Add refuting evidence."""
        self.refuting_evidence.append(evidence)
        if agent not in self.refuters:
            self.refuters.append(agent)
        self._recalculate_confidence()
        
    def _recalculate_confidence(self):
        """Recalculate confidence based on evidence."""
        if not self.supporting_evidence and not self.refuting_evidence:
            self.confidence = 0.5
            return
            
        support_score = sum(e.confidence for e in self.supporting_evidence)
        refute_score = sum(e.confidence for e in self.refuting_evidence)
        
        total = support_score + refute_score
        if total > 0:
            self.confidence = support_score / total
        else:
            self.confidence = 0.5
            
        # Update status based on confidence
        if self.confidence >= 0.85 and len(self.supporting_evidence) >= 2:
            self.status = HypothesisStatus.VALIDATED
            self.resolved_at = datetime.now().isoformat()
        elif self.confidence <= 0.15 and len(self.refuting_evidence) >= 2:
            self.status = HypothesisStatus.REFUTED
            self.resolved_at = datetime.now().isoformat()
        elif len(self.supporting_evidence) > len(self.refuting_evidence):
            self.status = HypothesisStatus.SUPPORTED
        elif len(self.refuting_evidence) > len(self.supporting_evidence):
            self.status = HypothesisStatus.REFUTED
        else:
            self.status = HypothesisStatus.INCONCLUSIVE


@dataclass
class DebateMessage:
    """A message in the debate."""
    agent: AgentRole
    message_type: str  # "propose", "support", "refute", "question", "conclude"
    content: str
    hypothesis_id: Optional[str] = None
    evidence: Optional[Evidence] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class HypothesisDebateSystem:
    """Manages multi-agent debate for vulnerability validation."""
    
    def __init__(self, verbose: bool = True):
        self.hypotheses: dict[str, Hypothesis] = {}
        self.debate_log: list[DebateMessage] = []
        self.verbose = verbose
        self.hypothesis_counter = 0
        
    def _print(self, message: str, prefix: str = ""):
        """Print with formatting if verbose."""
        if self.verbose:
            # Handle Unicode on Windows
            try:
                print(f"{prefix}{message}")
            except UnicodeEncodeError:
                # Fall back to ASCII-safe output
                safe_msg = message.encode('ascii', errors='replace').decode('ascii')
                print(f"{prefix}{safe_msg}")
    
    def _generate_hypothesis_id(self) -> str:
        """Generate unique hypothesis ID."""
        self.hypothesis_counter += 1
        return f"H-{self.hypothesis_counter:03d}"
    
    def propose_hypothesis(
        self,
        title: str,
        description: str,
        proposed_by: AgentRole,
        initial_evidence: Optional[Evidence] = None
    ) -> Hypothesis:
        """Propose a new hypothesis."""
        hyp_id = self._generate_hypothesis_id()
        
        hypothesis = Hypothesis(
            id=hyp_id,
            title=title,
            description=description,
            proposed_by=proposed_by,
            status=HypothesisStatus.PROPOSED
        )
        
        if initial_evidence:
            hypothesis.add_support(initial_evidence, proposed_by)
        
        self.hypotheses[hyp_id] = hypothesis
        
        # Log the proposal
        self.debate_log.append(DebateMessage(
            agent=proposed_by,
            message_type="propose",
            content=f"I propose {title}: {description}",
            hypothesis_id=hyp_id,
            evidence=initial_evidence
        ))
        
        self._print_proposal(hypothesis, initial_evidence)
        
        return hypothesis
    
    def _print_proposal(self, hyp: Hypothesis, evidence: Optional[Evidence]):
        """Print hypothesis proposal."""
        self._print("")
        self._print("=" * 70)
        self._print(f"[NEW HYPOTHESIS] [{hyp.id}]", "")
        self._print("=" * 70)
        self._print(f"Proposed by: {hyp.proposed_by.value}", "  ")
        self._print(f"Title: {hyp.title}", "  ")
        self._print(f"Description: {hyp.description}", "  ")
        if evidence:
            self._print(f"Initial Evidence: {evidence.type} (confidence: {evidence.confidence:.0%})", "  ")
        self._print("")
    
    def support_hypothesis(
        self,
        hypothesis_id: str,
        agent: AgentRole,
        evidence: Evidence,
        reasoning: str
    ):
        """Add support to a hypothesis."""
        if hypothesis_id not in self.hypotheses:
            return
            
        hyp = self.hypotheses[hypothesis_id]
        hyp.add_support(evidence, agent)
        hyp.status = HypothesisStatus.UNDER_REVIEW
        
        self.debate_log.append(DebateMessage(
            agent=agent,
            message_type="support",
            content=reasoning,
            hypothesis_id=hypothesis_id,
            evidence=evidence
        ))
        
        self._print_support(hyp, agent, evidence, reasoning)
    
    def _print_support(self, hyp: Hypothesis, agent: AgentRole, evidence: Evidence, reasoning: str):
        """Print support message."""
        self._print("")
        self._print(f"[+] SUPPORT for [{hyp.id}] {hyp.title}", "")
        self._print("-" * 50)
        self._print(f"Agent: {agent.value}", "  ")
        self._print(f"Reasoning: {reasoning}", "  ")
        self._print(f"Evidence Type: {evidence.type}", "  ")
        self._print(f"Confidence: {evidence.confidence:.0%}", "  ")
        self._print(f"Hypothesis Confidence: {hyp.confidence:.0%}", "  ")
        self._print("")
    
    def refute_hypothesis(
        self,
        hypothesis_id: str,
        agent: AgentRole,
        evidence: Evidence,
        reasoning: str
    ):
        """Refute a hypothesis."""
        if hypothesis_id not in self.hypotheses:
            return
            
        hyp = self.hypotheses[hypothesis_id]
        hyp.add_refutation(evidence, agent)
        
        self.debate_log.append(DebateMessage(
            agent=agent,
            message_type="refute",
            content=reasoning,
            hypothesis_id=hypothesis_id,
            evidence=evidence
        ))
        
        self._print_refutation(hyp, agent, evidence, reasoning)
    
    def _print_refutation(self, hyp: Hypothesis, agent: AgentRole, evidence: Evidence, reasoning: str):
        """Print refutation message."""
        self._print("")
        self._print(f"[-] REFUTATION for [{hyp.id}] {hyp.title}", "")
        self._print("-" * 50)
        self._print(f"Agent: {agent.value}", "  ")
        self._print(f"Counter-argument: {reasoning}", "  ")
        self._print(f"Evidence Type: {evidence.type}", "  ")
        self._print(f"Confidence: {evidence.confidence:.0%}", "  ")
        self._print(f"Hypothesis Confidence: {hyp.confidence:.0%}", "  ")
        self._print("")
    
    def suggest_chain(
        self,
        hypothesis_id: str,
        chain_with_id: str,
        agent: AgentRole,
        reasoning: str
    ):
        """Suggest chaining two hypotheses."""
        if hypothesis_id not in self.hypotheses or chain_with_id not in self.hypotheses:
            return
            
        hyp = self.hypotheses[hypothesis_id]
        chain_hyp = self.hypotheses[chain_with_id]
        
        if chain_with_id not in hyp.chain_potential:
            hyp.chain_potential.append(chain_with_id)
        
        self.debate_log.append(DebateMessage(
            agent=agent,
            message_type="chain",
            content=reasoning,
            hypothesis_id=hypothesis_id
        ))
        
        self._print_chain_suggestion(hyp, chain_hyp, agent, reasoning)
    
    def _print_chain_suggestion(self, hyp1: Hypothesis, hyp2: Hypothesis, agent: AgentRole, reasoning: str):
        """Print chain suggestion."""
        self._print("")
        self._print(f"🔗 CHAIN SUGGESTION", "")
        self._print("-" * 50)
        self._print(f"Agent: {agent.value}", "  ")
        self._print(f"Chain [{hyp1.id}] → [{hyp2.id}]", "  ")
        self._print(f"  {hyp1.title} → {hyp2.title}", "  ")
        self._print(f"Reasoning: {reasoning}", "  ")
        self._print("")
    
    def devils_advocate_check(self, hypothesis_id: str) -> list[str]:
        """Devil's advocate challenges the hypothesis."""
        if hypothesis_id not in self.hypotheses:
            return []
            
        hyp = self.hypotheses[hypothesis_id]
        challenges = []
        
        # Generate challenges based on hypothesis type
        if "injection" in hyp.title.lower():
            challenges.extend([
                "Could this 200 response be a generic error page that always returns 200?",
                "Is the 'success' indicator actually user data or just page content?",
                "Does the response differ from a normal failed request?",
            ])
        
        if "jwt" in hyp.title.lower():
            challenges.extend([
                "Is the endpoint actually protected? Maybe it's public.",
                "Could the 200 response be a login redirect page?",
                "Is there actually sensitive data in the response?",
            ])
        
        if "auth" in hyp.title.lower():
            challenges.extend([
                "Could this be a honeypot response?",
                "Is the 'token' in response actually functional?",
                "Does the response grant actual elevated privileges?",
            ])
        
        # Add generic challenges
        challenges.extend([
            "What differentiates this from a false positive?",
            "Can this be reproduced consistently?",
            "Is there concrete evidence of exploitation, not just anomaly?",
        ])
        
        self._print("")
        self._print(f"[!] DEVIL'S ADVOCATE CHALLENGES [{hyp.id}]", "")
        self._print("-" * 50)
        for i, challenge in enumerate(challenges[:3], 1):
            self._print(f"{i}. {challenge}", "  ")
        self._print("")
        
        return challenges[:3]
    
    def evaluate_hypothesis(self, hypothesis_id: str) -> dict[str, Any]:
        """Final evaluation of a hypothesis."""
        if hypothesis_id not in self.hypotheses:
            return {"error": "Hypothesis not found"}
            
        hyp = self.hypotheses[hypothesis_id]
        
        # Determine final status
        if hyp.confidence >= 0.85:
            verdict = "VALIDATED"
            icon = "[+]"
        elif hyp.confidence >= 0.6:
            verdict = "LIKELY"
            icon = "[~]"
        elif hyp.confidence >= 0.4:
            verdict = "INCONCLUSIVE"
            icon = "[?]"
        elif hyp.confidence >= 0.2:
            verdict = "UNLIKELY"
            icon = "[*]"
        else:
            verdict = "REFUTED"
            icon = "[-]"
        
        evaluation = {
            "hypothesis_id": hyp.id,
            "title": hyp.title,
            "verdict": verdict,
            "confidence": hyp.confidence,
            "proposed_by": hyp.proposed_by.value,
            "supporters": [a.value for a in hyp.supporters],
            "refuters": [a.value for a in hyp.refuters],
            "supporting_evidence_count": len(hyp.supporting_evidence),
            "refuting_evidence_count": len(hyp.refuting_evidence),
            "chain_potential": hyp.chain_potential,
            "is_false_positive": verdict in ["REFUTED", "UNLIKELY"],
        }
        
        self._print_evaluation(hyp, evaluation, icon)
        
        return evaluation
    
    def _print_evaluation(self, hyp: Hypothesis, evaluation: dict, icon: str):
        """Print final evaluation."""
        self._print("")
        self._print("=" * 70)
        self._print(f"{icon} HYPOTHESIS EVALUATION [{hyp.id}]", "")
        self._print("=" * 70)
        self._print(f"Title: {hyp.title}", "  ")
        self._print(f"Verdict: {evaluation['verdict']}", "  ")
        self._print(f"Confidence: {evaluation['confidence']:.0%}", "  ")
        self._print(f"Proposed by: {evaluation['proposed_by']}", "  ")
        self._print(f"Supporters: {', '.join(evaluation['supporters']) or 'None'}", "  ")
        self._print(f"Refuters: {', '.join(evaluation['refuters']) or 'None'}", "  ")
        self._print(f"Evidence: {evaluation['supporting_evidence_count']} supporting, {evaluation['refuting_evidence_count']} refuting", "  ")
        if evaluation['chain_potential']:
            self._print(f"Chain Potential: {', '.join(evaluation['chain_potential'])}", "  ")
        if evaluation['is_false_positive']:
            self._print(f"[!] MARKED AS FALSE POSITIVE - Not included in final report", "  ")
        self._print("")
    
    def print_debate_summary(self):
        """Print summary of all hypotheses and debate."""
        self._print("")
        self._print("=" * 70)
        self._print("=== DEBATE SUMMARY ===", "")
        self._print("=" * 70)
        
        validated = [h for h in self.hypotheses.values() if h.status == HypothesisStatus.VALIDATED]
        supported = [h for h in self.hypotheses.values() if h.status == HypothesisStatus.SUPPORTED]
        refuted = [h for h in self.hypotheses.values() if h.status == HypothesisStatus.REFUTED]
        inconclusive = [h for h in self.hypotheses.values() if h.status == HypothesisStatus.INCONCLUSIVE]
        
        self._print(f"Total Hypotheses: {len(self.hypotheses)}", "  ")
        self._print(f"[+] Validated: {len(validated)}", "  ")
        self._print(f"[~] Supported: {len(supported)}", "  ")
        self._print(f"[?] Inconclusive: {len(inconclusive)}", "  ")
        self._print(f"[-] Refuted: {len(refuted)}", "  ")
        self._print(f"Total Debate Messages: {len(self.debate_log)}", "  ")
        self._print("")
        
        if validated:
            self._print("VALIDATED VULNERABILITIES:", "  ")
            for h in validated:
                self._print(f"    [{h.id}] {h.title} ({h.confidence:.0%})", "")
        
        if supported:
            self._print("NEEDS MANUAL VERIFICATION:", "  ")
            for h in supported:
                self._print(f"    [{h.id}] {h.title} ({h.confidence:.0%})", "")
        
        if refuted:
            self._print("FALSE POSITIVES ELIMINATED:", "  ")
            for h in refuted:
                self._print(f"    [{h.id}] {h.title}", "")
        
        self._print("")
    
    def get_validated_hypotheses(self) -> list[Hypothesis]:
        """Get all validated hypotheses."""
        return [h for h in self.hypotheses.values() 
                if h.status == HypothesisStatus.VALIDATED or h.confidence >= 0.7]
    
    def get_false_positives(self) -> list[Hypothesis]:
        """Get hypotheses identified as false positives."""
        return [h for h in self.hypotheses.values() 
                if h.status == HypothesisStatus.REFUTED or h.confidence < 0.3]
    
    def export_debate(self, filepath: str):
        """Export debate log to JSON."""
        export_data = {
            "hypotheses": [
                {
                    "id": h.id,
                    "title": h.title,
                    "description": h.description,
                    "proposed_by": h.proposed_by.value,
                    "status": h.status.value,
                    "confidence": h.confidence,
                    "supporters": [a.value for a in h.supporters],
                    "refuters": [a.value for a in h.refuters],
                    "chain_potential": h.chain_potential,
                }
                for h in self.hypotheses.values()
            ],
            "debate_log": [
                {
                    "agent": m.agent.value,
                    "type": m.message_type,
                    "content": m.content,
                    "hypothesis_id": m.hypothesis_id,
                    "timestamp": m.timestamp,
                }
                for m in self.debate_log
            ]
        }
        
        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)


# Analysis functions for scan results
def analyze_status_code(status_code: int, context: str = "") -> dict[str, Any]:
    """Analyze HTTP status code for vulnerability indicators."""
    analysis = {
        "code": status_code,
        "category": "",
        "security_implication": "",
        "confidence_modifier": 0.0,
    }
    
    if status_code == 200:
        analysis["category"] = "success"
        analysis["security_implication"] = "Request accepted - check response content for actual vulnerability"
        analysis["confidence_modifier"] = 0.0  # Neutral, need content analysis
        
    elif status_code == 201:
        analysis["category"] = "created"
        analysis["security_implication"] = "Resource created - possible write access achieved"
        analysis["confidence_modifier"] = 0.2
        
    elif status_code == 302 or status_code == 301:
        analysis["category"] = "redirect"
        analysis["security_implication"] = "Redirect detected - check if bypassing auth or open redirect"
        analysis["confidence_modifier"] = 0.1
        
    elif status_code == 400:
        analysis["category"] = "bad_request"
        analysis["security_implication"] = "Payload may have caused parser error - potential injection point"
        analysis["confidence_modifier"] = 0.15
        
    elif status_code == 401:
        analysis["category"] = "unauthorized"
        analysis["security_implication"] = "Auth required - endpoint exists but protected"
        analysis["confidence_modifier"] = -0.1
        
    elif status_code == 403:
        analysis["category"] = "forbidden"
        analysis["security_implication"] = "Access denied - endpoint exists, may be bypassable"
        analysis["confidence_modifier"] = 0.05
        
    elif status_code == 404:
        analysis["category"] = "not_found"
        analysis["security_implication"] = "Endpoint doesn't exist"
        analysis["confidence_modifier"] = -0.3
        
    elif status_code == 405:
        analysis["category"] = "method_not_allowed"
        analysis["security_implication"] = "Endpoint exists but wrong method - try others"
        analysis["confidence_modifier"] = 0.0
        
    elif status_code == 500:
        analysis["category"] = "server_error"
        analysis["security_implication"] = "Internal error - payload may have triggered bug"
        analysis["confidence_modifier"] = 0.25
        
    elif status_code == 502 or status_code == 503:
        analysis["category"] = "service_error"
        analysis["security_implication"] = "Service unavailable - possible DoS or backend issue"
        analysis["confidence_modifier"] = 0.1
        
    else:
        analysis["category"] = "other"
        analysis["security_implication"] = f"Unusual status code {status_code}"
        analysis["confidence_modifier"] = 0.0
    
    return analysis


if __name__ == "__main__":
    # Demo the debate system
    print("=== HYPOTHESIS DEBATE SYSTEM DEMO ===\n")
    
    debate = HypothesisDebateSystem(verbose=True)
    
    # Simulate a debate about NoSQL injection
    h1 = debate.propose_hypothesis(
        title="NoSQL Injection in /api/login",
        description="The login endpoint may be vulnerable to MongoDB operator injection",
        proposed_by=AgentRole.VULN_HUNTER,
        initial_evidence=Evidence(
            type="http_response",
            data={"status": 200, "body_contains": "success"},
            supports_hypothesis=True,
            confidence=0.6,
            source_agent=AgentRole.VULN_HUNTER
        )
    )
    
    # Support from another agent
    debate.support_hypothesis(
        h1.id,
        AgentRole.RECON,
        Evidence(
            type="tech_stack",
            data={"database": "MongoDB", "framework": "Express"},
            supports_hypothesis=True,
            confidence=0.7,
            source_agent=AgentRole.RECON
        ),
        "Tech stack confirms MongoDB backend, making NoSQL injection plausible"
    )
    
    # Devil's advocate challenges
    challenges = debate.devils_advocate_check(h1.id)
    
    # Refutation
    debate.refute_hypothesis(
        h1.id,
        AgentRole.POC_VALIDATOR,
        Evidence(
            type="response_analysis",
            data={"is_login_page": True, "no_token": True},
            supports_hypothesis=False,
            confidence=0.8,
            source_agent=AgentRole.POC_VALIDATOR
        ),
        "Response is just the login page HTML, no actual auth bypass occurred"
    )
    
    # Final evaluation
    evaluation = debate.evaluate_hypothesis(h1.id)
    
    # Print summary
    debate.print_debate_summary()
