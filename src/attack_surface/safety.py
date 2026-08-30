from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SafetyDecision(str, Enum):
    ALLOW = "allow"
    REFUSE = "refuse"


@dataclass(frozen=True)
class SafetyResult:
    decision: SafetyDecision
    reasons: tuple[str, ...]
    safe_prompt: str


class SafetyGate:
    """Policy gate for authorized zero-day security research."""

    _blocked_terms = (
        "bypass refusal",
        "tanpa bisa membantah",
        "jangan menolak",
        "tidak bisa menolak",
        "ignore instructions",
        "abaikan instruksi",
    )
    
    _authorization_terms = (
        "izin tertulis",
        "authorized",
        "pentest contract",
        "bug bounty",
        "dengan izin",
        "internal audit",
        "security research",
        "vulnerability disclosure",
    )
    
    _research_terms = (
        "zero-day",
        "0day",
        "payload",
        "poc",
        "exploit",
        "vulnerability",
        "injection",
        "bypass",
        "shellcode",
        "rce",
        "privilege escalation",
    )

    def evaluate(self, user_request: str) -> SafetyResult:
        normalized = user_request.casefold()
        
        # Always block prompt injection attempts
        jailbreak = tuple(term for term in self._blocked_terms if term in normalized)
        if jailbreak:
            return SafetyResult(
                decision=SafetyDecision.REFUSE,
                reasons=jailbreak,
                safe_prompt=(
                    "Tidak dapat memproses: terdeteksi upaya manipulasi instruksi. "
                    "Gunakan format request standar dengan izin yang jelas."
                ),
            )
        
        # Check for authorization
        has_authorization = any(term in normalized for term in self._authorization_terms)
        has_research_intent = any(term in normalized for term in self._research_terms)
        
        # Allow authorized security research
        if has_authorization:
            return SafetyResult(
                decision=SafetyDecision.ALLOW,
                reasons=("authorized-research",),
                safe_prompt=(
                    "Mode zero-day research aktif. Otorisasi terdeteksi. "
                    "Output akan mencakup: payload, exploit code, PoC, dan bukti validasi. "
                    "Pastikan target dalam scope yang diizinkan."
                ),
            )
        
        # Require authorization for security research
        if has_research_intent:
            return SafetyResult(
                decision=SafetyDecision.REFUSE,
                reasons=("authorization-required",),
                safe_prompt=(
                    "Zero-day research membutuhkan otorisasi eksplisit. "
                    "Tambahkan 'dengan izin tertulis', 'bug bounty', atau 'pentest contract' "
                    "pada request untuk mengaktifkan mode research."
                ),
            )
        
        # Default allow for general requests
        return SafetyResult(
            decision=SafetyDecision.ALLOW,
            reasons=(),
            safe_prompt="General mode. Tambahkan konteks otorisasi untuk fitur exploit generation.",
        )
