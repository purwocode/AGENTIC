from __future__ import annotations

from dataclasses import dataclass

from .models import ModelAdapter


@dataclass(frozen=True)
class AgentTurn:
    agent: str
    model: str
    response: str
    round_number: int = 1


@dataclass(frozen=True)
class ZeroDayAgent:
    """Agent focused on zero-day discovery, exploitation, and PoC development."""
    name: str
    instruction: str
    model: ModelAdapter

    def respond(
        self,
        user_request: str,
        context: list[AgentTurn],
        target_info: str,
        attack_phase: str,
        round_number: int,
    ) -> AgentTurn:
        transcript = "\n".join(f"{turn.agent}: {turn.response}" for turn in context)
        prompt = (
            f"Target: {target_info}\n"
            f"Phase: {attack_phase}\n"
            f"Role: {self.instruction}\n"
            f"Objective: {user_request}\n"
            f"Previous findings:\n{transcript}\n"
            "Deliver concrete, actionable output: payloads, exploits, PoC code, evidence."
        )
        return AgentTurn(self.name, self.model.name, self.model.complete(prompt), round_number)


def build_agents(models: list[ModelAdapter]) -> list[ZeroDayAgent]:
    if len(models) < 5:
        raise ValueError("At least five models are required for zero-day research")

    return [
        ZeroDayAgent(
            "ReconAgent",
            "Lakukan reconnaissance mendalam: identifikasi endpoint, parameter, stack teknologi, "
            "versi komponen, header, cookie, session handling, dan attack surface.",
            models[0],
        ),
        ZeroDayAgent(
            "VulnHunterAgent",
            "Analisis vulnerability: cari injection points, auth flaws, logic bugs, "
            "memory issues. Hasilkan payload spesifik untuk setiap temuan.",
            models[1],
        ),
        ZeroDayAgent(
            "ExploitDevAgent",
            "Develop working exploits: tulis kode exploit lengkap dalam Python/Bash, "
            "weaponize payload, bypass proteksi jika ada. Output harus executable.",
            models[2],
        ),
        ZeroDayAgent(
            "PoCValidatorAgent",
            "Validasi PoC: jalankan exploit, dokumentasikan request/response, "
            "verifikasi dampak, eliminate false positive dengan multiple test case.",
            models[3],
        ),
        ZeroDayAgent(
            "EvidenceCollectorAgent",
            "Kumpulkan bukti: capture logs, screenshots, hash artifacts, "
            "buat timeline attack chain, assess severity dengan CVSS.",
            models[4],
        ),
    ]


# Legacy alias for backward compatibility
CouncilAgent = ZeroDayAgent


def build_council_agents(models: list[ModelAdapter]) -> list[ZeroDayAgent]:
    """Backward compatible wrapper."""
    return build_agents(models)
