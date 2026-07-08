"""멀티에이전트 코디네이터 — recon → exploit → C2 역할 협업.

각 역할 에이전트가 담당 층을 호출하고 결과를 다음 역할로 넘긴다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RoleResult:
    role: str
    summary: str
    detail: dict = field(default_factory=dict)


@dataclass
class MultiAgentResult:
    objective: str
    roles: List[RoleResult] = field(default_factory=list)
    success: bool = False           # exploit 효과 달성
    stealthy: bool = False          # 미탐지


# ── 역할 에이전트(결정론 층 래퍼) ─────────────────────────────────────────────
def _recon_agent(objective: str) -> RoleResult:
    """§F 표적개발 + TI 위협행위자 프로파일."""
    from ..integrations.threat_intel import _OBJECTIVE_SCENARIO, profile_scenario
    sid = _OBJECTIVE_SCENARIO.get(objective, "")
    actors = profile_scenario(sid) if sid else []
    return RoleResult("recon", f"표적 선정({objective}) · 관련 시나리오 {sid or '-'}",
                      {"scenario": sid, "threat_actors": actors})


def _exploit_agent(objective: str) -> RoleResult:
    """§E 적응교전으로 효과 달성 시도."""
    from ..assessment import adaptive_engage
    r = adaptive_engage(objective)
    detected = r.trace[-1][2].detected if r.trace else None
    return RoleResult("exploit", f"{r.verdict} via {r.winning_ttp or '-'}",
                      {"verdict": r.verdict, "winning_ttp": r.winning_ttp, "detected": detected})


def _c2_agent() -> RoleResult:
    """§O 연동으로 C2 채널 수립(env 없으면 폴백)."""
    from ..integrations import caldera
    st = caldera.status()
    return RoleResult("c2", f"C2 오케스트레이션({st['mode']})", {"mode": st["mode"]})


def run_multi_agent_campaign(objective: str) -> MultiAgentResult:
    recon = _recon_agent(objective)
    exploit = _exploit_agent(objective)
    c2 = _c2_agent()
    res = MultiAgentResult(objective, [recon, exploit, c2])
    res.success = exploit.detail.get("verdict") == "achieved"
    res.stealthy = res.success and exploit.detail.get("detected") is not True
    return res
