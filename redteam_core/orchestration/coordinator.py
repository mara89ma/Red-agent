"""사이버전투임무팀(CMT) 코디네이터 — 미군 사이버작전 직무 협업.

에이전트를 USCYBERCOM 사이버임무군(CMF)의 **OCO 수행 CMT**로 구조화한다.
직무(work roles)가 각자 담당 층을 호출하며 킬체인을 협업 수행:
  - MC   Mission Commander        — 교전 권한 판정(§B RoE)
  - TDNA Target Digital Network Analyst — 표적개발·정보(§F·TI)
  - ION  Interactive On-Net Operator    — 실행/온넷 작전(§E 적응교전)
  - BDA  All-Source/BDA Analyst          — 전투피해평가(§D·§A)
판정권은 여전히 모델 밖(각 직무는 결정론 층 호출).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# 목표 → 대표 액션(직무가 참조).
_OBJ_ACTION = {
    "nav_jam_denial": "jam", "c2_jam_denial": "jam", "nav_denial": "gnss_spoof",
    "recon_access": "active_scan", "weapon_effect": "force_arm",
    "soc_llm_inject": "ml_prompt_inject", "model_extraction": "ml_extract_secret",
    "network_recon": "active_scan",
}
_GROUND = {"armed": False, "in_flight": False, "alt_rel": 0.0, "mode": "GUIDED"}


@dataclass
class RoleResult:
    role: str                       # 직무 코드(MC/TDNA/ION/BDA)
    title: str                      # 직무명
    summary: str
    detail: dict = field(default_factory=dict)


@dataclass
class MultiAgentResult:
    objective: str
    roles: List[RoleResult] = field(default_factory=list)
    authorized: bool = False        # MC 교전 권한(BLOCKED 아님)
    success: bool = False           # ION 효과 달성
    stealthy: bool = False          # BDA: 미탐지


# ── CMT 직무(결정론 층 래퍼) ─────────────────────────────────────────────────
def _mc(objective: str) -> RoleResult:
    from ..roe import evaluate_roe, load_roe_profile
    action = _OBJ_ACTION.get(objective, "active_scan")
    d = evaluate_roe(action, _GROUND, {"sysid": 42, "pid": True}, load_roe_profile())
    return RoleResult("MC", "Mission Commander",
                      f"교전권한 {d.verdict.value}(요구 {d.required_authority})",
                      {"verdict": d.verdict.value, "required_authority": d.required_authority})


def _tdna(objective: str) -> RoleResult:
    from ..integrations.threat_intel import _OBJECTIVE_SCENARIO, profile_scenario
    sid = _OBJECTIVE_SCENARIO.get(objective, "")
    actors = profile_scenario(sid) if sid else []
    return RoleResult("TDNA", "Target Digital Network Analyst",
                      f"표적개발({objective}) · 시나리오 {sid or '-'} · 위협 {len(actors)}",
                      {"scenario": sid, "threat_actors": actors})


def _ion(objective: str) -> RoleResult:
    from ..assessment import adaptive_engage
    r = adaptive_engage(objective)
    detected = r.trace[-1][2].detected if r.trace else None
    return RoleResult("ION", "Interactive On-Net Operator",
                      f"온넷 실행: {r.verdict} via {r.winning_ttp or '-'}",
                      {"verdict": r.verdict, "winning_ttp": r.winning_ttp, "detected": detected})


def _bda(ion: RoleResult) -> RoleResult:
    ach = ion.detail.get("verdict") == "achieved"
    det = ion.detail.get("detected")
    verdict = "은밀 달성" if (ach and det is not True) else "탐지 달성" if ach else "미달"
    return RoleResult("BDA", "All-Source/BDA Analyst", f"전투피해평가: {verdict}",
                      {"effective": ach, "detected": det})


def run_multi_agent_campaign(objective: str) -> MultiAgentResult:
    mc = _mc(objective)
    tdna = _tdna(objective)
    ion = _ion(objective)
    bda = _bda(ion)
    res = MultiAgentResult(objective, [mc, tdna, ion, bda])
    res.authorized = mc.detail["verdict"] != "BLOCKED"
    res.success = ion.detail.get("verdict") == "achieved"
    res.stealthy = res.success and ion.detail.get("detected") is not True
    return res


# 별칭(사이버작전 조직 명명)
run_cmt_campaign = run_multi_agent_campaign
