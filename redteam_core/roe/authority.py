"""교전권한 레벨 — SROE + JP 3-60 ④(지휘결심·화력할당).

동언님 gate ∈ {none, low, hitl, human_only} 는 "승인 필요 강도"만 말한다.
교리는 그 위에 '권한 *레벨*'을 요구한다 — 물리 비가역·고 CDE 효과는 상급
지휘/국가통수 권한을 필요로 한다(weapons-release authority).
"""
from __future__ import annotations

from enum import IntEnum

from .cde import CdeTier


class AuthorityLevel(IntEnum):
    """교전 승인 권한 레벨(오름차순 = 상급)."""
    NONE = 0          # 무통제(정찰/읽기)
    LOW = 1           # 자동 허용·기록 (전술 운용자)
    COMPONENT = 2     # 구성군사령부/운용자 승인 (HITL)
    JFC = 3           # 합동군사령관 — 물리 비가역·중대 효과
    NATIONAL = 4      # 국가통수 — 심대 부수효과·비가역 대량효과


# 동언님 reversibility gate → 기본 권한 레벨
_GATE_BASE = {
    "none": AuthorityLevel.NONE,
    "low": AuthorityLevel.LOW,
    "hitl": AuthorityLevel.COMPONENT,
    "human_only": AuthorityLevel.JFC,
}

# CDE 등급 → 최소 요구 권한(부수효과가 클수록 상급 권한)
_CDE_FLOOR = {
    CdeTier.NONE: AuthorityLevel.NONE,
    CdeTier.LOW: AuthorityLevel.LOW,
    CdeTier.MODERATE: AuthorityLevel.COMPONENT,
    CdeTier.HIGH: AuthorityLevel.JFC,
    CdeTier.SEVERE: AuthorityLevel.NATIONAL,
}


def required_authority(gate: str, cde: CdeTier) -> AuthorityLevel:
    """기본 gate 권한과 CDE 하한 중 **상급**을 요구 권한으로(가장 보수적)."""
    base = _GATE_BASE.get(gate, AuthorityLevel.JFC)   # 미상은 보수적으로 JFC
    floor = _CDE_FLOOR.get(cde, AuthorityLevel.JFC)
    return AuthorityLevel(max(int(base), int(floor)))
