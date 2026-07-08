"""부수효과추정(CDE) — CJCSM 3160 방법론의 경량 결정론 근사.

동언님 reversibility.classify() 의 물리 심각도를 재사용하되, '효과 범위'
(점표적 vs 광역/스펙트럼)를 더해 CDE 등급을 매긴다. 전자전(jam/gnss_spoof)은
표적 외 자산·항법에 광역 부수효과를 줄 수 있어 등급을 올린다(JP 3-85 맥락).
"""
from __future__ import annotations

from enum import IntEnum

from ..safety.reversibility import classify


class CdeTier(IntEnum):
    NONE = 0
    LOW = 1
    MODERATE = 2
    HIGH = 3
    SEVERE = 4


# 광역/비표적 효과(스펙트럼·환경) 액션 — 부수효과 등급 상향 대상.
_AREA_EFFECT = {"jam", "gnss_spoof", "satcom_mitm"}

_RISK_TIER_BASE = {
    "read": CdeTier.NONE,
    "write_lowrisk": CdeTier.LOW,
    "write_highrisk": CdeTier.MODERATE,
    "physical_irreversible": CdeTier.HIGH,
}


def estimate_cde(action: str, live_physical_state: dict) -> CdeTier:
    """(risk_tier, gate)에서 물리 심각도를 얻고, 광역효과면 한 단계 상향."""
    risk_tier, gate = classify(live_physical_state, action)
    base = _RISK_TIER_BASE.get(risk_tier, CdeTier.HIGH)
    if gate == "human_only" and base < CdeTier.HIGH:
        base = CdeTier.HIGH                       # 인간전용 게이트 = 중대 효과 하한
    if action in _AREA_EFFECT:
        base = CdeTier(min(int(base) + 1, int(CdeTier.SEVERE)))   # 광역 부수효과 상향
    return base
