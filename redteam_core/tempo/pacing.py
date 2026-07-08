"""공격 템포 페이싱 — 시간-탐지 트레이드오프.

smash: 고강도 → 즉효(짧은 time-to-effect)이나 임계 초과로 탐지(짧은 MTTD).
slow : 저강도 → 임계 아래로 회피(∞ MTTD)이나 효과 누적에 시간 소요(긴 TTE).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

from ..assessment.replan import EFFECT_FLOOR
from ..assessment.rules import action_to_rule

TEMPO_PROFILES = {
    "smash_and_grab": {"interval_min": 0.1, "mult": 4.0},   # 고속·고강도
    "low_and_slow": {"interval_min": 60.0, "mult": 0.4},    # 저속·저강도
}


@dataclass
class TempoResult:
    action: str
    tempo: str
    intensity: float
    detected: Optional[bool]        # None=사각지대
    time_to_effect_min: float       # 효과 달성까지(분)
    mttd_min: Optional[float]       # 탐지까지(분), None=∞(미탐지)


def pace(action: str, tempo: str) -> TempoResult:
    prof = TEMPO_PROFILES[tempo]
    spec = action_to_rule(action)
    thr = spec.threshold if (spec and spec.threshold is not None) else 1.0
    floor = EFFECT_FLOOR.get(action, thr * 0.5)
    intensity = round(thr * prof["mult"], 4)

    if spec is None:
        detected = None                         # 사각지대(미매핑)
    elif spec.kind == "categorical":
        detected = True                         # 범주형 = 항상 탐지
    else:
        detected = intensity >= thr             # 연속: 임계 초과 시 탐지

    # 효과 누적: 강도가 효과바닥 미만이면 여러 스텝 필요(저속의 대가).
    steps = 1 if intensity >= floor else max(1, math.ceil(floor / max(intensity, 1e-9)))
    tte = round(steps * prof["interval_min"], 2)
    mttd = prof["interval_min"] if detected else None
    return TempoResult(action, tempo, intensity, detected, tte, mttd)


def tempo_tradeoff(action: str) -> dict:
    """한 액션의 smash vs slow 트레이드오프."""
    return {t: pace(action, t) for t in TEMPO_PROFILES}
