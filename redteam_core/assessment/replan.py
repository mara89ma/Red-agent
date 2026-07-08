"""적응형 재계획 — 재타격권고를 실제 실행하는 폐루프 (고도화 §E).

persistent engagement / OODA: red 가 방어자 반응(탐지)에 orient 해 재타격을
*권고*(§D)에 그치지 않고 *실행*한다.
  - lower_intensity : 강도를 낮춰 탐지 임계 아래로(단, 효과 바닥 미만이면 전환).
  - raise_intensity : 효과 미달이면 강도 상향.
  - switch_ttp      : 같은 목표(effect)를 다른 TTP 로 — 사각지대/연속임계 우선.

핵심 교리 통찰: 어떤 효과는 '효과 바닥(effect floor) ≥ 탐지 임계'라 **강도로는
절대 회피 불가**(효과를 내는 순간 탐지). 이때 red 는 TTP 를 전환해야 하며, 그
전환이 blue 의 탐지 사각을 드러낸다(= 방어 보강 지점).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .bda import assess_action
from .combat import CombatAssessment, assess_combat
from .rules import action_to_rule

# 목표(효과) → 이를 달성하는 TTP 대안(선호순). jam 은 현재 blue 미매핑=사각지대.
OBJECTIVES = {
    "nav_denial": ["gnss_spoof", "jam"],            # 항법 거부: 스푸핑→(불가시)재밍
    "nav_jam_denial": ["jam"],                       # S30: GNSS 재밍 단독(항법 거부, 사각지대)
    "recon_access": ["active_scan"],                # 정찰/자격증명
    "weapon_effect": ["force_arm", "unauthorized_command"],  # 둘 다 범주형 → 견고
}

# 연속 액션의 '효과 바닥' — 이 미만이면 효과 미달. blue 임계와의 관계가 회피창을 정함.
EFFECT_FLOOR = {
    "gnss_spoof": 0.05,      # > blue S1 게이트(0.0238) → 회피창 없음 → 전환 유발
    "active_scan": 1.0,      # < blue S6(5) → 회피창 존재 → 강도 하향으로 회피 성공
    "spoof_telemetry": 2.0,  # < blue S18(5) → 회피창 존재
}
_DEFAULT_START = {"gnss_spoof": 0.8, "active_scan": 20.0, "spoof_telemetry": 16.0}


@dataclass
class CampaignResult:
    objective: str
    verdict: str                 # "achieved" | "blocked"
    winning_ttp: Optional[str]
    trace: List[Tuple[str, float, CombatAssessment]] = field(default_factory=list)


def _effect_achieved(action: str, intensity: float) -> bool:
    floor = EFFECT_FLOOR.get(action)
    return True if floor is None else intensity >= floor      # 범주형/사각 = 효과 가정


def adaptive_engage(objective: str, backoff: float = 0.5, max_iters: int = 24) -> CampaignResult:
    ttps = list(OBJECTIVES[objective])
    ti = 0
    action = ttps[ti]
    intensity = _DEFAULT_START.get(action, 1.0)
    trace: List[Tuple[str, float, CombatAssessment]] = []

    def _switch() -> bool:
        nonlocal ti, action, intensity
        ti += 1
        if ti >= len(ttps):
            return False
        action = ttps[ti]
        intensity = _DEFAULT_START.get(action, 1.0)
        return True

    for _ in range(max_iters):
        spec = action_to_rule(action)
        detected = assess_action(action, intensity=intensity).detected if spec else None
        effect = _effect_achieved(action, intensity)
        adaptable = bool(spec and spec.kind == "continuous")
        ca = assess_combat(action, executed=True, effect_achieved=effect,
                           detected=detected, adaptable=adaptable)
        trace.append((action, intensity, ca))

        if ca.effective:
            return CampaignResult(objective, "achieved", action, trace)

        adj = ca.reattack.adjustment
        if adj == "lower_intensity":
            new = round(intensity * backoff, 6)
            if new < EFFECT_FLOOR.get(action, 0.0):        # 회피하면 효과 붕괴 → 전환
                if not _switch():
                    return CampaignResult(objective, "blocked", None, trace)
            else:
                intensity = new
        elif adj == "raise_intensity":
            intensity = round(intensity * 2.0, 6)
        elif adj == "switch_ttp":
            if not _switch():
                return CampaignResult(objective, "blocked", None, trace)
        else:
            return CampaignResult(objective, "achieved", action, trace)

    return CampaignResult(objective, "blocked", None, trace)
