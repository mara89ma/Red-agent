"""전투평가 — JP 3-60 ⑥단계 (MOP·MOE·재타격권고).

§A BDA("탐지됐나")를 조인트 타게팅 ⑥단계로 완성한다:
  - MOP (Measures of Performance): 임무수행도 — 전달/실행이 제대로 됐나.
  - MOE (Measures of Effectiveness): 효과달성 + **생존성(미탐지)**.
    공격측 MOE 는 "효과를 냈나"뿐 아니라 "탐지 없이 살아남았나"를 포함한다.
  - 재타격권고 (reattack recommendation): 미달 시 무엇을 어떻게 조정할지.

§C EMSO 효과(effect_achieved)와 §A 탐지(detected)를 한 교전평가로 묶는다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .bda import assess_action
from .rules import action_to_rule


@dataclass
class ReattackRecommendation:
    needed: bool
    adjustment: str      # none|fix_delivery|raise_intensity|lower_intensity|switch_ttp
    rationale: str


@dataclass
class CombatAssessment:
    action: str
    mop_executed: bool           # 임무수행도
    moe_effect: bool             # 효과달성
    moe_survivability: bool      # 생존성(미탐지)
    effective: bool              # 종합(MOP∧효과∧생존)
    detected: Optional[bool]
    reattack: ReattackRecommendation
    doctrine_refs: tuple = ("JP 3-60 ⑥ Combat Assessment", "MOE/MOP", "Reattack Rec")


def assess_combat(action: str, *, executed: bool, effect_achieved: bool,
                  detected: Optional[bool], adaptable: bool) -> CombatAssessment:
    survivability = (detected is not True)          # None(사각) 도 생존으로 간주
    effective = executed and effect_achieved and survivability

    if not executed:
        rec = ReattackRecommendation(True, "fix_delivery", "MOP 미달: 전달/실행 실패 → 접근·페이로드 교정")
    elif not effect_achieved:
        rec = ReattackRecommendation(True, "raise_intensity",
                                     "MOE 미달(효과 불충분) → 강도/지오메트리 상향 재타격")
    elif detected is True:
        if adaptable:
            rec = ReattackRecommendation(True, "lower_intensity",
                                         "생존성 미달(탐지)·연속임계 → 임계 아래로 강도 하향 재타격")
        else:
            rec = ReattackRecommendation(True, "switch_ttp",
                                         "생존성 미달(탐지)·범주형(강도 회피 불가) → TTP 전환")
    else:
        rec = ReattackRecommendation(False, "none", "목표 달성(효과+생존) → 재타격 불요")

    return CombatAssessment(
        action=action, mop_executed=executed, moe_effect=effect_achieved,
        moe_survivability=survivability, effective=effective, detected=detected,
        reattack=rec)


def run_engagement(action: str, *, geometry: Optional[dict] = None,
                   intensity: Optional[float] = None,
                   executed: bool = True) -> CombatAssessment:
    """§C EMSO(있으면) → 효과·강도 → §A BDA(탐지) → ⑥단계 전투평가로 묶는다."""
    effect_achieved = True
    if action in ("gnss_spoof", "jam") and geometry is not None:
        from ..emso import plan_emso
        out = plan_emso(action, geometry)
        effect_achieved = out.effect.achieved
        if "pos_horiz_variance" in out.effect.telemetry_hint:
            intensity = out.effect.telemetry_hint["pos_horiz_variance"]

    bda = assess_action(action, intensity=intensity if intensity is not None else 1.0)
    spec = action_to_rule(action)
    adaptable = bool(spec and spec.kind == "continuous")
    return assess_combat(action, executed=executed, effect_achieved=effect_achieved,
                         detected=bda.detected, adaptable=adaptable)
