"""임무형 지휘 오케스트레이터.

MissionProfile(사람 1회 입력) → 오케스트레이터 자율 지휘:
  1) 지휘관 의도(desired_effects)를 하위 목표로 분해(수단 자율 선택)
  2) RoE 상한 초과 목표는 자율 보류(권한은 모델 밖)
  3) 남은 목표를 CMT 로 실행·적응
  4) 최종상태(end_state) 달성 판정 + 자율 결심 로그
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# 지휘관 의도(효과) → 이를 달성하는 후보 목표(수단). 오케스트레이터가 자율 선택.
_EFFECT_MEANS = {
    "nav_denial": ["nav_denial", "nav_jam_denial", "imu_spoof"],
    "c2_denial": ["c2_jam_denial"],
    "isr_disruption": ["data_exfiltration", "video_stream_hijack"],
    "soft_kill_ai": ["soc_llm_inject", "model_extraction"],
    "ground_compromise": ["gcs_mission_parse", "mavros_cmd_inject", "fleet_api_bypass"],
    "recon": ["recon_access", "network_recon"],
}
# 목표 → 요구 권한(RoE 상한 판정용). 낮을수록 저권한.
_OBJ_AUTHORITY = {"weapon_effect": 4, "nav_jam_denial": 3, "c2_jam_denial": 3,
                  "nav_denial": 2, "video_stream_hijack": 2, "gcs_mission_parse": 2,
                  "mavros_cmd_inject": 2, "fleet_api_bypass": 2, "data_exfiltration": 2,
                  "soc_llm_inject": 2, "model_extraction": 2, "imu_spoof": 2,
                  "recon_access": 1, "network_recon": 1}


@dataclass
class MissionProfile:
    """사람이 1회 부여 — 이후 오케스트레이터가 자율 지휘."""
    commander_intent: str                     # 자연어 의도(로그용)
    desired_effects: List[str]                 # 달성할 효과(수단은 자율)
    roe_ceiling: int = 2                        # RoE 권한 상한(초과 목표 자율 보류)
    require_stealth: bool = False              # 최종상태 조건: 은밀 필수?
    end_state: str = ""


@dataclass
class Decision:
    objective: str
    action: str                                # executed | withheld_roe | failed
    verdict: str
    stealthy: Optional[bool]
    rationale: str


@dataclass
class MissionResult:
    intent: str
    decisions: List[Decision] = field(default_factory=list)
    end_state_achieved: bool = False
    autonomous: bool = True                     # 인간 추가개입 없이 수행


def run_mission_command(profile: MissionProfile) -> MissionResult:
    from ..assessment import OBJECTIVES, adaptive_engage
    res = MissionResult(profile.commander_intent)

    # 1) 의도 → 수단(목표) 자율 분해
    means: List[str] = []
    for eff in profile.desired_effects:
        for obj in _EFFECT_MEANS.get(eff, [eff]):
            if obj in OBJECTIVES and obj not in means:
                means.append(obj)

    achieved_effects = 0
    for eff in profile.desired_effects:
        eff_done = False
        for obj in _EFFECT_MEANS.get(eff, [eff]):
            if obj not in means:
                continue
            # 2) RoE 상한 초과 → 자율 보류(권한은 모델 밖)
            if _OBJ_AUTHORITY.get(obj, 2) > profile.roe_ceiling:
                res.decisions.append(Decision(obj, "withheld_roe", "-", None,
                    f"요구권한 {_OBJ_AUTHORITY.get(obj)} > 상한 {profile.roe_ceiling} → 자율 보류"))
                continue
            # 3) CMT 실행·적응
            r = adaptive_engage(obj)
            detected = r.trace[-1][2].detected if r.trace else None
            stealthy = r.verdict == "achieved" and detected is not True
            ok = r.verdict == "achieved" and (stealthy or not profile.require_stealth)
            res.decisions.append(Decision(obj, "executed", r.verdict, stealthy,
                "의도 달성 수단 자율 선택·실행"))
            if ok:
                eff_done = True
                break
        if eff_done:
            achieved_effects += 1

    # 4) 최종상태: 모든 desired_effect 달성(+은밀 조건)
    res.end_state_achieved = achieved_effects == len(profile.desired_effects) \
        and achieved_effects > 0
    return res
