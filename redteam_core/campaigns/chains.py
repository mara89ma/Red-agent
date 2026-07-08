"""캠페인 체인 실행 — 시나리오 시퀀스를 순서 수행하고 탐지 프로파일 산출.

각 단계 시나리오를 대표 실행(action+intensity)하거나, 에이전트 미배선·배포룰만
있는 시나리오는 알려진 탐지상태(static)로 처리한다.
  - completed: 전 단계가 효과 달성(공격 실행됨).
  - stealthy : 어느 단계도 탐지 True 아님(전 단계 사각/회피).
  - 탐지 관통: completed 이나 일부 단계 탐지 → 방어 상관룰이 잡을 수 있음.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .. import assessment as A
from ..assessment.bda import assess_action

# 시나리오 → 대표 실행 (action, intensity). intensity None = 범주형/사각.
_SCENARIO_ACTION = {
    "S1": ("gnss_spoof", 0.8),          # 스푸핑(탐지)
    "S6": ("active_scan", 2.5),         # 정찰(회피된 저율)
    "S11": ("force_arm", None),         # 무장(범주형 탐지)
    "S15": ("unauthorized_command", None),
    "S30": ("jam", None),               # GNSS 재밍(사각)
    "S31": ("jam", None),               # C2 재밍(사각)
    "S32": ("ml_prompt_inject", None),  # 프롬프트 인젝션(사각)
    "S33": ("ml_extract_secret", None), # 모델 추출(사각)
    "S34": ("active_scan", 2.5),
}

# 배포룰은 있으나 에이전트 미배선 → 알려진 탐지상태(배포=탐지 / 미배포=사각).
_SCENARIO_STATIC = {
    "S4": True, "S12": True, "S13": True, "S14": True,   # 배포룰 → 탐지
    "S16": True, "S17": True, "S20": True,               # 배포룰 → 탐지
    "S8": None,                                          # 미배포 → 사각지대
    # 유출 계열 신규(S35~S38) — 전용 탐지룰 미배포 = 사각지대.
    "S35": None, "S36": None, "S37": None, "S38": None,
}

# 캠페인 체인(신규 C8~C10 포함). C1~C7 은 대조용 일부만.
CHAINS = {
    "C1": ["S6", "S13", "S15", "S11"],
    "C2": ["S14", "S4", "S1"],
    "C4": ["S6", "S12", "S11"],
    "C8": ["S30", "S16", "S20"],        # GNSS재밍→항법거부→AOI이탈/임무실패
    "C9": ["S32", "S8"],                # SOC LLM 인젝션→군집포화(대응 무력화)
    "C10": ["S30", "S1", "S17"],        # GNSS재밍(사각)→은밀 스푸핑→SAR 유출
    "C11": ["S6", "S38", "S17"],        # 자격증명→암호키 유출→(서명위조로 S18우회)인증 유출
    "C12": ["S6", "S37", "S35"],        # 자격증명→스테이징→대량 영상/SAR 유출
}


@dataclass
class ChainResult:
    chain_id: str
    verdict: str                        # stealthy | detected | blocked
    stages: List[Tuple[str, bool, Optional[bool]]] = field(default_factory=list)  # (sid, achieved, detected)
    detected_at: List[str] = field(default_factory=list)


def _exec_scenario(sid: str) -> Tuple[bool, Optional[bool]]:
    if sid in _SCENARIO_ACTION:
        action, intensity = _SCENARIO_ACTION[sid]
        out = assess_action(action, intensity=intensity if intensity is not None else 1.0)
        return True, out.detected
    if sid in _SCENARIO_STATIC:
        return True, _SCENARIO_STATIC[sid]
    return True, None                    # 미상 → 사각 가정


def run_chain(chain_id: str) -> ChainResult:
    stages: List[Tuple[str, bool, Optional[bool]]] = []
    detected_at: List[str] = []
    for sid in CHAINS[chain_id]:
        achieved, detected = _exec_scenario(sid)
        stages.append((sid, achieved, detected))
        if detected is True:
            detected_at.append(sid)
    completed = all(a for _, a, _ in stages)
    if not completed:
        verdict = "blocked"
    elif detected_at:
        verdict = "detected"             # 탐지 관통(상관룰이 잡음)
    else:
        verdict = "stealthy"             # 은밀 관통(전 단계 사각/회피)
    return ChainResult(chain_id, verdict, stages, detected_at)
