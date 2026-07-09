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
    # WiFi 계층(S39~S42, §V) — 802.11 전용 탐지룰 미배포 = 사각지대.
    "S39": None, "S40": None, "S41": None, "S42": None,
    # 고급(S43~S47, §W) — RC링크·DShot·anti-forensics 전용 탐지룰 미배포 = 사각지대.
    "S43": None, "S44": None, "S45": None, "S46": None, "S47": None,
    # Web/API·Linux 권한상승(S48~S52) — UAV Sentinel 밖 IT 계층 = 사각지대(§T 탐지).
    "S48": None, "S49": None, "S50": None, "S51": None, "S52": None,
    # 아카이브 경로순회(S53~S55) — 파일추출 계층 = 사각지대(§T 탐지).
    "S53": None, "S54": None, "S55": None,
    # 다중센서 폴트인젝션(S56~S59, §Z) — EKF 계층 전용 탐지룰 미배포 = 사각지대.
    "S56": None, "S57": None, "S58": None, "S59": None,
    # 지상 세그먼트 소프트웨어(S72~S85) — UAV Sentinel 텔레메트리 평면 미감시 = 사각지대.
    "S72": None, "S73": None, "S74": None, "S75": None,   # GCS 앱
    "S76": None, "S77": None, "S78": None,                # 컴패니언/ROS
    "S79": None, "S80": None, "S81": None,                # 데이터링크
    "S82": None, "S83": None, "S84": None, "S85": None,   # 클라우드
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
    "C13": ["S6", "S49", "S51", "S52"],  # 자격증명→웹셸업로드→컨테이너escape→cron지속(IT 킬체인)
    # ── 신규 C14~C18: IT(S48~S55 사각)↔OT(S1~S29) 브릿지 ──
    "C14": ["S53", "S4", "S1"],          # 아카이브 공급망(Zip Slip)→펌웨어 변조→항법거부
    "C15": ["S49", "S51", "S12", "S11"],  # 웹셸→컨테이너escape→임무 자기승인→무장(IT→OT)
    "C16": ["S49", "S50", "S51", "S52"],  # 웹셸→SUID→escape→cron(순수 IT 권한상승·완전 사각)
    "C17": ["S53", "S49", "S17"],        # 아카이브 전달→웹셸→SAR 유출
    "C18": ["S48", "S11"],               # 인증우회(IDOR)→무장(범주형 견고차단 실증)
    # ── 신규 C19~C20: 지상 세그먼트 소프트웨어 킬체인(전부 Sentinel 사각) ──
    "C19": ["S72", "S78", "S85"],        # GCS 악성미션→MAVROS 명령주입→C4I 위조명령(지상 관통)
    "C20": ["S82", "S83", "S84"],        # 함대API 인증우회→텔레메트리 오염→영상스트림 하이재킹
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
