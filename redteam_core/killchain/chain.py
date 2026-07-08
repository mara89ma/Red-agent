"""킬체인 관통 — 7단계를 순서 수행하고 완전/은밀 관통 여부 판정.

단계 상태: "수행"(ok) | "탐지"(수행되나 blue 탐지) | "차단"(수행 불가).
  - 완전 관통(completed) = 차단 단계 없음.
  - 은밀 관통(stealthy) = 완전 관통 + 탐지 단계 없음.
전달 도달성은 §G 지형(막히지 않은 경로 존재)으로, 목표행동은 §E 적응교전으로 판정.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..assessment import OBJECTIVES, adaptive_engage
from ..maneuver.terrain import ATTACKER, simple_paths
from .capabilities import C2_TECHNIQUES, PERSISTENCE_TECHNIQUES

# 표적 자산 → 목표행동(§E objective)
TARGET_OBJECTIVE = {
    "gnss_rcv": "nav_denial",
    "weapon": "weapon_effect",
    "gcs": "recon_access",
}

STAGE_NAMES = ["정찰", "무기화", "전달", "악용", "설치/지속", "C2", "목표행동"]


@dataclass
class StageResult:
    stage: str
    status: str          # 수행 | 탐지 | 차단
    detail: str = ""


@dataclass
class KillChainResult:
    target: str
    stages: List[StageResult] = field(default_factory=list)
    completed: bool = False      # 완전 관통(차단 없음)
    stealthy: bool = False       # 은밀 관통(탐지도 없음)


def _reachable(target: str) -> bool:
    """§G 지형에서 막힌 엣지가 없는 경로가 하나라도 있으면 전달 가능."""
    for path in simple_paths(ATTACKER, target):
        if all(e.blocked_reason is None for e in path):
            return True
    return False


def run_killchain(target: str, persistence: str = "credential_foothold",
                  c2: str = "common_port") -> KillChainResult:
    obj = TARGET_OBJECTIVE[target]
    stages: List[StageResult] = []

    # 1 정찰
    rec = adaptive_engage("recon_access")
    stages.append(StageResult("정찰", "수행" if rec.verdict == "achieved" else "차단",
                              f"recon_access via {rec.winning_ttp}"))
    # 2 무기화 — 목표에 대응 TTP 무기고 존재
    stages.append(StageResult("무기화", "수행" if obj in OBJECTIVES else "차단",
                              f"무기고 대응 TTP: {OBJECTIVES.get(obj)}"))
    # 3 전달 — 지형 도달성
    deliver_ok = _reachable(target)
    stages.append(StageResult("전달", "수행" if deliver_ok else "차단",
                              "막히지 않은 경로 존재" if deliver_ok else "전 경로 차단"))
    # 4 악용 — 전달되면 실행 발판 확보
    stages.append(StageResult("악용", "수행" if deliver_ok else "차단",
                              "표적 자산 실행 발판 확보"))
    # 5 설치/지속
    p = PERSISTENCE_TECHNIQUES[persistence]
    stages.append(StageResult("설치/지속", "탐지" if p["detected"] else "수행", p["note"]))
    # 6 C2
    c = C2_TECHNIQUES[c2]
    stages.append(StageResult("C2", "탐지" if c["detected"] else "수행", c["note"]))
    # 7 목표행동
    act = adaptive_engage(obj)
    stages.append(StageResult("목표행동", "수행" if act.verdict == "achieved" else "차단",
                              f"{obj} via {act.winning_ttp}" if act.winning_ttp else f"{obj} 견고 차단"))

    completed = all(s.status != "차단" for s in stages)
    stealthy = completed and all(s.status != "탐지" for s in stages)
    return KillChainResult(target=target, stages=stages, completed=completed, stealthy=stealthy)
