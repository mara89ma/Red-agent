"""사이버 지형 — UAS 자산 그래프(노드=자산, 엣지=기동 경로).

엣지의 phase 는 ATT&CK 전술(초기접근/측면이동/효과)에 대응하고, objective 가 있으면
그 hop 에서 §E 적응교전을 수행한다. blocked_reason 이 있으면 그 경로는 막힘(재경로 유발).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

ATTACKER = "attacker"

# 자산(노드): id → (표시명, 세그먼트)
ASSETS = {
    "attacker": ("공격자", "external"),
    "gcs": ("지상통제소(GCS)", "ground"),
    "c2_link": ("C2 데이터링크", "link"),
    "autopilot": ("오토파일럿", "air"),
    "gnss_rcv": ("GNSS 수신기", "air"),
    "weapon": ("무장 체계", "air"),
}


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    phase: str                      # initial_access | lateral_movement | effect
    objective: Optional[str] = None # §E OBJECTIVES 키(효과 hop) / None(순수 접근)
    blocked_reason: Optional[str] = None   # 있으면 이 경로 막힘(지형/방화벽 등)


# 공격 그래프(엣지). RF 직접 경로 vs 네트워크 측면이동 경로의 대안이 핵심.
EDGES: List[Edge] = [
    Edge("attacker", "gcs", "initial_access", "recon_access"),          # 자격증명 초기접근
    Edge("attacker", "gnss_rcv", "effect", "nav_denial",
         blocked_reason="RF LOS 차단(지형 은폐) — 직접 EW 불가"),        # RF 직접(데모상 막힘)
    Edge("gcs", "c2_link", "lateral_movement"),                          # GCS→데이터링크
    Edge("c2_link", "autopilot", "lateral_movement"),                    # C2 주입으로 오토파일럿
    Edge("autopilot", "gnss_rcv", "effect", "nav_denial"),              # 항법 거부
    Edge("autopilot", "weapon", "effect", "weapon_effect"),             # 무장 효과
]


def _out(node: str) -> List[Edge]:
    return [e for e in EDGES if e.src == node]


def simple_paths(start: str, goal: str, _seen=None) -> List[List[Edge]]:
    """start→goal 단순경로(사이클 없음) 전부, 짧은 것 우선."""
    _seen = _seen or {start}
    if start == goal:
        return [[]]
    paths: List[List[Edge]] = []
    for e in _out(start):
        if e.dst in _seen:
            continue
        for sub in simple_paths(e.dst, goal, _seen | {e.dst}):
            paths.append([e, *sub])
    return sorted(paths, key=len)
