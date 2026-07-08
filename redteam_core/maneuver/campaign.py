"""기동 캠페인 — 지형을 순회하며 효과에 도달, 막히면 재경로.

각 hop:
  - 순수 접근(objective=None): 측면이동/초기접근 = 접근 확보(access gained).
  - 효과(objective 有): §E 적응교전 수행 → 달성/차단.
경로 중 한 hop 이라도 막히면 다음 단순경로로 재경로(maneuver). 전 경로 소진이면 blocked.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..assessment import adaptive_engage
from .terrain import ATTACKER, ASSETS, Edge, simple_paths


@dataclass
class HopResult:
    src: str
    dst: str
    phase: str
    status: str                 # gained | achieved | blocked
    detail: str = ""


@dataclass
class CampaignResult:
    target: str
    verdict: str                # reached | blocked
    winning_path: Optional[List[str]]      # 자산 id 순서
    attempts: int               # 시도한 경로 수(재경로 횟수+1)
    hops: List[HopResult] = field(default_factory=list)    # 성공/최종 실패 경로의 hop 로그


def _run_path(path: List[Edge]) -> (bool, List[HopResult]):
    hops: List[HopResult] = []
    for e in path:
        if e.blocked_reason:
            hops.append(HopResult(e.src, e.dst, e.phase, "blocked", e.blocked_reason))
            return False, hops
        if e.objective:
            r = adaptive_engage(e.objective)
            if r.verdict == "achieved":
                hops.append(HopResult(e.src, e.dst, e.phase, "achieved",
                                      f"{e.objective} via {r.winning_ttp}"))
            else:
                hops.append(HopResult(e.src, e.dst, e.phase, "blocked",
                                      f"{e.objective} 차단(견고)"))
                return False, hops
        else:
            hops.append(HopResult(e.src, e.dst, e.phase, "gained", "접근 확보(측면이동)"))
    return True, hops


def run_campaign(target: str) -> CampaignResult:
    paths = simple_paths(ATTACKER, target)
    last_hops: List[HopResult] = []
    for i, path in enumerate(paths, 1):
        ok, hops = _run_path(path)
        last_hops = hops
        if ok:
            route = [ATTACKER, *[e.dst for e in path]]
            return CampaignResult(target, "reached", route, i, hops)
    return CampaignResult(target, "blocked", None, len(paths) or 1, last_hops)
