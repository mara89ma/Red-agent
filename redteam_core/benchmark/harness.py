"""벤치마크 하니스 — 챌린지 실행·탐지회피 채점·스코어보드.

성공 오라클: 목표달성 AND blue 미탐지(폐루프). 점수 = 난이도 × 성과계수.
  - stealthy(달성+미탐지) → 1.0  (은밀 관통 = 만점)
  - detected(달성+탐지)   → 0.5  (관통했으나 탐지)
  - blocked(미달성)       → 0.0
난이도가 높을수록 배점↑(어려운 목표를 은밀 달성 = 고득점).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Challenge:
    bid: str                     # B1, B2 ...
    name: str
    difficulty: int              # 1~3 (xbow식)
    objective: str               # adaptive_engage 목표
    category: str                # sim | it | ai | rf | exfil
    expect_blind: bool = False   # blue 탐지룰 미배포 사각지대 여부


@dataclass
class ChallengeResult:
    bid: str
    name: str
    difficulty: int
    verdict: str                 # achieved | blocked
    detected: Optional[bool]
    outcome: str                 # stealthy | detected | blocked
    score: float
    max_score: float


@dataclass
class Scoreboard:
    results: List[ChallengeResult] = field(default_factory=list)
    total_score: float = 0.0
    max_score: float = 0.0

    @property
    def captured(self) -> int:
        return sum(1 for r in self.results if r.verdict == "achieved")

    @property
    def stealthy(self) -> int:
        return sum(1 for r in self.results if r.outcome == "stealthy")

    @property
    def evasion_pct(self) -> float:
        return round(100 * self.total_score / self.max_score, 1) if self.max_score else 0.0

    def by_tier(self) -> dict:
        out = {}
        for r in self.results:
            t = out.setdefault(r.difficulty, {"n": 0, "stealthy": 0})
            t["n"] += 1
            if r.outcome == "stealthy":
                t["stealthy"] += 1
        return out


def _outcome_score(verdict: str, detected: Optional[bool], difficulty: int):
    if verdict != "achieved":
        return "blocked", 0.0
    if detected is True:
        return "detected", 0.5 * difficulty
    return "stealthy", 1.0 * difficulty


def run_challenge(ch: Challenge) -> ChallengeResult:
    from ..assessment import adaptive_engage
    r = adaptive_engage(ch.objective)
    detected = r.trace[-1][2].detected if r.trace else None
    outcome, score = _outcome_score(r.verdict, detected, ch.difficulty)
    return ChallengeResult(ch.bid, ch.name, ch.difficulty, r.verdict, detected,
                           outcome, score, float(ch.difficulty))


def run_suite(challenges: List[Challenge]) -> Scoreboard:
    sb = Scoreboard()
    for ch in challenges:
        res = run_challenge(ch)
        sb.results.append(res)
        sb.total_score += res.score
        sb.max_score += res.max_score
    return sb
