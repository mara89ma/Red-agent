"""Orient-phase denial + OODA 속도경쟁.

Orient 마비: 모순 근거 k개를 동시 주입 → 불확실성(엔트로피) 극대화 → 판정 지연.
속도경쟁: red Actions-on-Objective 완료시각 vs blue Report/RuleUpdate 폐쇄시각.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List


@dataclass
class OrientDenialResult:
    contradictions: int
    uncertainty: float          # 0~1 정규화 엔트로피
    orient_paralyzed: bool
    reframed_from: str
    note: str


def orient_phase_denial(contradictions: int, reframe_scenario: str = "S29") -> OrientDenialResult:
    """모순 근거 주입으로 Orient 불확실성 극대화. S5/S29(RAG 포이즈닝) 재프레임."""
    # 2^k 균등 가설이면 정규화 엔트로피 = k/(k+ref). 모순이 많을수록 1에 근접.
    u = round(contradictions / (contradictions + 2), 3) if contradictions else 0.0
    paralyzed = u >= 0.5
    note = (f"모순 근거 {contradictions}개 → Investigation 불확실성 {u} → Orient 마비. "
            f"'{reframe_scenario}(RAG 포이즈닝)'을 Orient-phase denial 로 재서술"
            if paralyzed else "불확실성 미달")
    return OrientDenialResult(contradictions, u, paralyzed, reframe_scenario, note)


@dataclass
class OodaRaceResult:
    red_objective_time: float   # red Actions-on-Objective 완료(초/틱)
    blue_close_time: float      # blue Report→RuleUpdate 폐쇄
    winner: str                 # red | blue
    margin: float
    inside_loop: bool           # red 가 blue OODA 안으로 들어감
    note: str


def ooda_race(red_objective_time: float, blue_close_time: float) -> OodaRaceResult:
    """red↔blue 공통 스코어보드: 누구 OODA 가 더 빠른가."""
    red_wins = red_objective_time < blue_close_time
    margin = round(abs(blue_close_time - red_objective_time), 3)
    note = (f"red 가 blue 폐쇄({blue_close_time}) 전에 목표달성({red_objective_time}) "
            f"→ blue OODA 안으로 진입(마진 {margin})" if red_wins
            else f"blue 가 먼저 폐쇄 → red 차단(마진 {margin})")
    return OodaRaceResult(red_objective_time, blue_close_time,
                          "red" if red_wins else "blue", margin, red_wins, note)
