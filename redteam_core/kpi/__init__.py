"""kpi — 레드팀 에이전트 KPI 집계 (고도화 §N).

기존 층들이 산출한 원자값에서 상위 KPI를 집계한다.
1순위 방어공백(coverage_gap) · 2순위 잔존/탐지단계(dwell) · 3순위 임계보정(calibration).
(4~6순위: MITRE 커버리지·RoE 준수·재타격 효율 — 후속.)
"""
from .metrics import calibration, coverage_gap, dwell, full_report

__all__ = ["calibration", "coverage_gap", "dwell", "full_report"]
