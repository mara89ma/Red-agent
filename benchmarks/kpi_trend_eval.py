#!/usr/bin/env python3
"""레드팀 KPI 개선 데모 — 근거화 스코어카드 + 라운드별 추세.

    python benchmarks/kpi_trend_eval.py

목표 근거화(외부 벤치마크 정박) + 퍼플팀 갭클로저 추세 투영. 결정론.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.benchmark import (                             # noqa: E402
    format_scorecard, format_trend, kpi_scorecard, project_rounds,
)


def main() -> None:
    print("=== fried-pollack-ai · 레드팀 KPI 개선 §Y ===\n")
    print(format_scorecard(kpi_scorecard()))
    print()
    print(format_trend(project_rounds(4)))


if __name__ == "__main__":
    main()
