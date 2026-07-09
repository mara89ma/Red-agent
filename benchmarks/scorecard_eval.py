#!/usr/bin/env python3
"""레드팀 KPI 벤치마크 스코어카드 데모 — 한 번 실행 = 7카테고리 + 목표대비 rating.

    python benchmarks/scorecard_eval.py

벤더/SW 종속 0. 전부 §P KPI 결정론 산출.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.benchmark import format_scorecard, kpi_scorecard   # noqa: E402


def main() -> None:
    print("=== fried-pollack-ai · 레드팀 KPI 벤치마크 §Y ===\n")
    print(format_scorecard(kpi_scorecard()))


if __name__ == "__main__":
    main()
