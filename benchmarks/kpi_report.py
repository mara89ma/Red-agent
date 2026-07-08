#!/usr/bin/env python3
"""KPI 대시보드 — 1~3순위 (방어공백·잔존·임계보정).

    python benchmarks/kpi_report.py

기존 층 원자값을 집계해 레드팀 KPI를 한 화면에 출력. 결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.kpi import calibration, coverage_gap, dwell      # noqa: E402


def main() -> None:
    print("=== fried-pollack-ai · 레드팀 KPI 대시보드 (1~3순위) ===\n")

    cg = coverage_gap()
    print("① 방어 공백 지표 (Blue Coverage Gap)")
    print(f"   사각지대율      : {cg['blind_spot_ratio']*100:.0f}%  "
          f"({len(cg['blind_spots'])}/{cg['total_scenarios']}) → {', '.join(cg['blind_spots'])}")
    print(f"   회피가능율      : {cg['evadable_ratio']*100:.0f}%  → {', '.join(cg['evadable'])}")
    print(f"   은밀관통 캠페인 : {cg['stealthy_campaign_ratio']*100:.0f}%  "
          f"({len(cg['stealthy_campaigns'])}/{cg['total_campaigns']}) → {', '.join(cg['stealthy_campaigns'])}")

    print("\n② 공격자 잔존 / 탐지까지 단계 (dwell)")
    for cid, steps in dwell().items():
        print(f"   {cid:<5}: {'∞ (미탐지)' if steps is None else f'{steps}단계에서 탐지'}")

    print("\n③ 임계 실측 보정 기여 (Calibration)")
    print(f"   {'룰':<28}{'param':<20}{'실측경계':>9}{'가상값':>9}{'오차':>9}")
    for r in calibration():
        print(f"   {r['rule']:<28}{r['param']:<20}"
              f"{_f(r['measured_boundary']):>9}{_f(r['blue_assumed']):>9}{_f(r['abs_error']):>9}")

    print("\n요약: 사각지대(EW·AI)와 완전 은밀 캠페인(C9)이 방어 최우선 보강. "
          "임계 보정은 UAV_Threshold_List 갱신으로 반영.")


def _f(x) -> str:
    return "-" if x is None else f"{x:g}"


if __name__ == "__main__":
    main()
