#!/usr/bin/env python3
"""공격 템포 데모 — 고도화 §P (시간-탐지 트레이드오프).

    python benchmarks/tempo_eval.py

smash-and-grab vs low-and-slow 를 대표 액션에 적용. 결정론·무의존.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.tempo import tempo_tradeoff          # noqa: E402

ACTIONS = [("active_scan", "S6 브루트포스"), ("gnss_spoof", "S1 GNSS 스푸핑"),
           ("spoof_telemetry", "S18 MAVLink")]


def main() -> None:
    print("=== fried-pollack-ai · 공격 템포 §P (시간-탐지 트레이드오프) ===\n")
    print(f"  {'액션':<20}{'템포':<18}{'강도':<9}{'탐지':<8}{'효과까지(분)':<14}{'MTTD(분)'}")
    for action, label in ACTIONS:
        tr = tempo_tradeoff(action)
        for tempo, r in tr.items():
            det = {True: "탐지", False: "회피", None: "사각"}[r.detected]
            mttd = "∞" if r.mttd_min is None else r.mttd_min
            print(f"  {label:<20}{tempo:<18}{r.intensity:<9}{det:<8}"
                  f"{r.time_to_effect_min:<14}{mttd}")
        print()
    print("핵심: low-and-slow 는 임계 아래로 회피(∞ MTTD)하나 효과까지 시간↑. "
          "smash 는 즉효이나 즉시 탐지. → 방어는 '누적 저율' 탐지가 필요.")


if __name__ == "__main__":
    main()
