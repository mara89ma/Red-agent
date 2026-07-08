#!/usr/bin/env python3
"""S30 — GNSS 재밍(항법 거부) 시나리오 실행 데모.

    python benchmarks/s30_gnss_jam_eval.py

신규 시나리오 S30을 에이전트로 실행: EMSO 재밍 물리(J/S) → 항법 거부 효과 →
blue 탐지 관측(미매핑 = 사각지대) → 전투평가(효과+생존=은밀 달성).
핵심: 재밍은 blue 룰에 안 잡혀 항상 은밀 관통 → 방어 보강 1순위(재밍 탐지룰 신설).
결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.assessment import run_engagement          # noqa: E402
from redteam_core.emso import plan_emso                       # noqa: E402

GNSS_L1 = 1575.42
CASES = [
    ("근접 고출력 재밍", {"jammer_eirp_dbm": 40, "jammer_dist_m": 100}),
    ("중거리 재밍", {"jammer_eirp_dbm": 30, "jammer_dist_m": 800}),
    ("원거리 저출력 재밍", {"jammer_eirp_dbm": -10, "jammer_dist_m": 20000}),
]


def main() -> None:
    print("=== fried-pollack-ai · S30 GNSS 재밍(항법 거부) 시나리오 ===")
    print("EMSO J/S 물리 → 항법거부 → blue 탐지(사각지대) → 전투평가\n")
    print(f"  {'시나리오':<16}{'J/S(dB)':<10}{'효과':<7}{'blue탐지':<10}{'종합':<8}{'재타격'}")
    for label, geom in CASES:
        g = {**geom, "signal_eirp_dbm": 16, "signal_dist_m": 20000, "freq_mhz": GNSS_L1}
        js = plan_emso("jam", g).effect.metric_db
        ca = run_engagement("jam", geometry=g)
        det = {True: "탐지", False: "회피", None: "사각지대"}[ca.detected]
        print(f"  {label:<16}{js:<10}{_b(ca.moe_effect):<7}{det:<10}"
              f"{_b(ca.effective):<8}{ca.reattack.adjustment}")
    print("\n판정: 효과 달성(J/S≥번스루) 시 blue 룰 미매핑 → 항상 은밀 관통(효과+생존).")
    print("      S30은 에이전트로 실행 검증됨 → 5장 방어 보강 1순위: GNSS 재밍 탐지룰 신설.")


def _b(x) -> str:
    return {True: "○", False: "✗", None: "-"}[x]


if __name__ == "__main__":
    main()
