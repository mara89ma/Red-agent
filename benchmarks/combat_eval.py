#!/usr/bin/env python3
"""전투평가 데모 — 고도화 §D (JP 3-60 ⑥ MOE/MOP·재타격권고).

    python benchmarks/combat_eval.py

§C EMSO 효과 → §A 탐지 → ⑥단계 전투평가(MOP·MOE·생존성)·재타격권고를 표로.
결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.assessment import run_engagement, assess_combat   # noqa: E402

# (라벨, 호출)
CASES = [
    ("근접 고출력 스푸핑", lambda: run_engagement("gnss_spoof", geometry={"spoof_eirp_dbm": 20, "spoof_dist_m": 100})),
    ("원거리 저출력 스푸핑", lambda: run_engagement("gnss_spoof", geometry={"spoof_eirp_dbm": -20, "spoof_dist_m": 20000})),
    ("무장(범주형)", lambda: assess_combat("force_arm", executed=True, effect_achieved=True, detected=True, adaptable=False)),
    ("정찰(사각지대)", lambda: assess_combat("param_read", executed=True, effect_achieved=True, detected=None, adaptable=False)),
]


def main() -> None:
    print("=== fried-pollack-ai · 전투평가 — 고도화 §D (JP 3-60 ⑥) ===")
    print("MOP=임무수행 · MOE=효과 · 생존=미탐지 · 종합=효과+생존\n")
    print(f"  {'교전':<18}{'MOP':<6}{'효과':<6}{'생존':<6}{'종합':<7}{'재타격권고'}")
    for label, fn in CASES:
        ca = fn()
        rec = f"{ca.reattack.adjustment} — {ca.reattack.rationale}" if ca.reattack.needed else "불요"
        print(f"  {label:<18}{_b(ca.mop_executed):<6}{_b(ca.moe_effect):<6}"
              f"{_b(ca.moe_survivability):<6}{_b(ca.effective):<7}{rec}")
    print("\n교리: 공격측 MOE = 효과달성 + 생존성(미탐지). 미달 유형별 재타격권고(⑥단계).")


def _b(x) -> str:
    return {True: "○", False: "✗", None: "-"}[x]


if __name__ == "__main__":
    main()
