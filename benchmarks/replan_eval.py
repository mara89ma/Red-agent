#!/usr/bin/env python3
"""적응형 재계획 데모 — 고도화 §E (persistent engagement / OODA).

    python benchmarks/replan_eval.py

재타격권고를 실제 실행: 강도 하향/전환을 반복해 목표(효과+생존)를 달성하거나,
모든 TTP 가 견고하면 blocked. 결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.assessment import adaptive_engage, OBJECTIVES   # noqa: E402


def main() -> None:
    print("=== fried-pollack-ai · 적응형 재계획 — 고도화 §E (persistent engagement) ===")
    print("재타격권고 실행: lower_intensity / raise_intensity / switch_ttp → 목표 달성 or blocked\n")
    for obj in OBJECTIVES:
        r = adaptive_engage(obj)
        head = "✅ 달성" if r.verdict == "achieved" else "⛔ blocked"
        print(f"[{obj}] {head}" + (f" via {r.winning_ttp}" if r.winning_ttp else ""))
        for action, intensity, ca in r.trace:
            det = {True: "탐지", False: "회피", None: "사각"}[ca.detected]
            print(f"    {action:<20} intensity={intensity:<8} 효과={_b(ca.moe_effect)} "
                  f"{det:<5} → {ca.reattack.adjustment}")
        print()
    print("교리 통찰: 효과바닥 ≥ 탐지임계면 강도로 회피 불가 → TTP 전환(사각지대 노출).")
    print("           전 TTP 견고(범주형)면 blocked = blue 방어가 그 목표에 견고함을 실증.")


def _b(x) -> str:
    return "○" if x else "✗"


if __name__ == "__main__":
    main()
