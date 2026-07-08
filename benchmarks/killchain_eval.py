#!/usr/bin/env python3
"""킬체인 관통 데모 — 고도화 §J (7단계 end-to-end).

    python benchmarks/killchain_eval.py

정찰→무기화→전달→악용→설치지속→C2→목표행동을 순서 수행하고 완전/은밀 관통 판정.
결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.killchain import run_killchain      # noqa: E402

CASES = [
    ("GNSS · 은밀기법", "gnss_rcv", "credential_foothold", "common_port"),
    ("GNSS · 소란기법", "gnss_rcv", "firmware_implant", "rogue_router"),
    ("무장 · 은밀기법", "weapon", "credential_foothold", "common_port"),
]


def main() -> None:
    print("=== fried-pollack-ai · 킬체인 7단계 관통 — 고도화 §J ===\n")
    for label, target, persist, c2 in CASES:
        r = run_killchain(target, persistence=persist, c2=c2)
        verdict = ("🥷 은밀 관통" if r.stealthy else
                   "✅ 완전 관통(탐지됨)" if r.completed else "⛔ 미완주")
        print(f"[{label}] {verdict}")
        for s in r.stages:
            mark = {"수행": "✅", "탐지": "🔴", "차단": "⛔"}[s.status]
            print(f"    {mark} {s.stage:<10} {s.detail}")
        print()
    print("판정: 은밀기법(유효계정 발판·상용포트 C2)=사각지대 → 은밀 관통 가능.")
    print("      소란기법(임플란트·불량라우터)=blue S4/S21/S26 탐지 → 관통하나 노출.")
    print("      무장 목표행동은 범주형(견고) → 6단계까지 가도 최종 차단 = 미완주.")


if __name__ == "__main__":
    main()
