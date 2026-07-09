#!/usr/bin/env python3
"""xbow식 능력 벤치마크 §Y 데모 — UAV 스위트·탐지회피 채점·외부 어댑터.

    python benchmarks/benchmark_eval.py

성공 오라클 = 목표달성 AND blue 미탐지(폐루프). 결정론·무의존.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.benchmark import (                             # noqa: E402
    UAV_BENCHMARKS, external_status, run_suite,
)


def main() -> None:
    print("=== fried-pollack-ai · xbow식 능력 벤치마크 §Y ===\n")
    sb = run_suite(UAV_BENCHMARKS)

    print("① UAV 도메인 스위트 (오라클=달성 AND 미탐지)")
    icon = {"stealthy": "🥷", "detected": "🔴", "blocked": "⛔"}
    for r in sb.results:
        print(f"   {r.bid:<4}T{r.difficulty} {r.name:<22} {icon[r.outcome]} {r.outcome:<9} "
              f"{r.score:.1f}/{r.max_score:.0f}")

    print(f"\n② 스코어보드")
    print(f"   챌린지 {len(sb.results)}개 · 관통 {sb.captured} · 은밀 {sb.stealthy}")
    print(f"   탐지회피 점수 {sb.total_score:.1f}/{sb.max_score:.0f} = {sb.evasion_pct}%")
    for tier, d in sorted(sb.by_tier().items()):
        print(f"   Tier {tier}: {d['stealthy']}/{d['n']} 은밀 관통")

    print("\n③ 외부 벤치마크 어댑터")
    for b in external_status():
        print(f"   {b['name']:<28} [{b['mode']:<9}] {b['kind']:<16} → {b['maps']}")

    print("\n핵심: 'flag 캡처'가 아니라 '달성 AND 미탐지'로 채점(폐루프 차별점).")
    print(f"      은밀 관통률이 방어 사각지대를 정량화 — Tier↑일수록 배점↑.")


if __name__ == "__main__":
    main()
