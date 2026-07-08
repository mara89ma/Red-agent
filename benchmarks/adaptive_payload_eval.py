#!/usr/bin/env python3
"""상황 맞춤 페이로드 생성 데모 — 고도화 §N-adaptive.

    python benchmarks/adaptive_payload_eval.py

SituationContext(표적 룰·실제 워치리스트·임계)를 받아 그 상황에 특정된 페이로드를
결정론 조립. 고정 시드 대비 '겨냥 룰의 예외 워치리스트 사칭·실제 임계 키 삽입'을 보여줌.
결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.payloads import (                          # noqa: E402
    AdaptivePayloadGenerator, SituationContext, run_adaptive, bypass_rate,
)

CASES = [
    SituationContext(scenario="S32", target_rule="S1_GNSS_Spoofing"),
    SituationContext(scenario="S32", target_rule="S6_Operator_BruteForce"),
    SituationContext(scenario="S33", target_rule="S1_GNSS_Spoofing"),
]


def main() -> None:
    gen = AdaptivePayloadGenerator()
    print("=== fried-pollack-ai · 상황 맞춤 페이로드 — 고도화 §N-adaptive ===\n")
    for ctx in CASES:
        print(f"[{ctx.scenario} → 표적룰 {ctx.target_rule}]")
        for p in gen.generate(ctx):
            print(f"  • {p.text}")
            print(f"    ↳ 적응근거: {p.rationale}")
            if p.variants:
                print(f"    ↳ 변형(homoglyph): {p.variants[0][:50]}…")
        outs = run_adaptive(ctx)
        print(f"    ↳ 실행 우회율: {bypass_rate(outs)*100:.0f}% ({len(outs)}개)\n")

    print("고정 시드와 달리 겨냥 룰의 실제 워치리스트/임계/필드를 반영 → 표적 특정.")
    print("LLM 키(ADAPTIVE_PAYLOAD_LLM=1) 있으면 변형 추가, 없으면 결정론 폴백.")


if __name__ == "__main__":
    main()
