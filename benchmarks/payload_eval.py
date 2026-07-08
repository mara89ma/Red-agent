#!/usr/bin/env python3
"""ML 공격 페이로드 생성 데모 — 고도화 §N (PyRIT/Garak 방식).

    python benchmarks/payload_eval.py

S32 프롬프트 인젝션 · S33 모델 추출 · S7 적대 패치의 구체 페이로드 생성.
결정론·무의존(Tier-0). 대상=시험창 내 자체 SOC(인가된 레드팀).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.payloads import (                          # noqa: E402
    generate_prompt_injections, generate_extraction_ladder, generate_adversarial_specs,
)


def main() -> None:
    print("=== fried-pollack-ai · ML 공격 페이로드 생성 — 고도화 §N ===\n")

    print("── S32 프롬프트 인젝션 (시드×컨버터) ──")
    pis = generate_prompt_injections(target="GNSS 스푸핑", converters=["none", "base64", "homoglyph"])
    for p in pis[:6]:
        preview = p.text[:60].replace("\n", " ")
        print(f"  [{p.pid}] {p.category:<20} {preview}")
    print(f"  ... 총 {len(pis)}개 생성\n")

    print("── S33 모델 추출 래더 ──")
    for q in generate_extraction_ladder():
        print(f"  {q.step}. [{q.intent:<18}] {q.query}")

    print("\n── S7 적대 패치 스펙 ──")
    for a in generate_adversarial_specs():
        print(f"  [{a.sid}] {a.patch_type:<8} @{a.location:<10} → {a.target_misclass}")

    print("\n대상=자체 SOC(pollack-ai) 방어 AI. 결정론 시드+컨버터(LLM 자유생성 X).")
    print("모두 blue 미매핑 = 사각지대(S32/S33/S7) → 방어 보강: LLM I/O·모델질의 탐지 신설.")


if __name__ == "__main__":
    main()
