#!/usr/bin/env python3
"""APT 에뮬레이션 데모 — 고도화 §O (APT 패턴 참조·실행).

    python benchmarks/apt_emulation_eval.py

각 APT의 순서 킬체인을 '그 APT로서' 실행 → blue가 어디서 잡나 산출.
결정론·무의존. 실 플랜: env CTID_PLAN_URL.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.integrations import apt_emulation as apt          # noqa: E402


def main() -> None:
    print("=== fried-pollack-ai · APT 에뮬레이션 §O ===")
    print(f"CTID: {apt.status()['mode']} · APT 프로파일 {apt.status()['apt_profiles']}개\n")
    for actor in apt.APT_EMULATION:
        r = apt.run_apt_emulation(actor)
        head = "🥷 은밀 관통" if r.verdict == "stealthy" else "🔴 탐지됨"
        flow = " → ".join(
            f"{s}{'(사각)' if d is None else '(탐지)' if d else '(회피)'}" for s, d in r.steps)
        note = f"  ← {', '.join(r.detected_at)}에서 탐지" if r.detected_at else ""
        print(f"[{actor}] {head}")
        print(f"     {flow}{note}\n")
    print("해석: 실 APT 킬체인 순서로 에뮬레이션 → blue 방어가 각 APT를 어디서 잡는지 실증.")
    print("      AML Adversary(AI 계열)는 전 단계 미배포 = 완전 은밀 → AI 계층 방어 최우선.")
    print("      한국 방산 관련 Lazarus·Kimsuky 포함(DPRK ROK 표적).")


if __name__ == "__main__":
    main()
