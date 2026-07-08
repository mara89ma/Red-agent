#!/usr/bin/env python3
"""캠페인 체인 상세 러너 데모 — C14~C18 단계별 페이로드·에스컬레이션·탐지.

    python benchmarks/chain_detail_eval.py

킬체인 상세(보고서/Notion)를 코드로 산출. 결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.campaigns import chain_detail                             # noqa: E402


def main():
    print("=== fried-pollack-ai · 캠페인 체인 상세 (C14~C18) ===\n")
    for c in ("C14", "C15", "C16", "C17", "C18"):
        d = chain_detail(c)
        mark = {"stealthy": "🥷", "detected": "🔴", "blocked": "⛔"}[d.verdict]
        print(f"{mark} {c} [{d.verdict}] 최초탐지={d.first_detected or '—'}")
        print(f"   {d.narrative}")
        for s in d.stages:
            det = "🔴탐지" if s.detected else "⚪사각"
            print(f"     {s.sid}[{s.layer}] {s.name} · {s.escalation} · {det}")
            print(f"        └ {s.payload}")
        print()


if __name__ == "__main__":
    main()
