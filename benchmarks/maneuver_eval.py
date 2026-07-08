#!/usr/bin/env python3
"""기동/측면이동 데모 — 고도화 §G (Movement & Maneuver).

    python benchmarks/maneuver_eval.py

지형을 순회하며 효과에 기동, 막히면 재경로. 결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.maneuver import run_campaign, ASSETS      # noqa: E402


def _name(aid: str) -> str:
    return ASSETS.get(aid, (aid, ""))[0]


def main() -> None:
    print("=== fried-pollack-ai · 기동/측면이동 — 고도화 §G (Movement & Maneuver) ===\n")
    for target in ("gnss_rcv", "weapon"):
        r = run_campaign(target)
        head = "✅ 도달" if r.verdict == "reached" else "⛔ 차단"
        print(f"[표적: {_name(target)}] {head}  (경로 시도 {r.attempts}회)")
        if r.winning_path:
            print("  경로: " + " → ".join(_name(a) for a in r.winning_path))
        for h in r.hops:
            mark = {"gained": "▸", "achieved": "✅", "blocked": "⛔"}[h.status]
            print(f"    {mark} [{h.phase:<16}] {_name(h.src)} → {_name(h.dst)}  · {h.detail}")
        print()
    print("교리: JP 3-12 사이버 기동 + ATT&CK 측면이동. 경로 차단 시 재경로(maneuver).")
    print("      무장은 기동 도달하나 최종 효과가 견고(범주형) → 차단 = blue 방어 실증.")


if __name__ == "__main__":
    main()
