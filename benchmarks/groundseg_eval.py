#!/usr/bin/env python3
"""지상 세그먼트 공격 데모 — GCS·ROS·데이터링크·클라우드 (S72~S85).

    python benchmarks/groundseg_eval.py

결정론·무의존(dry). 실 공격은 표적 env + §T 샌드박스.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.groundseg import GROUND_SCENARIOS, run_ground, surfaces   # noqa: E402
from redteam_core.campaigns import run_chain                                 # noqa: E402


def main() -> None:
    print("=== fried-pollack-ai · 지상 세그먼트 소프트웨어 공격 ===\n")
    for surf, info in surfaces().items():
        print(f"[{info['label']}]")
        for sid in info["scenarios"]:
            r = run_ground(sid, dry=True)
            print(f"   {sid} {GROUND_SCENARIOS[sid]['name']:<24} → {r.artifact[:52]}")
        print()

    print("지상 세그먼트 킬체인:")
    for cid in ("C19", "C20"):
        cr = run_chain(cid)
        icon = {"stealthy": "🥷", "detected": "🔴", "blocked": "⛔"}[cr.verdict]
        flow = "→".join(s for s, _, _ in cr.stages)
        print(f"   {cid}: {flow}  {icon} {cr.verdict}")

    print("\n핵심: 지상 소프트웨어(GCS·ROS·데이터링크·클라우드)는 UAV Sentinel이 감시하는")
    print("      텔레메트리/공중 평면 밖 = 전부 사각지대. 공중만 방어하면 지상으로 관통.")


if __name__ == "__main__":
    main()
