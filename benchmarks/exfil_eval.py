#!/usr/bin/env python3
"""데이터 유출 시나리오 데모 — S35~S38 (암호키 포함).

    python benchmarks/exfil_eval.py

전용 유출 시나리오를 에이전트로 실행. 결정론·무의존.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.exfil import EXFIL_SCENARIOS, run_exfil        # noqa: E402
from redteam_core.campaigns import run_chain                      # noqa: E402


def main() -> None:
    print("=== fried-pollack-ai · 데이터 유출 시나리오 S35~S38 ===\n")
    print(f"  {'#':<5}{'시나리오':<20}{'MITRE':<14}{'결과':<10}{'탐지'}")
    for sid in EXFIL_SCENARIOS:
        r = run_exfil(sid)
        det = {True: "🔴 탐지", False: "🟢 회피", None: "⚪ 사각지대"}[r["detected"]]
        print(f"  {sid:<5}{r['name']:<20}{r['mitre']:<14}{r['verdict']:<10}{det}")

    print("\n유출 캠페인:")
    for cid in ("C11", "C12"):
        cr = run_chain(cid)
        head = {"stealthy": "🥷 은밀", "detected": "🔴 탐지", "blocked": "⛔ 차단"}[cr.verdict]
        flow = "→".join(s for s, _, _ in cr.stages)
        print(f"  {cid}: {flow}  {head}")

    print("\n핵심: 유출 계열(S35~S38) 전용 탐지룰 미배포 = 사각지대. "
          "특히 S38 암호키 유출 → MAVLink 서명키 탈취 → 서명 위조로 S18(무서명 탐지) 우회.")
    print("      → 방어 보강: 유출량/채널 이상 탐지 + 키 접근 감사 + 서명키 로테이션.")


if __name__ == "__main__":
    main()
