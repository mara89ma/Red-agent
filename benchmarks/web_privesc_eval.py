#!/usr/bin/env python3
"""Web/API·Linux 권한상승 신규 시나리오 데모 — S48~S52 + §T 분석 + 배선.

    python benchmarks/web_privesc_eval.py

red 익스플로잇(§N exploits) → run_exploit 배선 → §T 정적 분석 판정.
blue UAV Sentinel 사각지대(IT 계층)를 §T 가 커버. 결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.campaigns import run_chain                                 # noqa: E402
from redteam_core.payloads.exploits import EXPLOIT_SCENARIOS, run_exploit    # noqa: E402


def main():
    print("=== fried-pollack-ai · Web/API·Linux 권한상승 (S48~S52) + §T 분석 ===\n")
    print(f"  {'시나리오':<7}{'기법':<9}{'판정':<13}{'지표'}")
    for sid in EXPLOIT_SCENARIOS:
        o = run_exploit(sid)
        mark = {"malicious": "🔴", "suspicious": "🟠", "benign": "🟢"}[o["sandbox_verdict"]]
        tag = mark + (" ⚪사각" if o["blind_spot"] else "")
        ind = o["indicators"][0] if o["indicators"] else "-"
        print(f"  {sid:<7}{o['kind']:<9}{tag:<13}{ind}")

    print("\n=== IT 킬체인 C13 (자격증명→웹셸→컨테이너escape→cron) ===")
    r = run_chain("C13")
    print(f"  판정={r.verdict} · 단계={[(s, d) for s, _, d in r.stages]}")
    print("\n판정: 웹셸·역직렬화·escape·SUID·cron = §T 탐지 / IDOR = blue 사각지대.")
    print("      전부 UAV Sentinel 룰 밖 IT 계층 → C13 은 blue SOC 에 거의 안 보임(방어 공백).")


if __name__ == "__main__":
    main()
