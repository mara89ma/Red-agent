#!/usr/bin/env python3
"""빈 번호 채움 시나리오 데모 — S22·S28·S63~S65·S74~S85 (17개).

    python benchmarks/extended_eval.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.extended import EXTENDED_SCENARIOS, run_extended, themes   # noqa: E402


def main() -> None:
    print("=== 빈 번호 채움 시나리오 (17개, 전부 사각지대) ===\n")
    for theme, sids in themes().items():
        print(f"[{theme}]")
        for sid in sorted(sids, key=lambda x: int(x[1:])):
            r = run_extended(sid)
            print(f"   {sid} {r.name:<34} {r.mitre}")
        print()
    nums = sorted(int(s[1:]) for s in EXTENDED_SCENARIOS)
    print(f"채운 번호: {['S%d' % n for n in nums]}")
    print("→ 이제 S1~S102 연속(빈 번호 0).")


if __name__ == "__main__":
    main()
