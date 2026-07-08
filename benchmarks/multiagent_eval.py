#!/usr/bin/env python3
"""멀티에이전트 레드팀 데모 — 고도화 §Q (recon/exploit/C2 역할 협업).

    python benchmarks/multiagent_eval.py

역할 에이전트가 담당 층을 호출하며 킬체인 협업. 결정론·무의존.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.orchestration import run_cmt_campaign      # noqa: E402

OBJECTIVES = ["nav_jam_denial", "recon_access", "weapon_effect", "soc_llm_inject"]


def main() -> None:
    print("=== fried-pollack-ai · 사이버전투임무팀(CMT) — 미군 사이버작전 조직 ===\n")
    for obj in OBJECTIVES:
        r = run_cmt_campaign(obj)
        head = ("🥷 은밀 성공" if r.stealthy else "✅ 성공(탐지)" if r.success else "⛔ 실패")
        print(f"[{obj}] {head}  (권한 {'승인' if r.authorized else '차단'})")
        for role in r.roles:
            print(f"   {role.role:<5}{role.title:<32}: {role.summary}")
        print()
    print("직무 협업: MC(교전권한 §B) → TDNA(표적개발 §F·TI) → ION(온넷실행 §E) → BDA(§D·§A).")
    print("교리: USCYBERCOM 사이버임무군(CMF) OCO 수행 CMT.")


if __name__ == "__main__":
    main()
