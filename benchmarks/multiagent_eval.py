#!/usr/bin/env python3
"""멀티에이전트 레드팀 데모 — 고도화 §Q (recon/exploit/C2 역할 협업).

    python benchmarks/multiagent_eval.py

역할 에이전트가 담당 층을 호출하며 킬체인 협업. 결정론·무의존.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.orchestration import run_multi_agent_campaign      # noqa: E402

OBJECTIVES = ["nav_jam_denial", "recon_access", "weapon_effect", "soc_llm_inject"]


def main() -> None:
    print("=== fried-pollack-ai · 멀티에이전트 레드팀 §Q ===\n")
    for obj in OBJECTIVES:
        r = run_multi_agent_campaign(obj)
        head = ("🥷 은밀 성공" if r.stealthy else "✅ 성공(탐지)" if r.success else "⛔ 실패")
        print(f"[{obj}] {head}")
        for role in r.roles:
            print(f"   {role.role:<9}: {role.summary}")
        print()
    print("역할 분담: recon(§F+TI 표적/위협) → exploit(§E 적응교전) → C2(§O 연동).")


if __name__ == "__main__":
    main()
