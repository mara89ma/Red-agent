#!/usr/bin/env python3
"""§Q 실도구 실행 + §T 샌드박스 가드 데모 — detonate-before-live.

    python benchmarks/sandbox_guard_eval.py

실 도구(PyRIT/Caldera) 실행 전 샌드박스 폭파 → 스코프 내·봉인일 때만 실행, 아니면 차단.
결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.sandbox import SandboxPolicy, ai_spec, caldera_spec, guarded   # noqa: E402

_SCOPE = SandboxPolicy(allowed_cidrs=["10.50.0.0/24"])


def _live():   # 실 도구 실행을 대신하는 마커
    return {"mode": "real", "note": "실 도구 실행됨"}


CASES = [
    ("AI 공격 → 스코프 내 LLM", ai_spec("prompt_injection", "http://10.50.0.30:8000")),
    ("AI 공격 → 스코프 밖 LLM", ai_spec("prompt_injection", "http://203.0.113.66:8000")),
    ("Caldera → 스코프 내 서버", caldera_spec("C1", "http://10.50.0.40:8888")),
    ("Caldera → 도메인(해석필요)", caldera_spec("C1", "https://caldera.example.com")),
]


def main():
    print("=== fried-pollack-ai · §Q 실도구 + §T 샌드박스 가드 ===")
    print("detonate-before-live: 스코프 내·봉인일 때만 실 실행, 아니면 fail-closed\n")
    for label, spec in CASES:
        r = guarded(spec, _live, _SCOPE)
        if r["mode"] == "real":
            print(f"  🟢 {label:<26} → 실 실행 허용")
        else:
            print(f"  ⛔ {label:<26} → 차단(blocked_by_sandbox) · {r.get('egress_blocked')}")
    print("\n판정: 실 도구/페이로드는 반드시 §T 샌드박스를 통과해야 §Q 라이브 실행. 스코프 밖=차단.")


if __name__ == "__main__":
    main()
