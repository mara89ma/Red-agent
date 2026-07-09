"""외부 벤치마크 어댑터 — xbow·Cybench·NYU CTF·CyberSecEval·garak seam.

우리 계층을 외부 표준 벤치마크에 매핑(발표 근거·상호검증). env 지정 시 실 연동,
아니면 참조 테이블. 실 실행(도커/네트워크)은 §T 샌드박스 통과 시에만.
"""
from __future__ import annotations

import os
from typing import List

# 외부 벤치마크 → 우리 계층 매핑
EXTERNAL_BENCHMARKS = [
    {"name": "xbow validation-benchmarks", "kind": "web CTF(104)", "env": "XBOW_PATH",
     "maps": "§exploits S48~S52·§X toolsearch", "note": "flag 캡처 오라클"},
    {"name": "Cybench", "kind": "CTF agent(40)", "env": "CYBENCH_PATH",
     "maps": "에이전트 파이프라인 전체", "note": "난이도·서브태스크 채점"},
    {"name": "NYU CTF Bench", "kind": "CTF(200)", "env": "NYUCTF_PATH",
     "maps": "§exploits·§K/§L", "note": "카테고리별"},
    {"name": "CyberSecEval", "kind": "LLM 오펜시브", "env": "CYBERSECEVAL_PATH",
     "maps": "§N payloads·§Q integrations", "note": "공격 능력·거부율"},
    {"name": "garak", "kind": "LLM 취약점 프로브", "env": "GARAK_TARGET",
     "maps": "§N S32/S33·ai_attack", "note": "인젝션·추출 프로브"},
    {"name": "AgentDojo", "kind": "프롬프트 인젝션", "env": "AGENTDOJO_PATH",
     "maps": "§N S32", "note": "간접 인젝션 스위트"},
]


def external_status() -> List[dict]:
    """각 외부 벤치마크의 연동 가용성(env)·모드."""
    out = []
    for b in EXTERNAL_BENCHMARKS:
        avail = bool(os.environ.get(b["env"]))
        out.append({"name": b["name"], "kind": b["kind"], "maps": b["maps"],
                    "mode": "real" if avail else "reference", "env": b["env"]})
    return out
