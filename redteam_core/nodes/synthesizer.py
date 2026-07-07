"""(6a) Cmd Synth — think-augmented 인자 추론 (§1.4(6)·§2.4).

정적 KB(rag/static_kb.py) 스펙에 맞춰 원자 명령을 조립(인자 환각 방지).
`think` 필드에 근거를 남기되, 실행 페이로드에서는 제거된다(감사만).
"""

from __future__ import annotations

from ..rag import static_kb
from ..tools.mavlink import build_command


def synthesizer(state) -> dict:
    plan = state["current_plan"]
    if plan is None:
        return {}
    node = state["ptg"][plan["node_id"]]
    profile = state["profile"]
    sysid = profile["target_profile"]["hosts"][0].get("sysid", 1)

    spec = static_kb.spec_for(node.action)               # untrusted 스펙
    think = (f"action={node.action}; kb.cmd={spec.get('cmd')}; "
             f"params_semantics={spec.get('params')}; sysid∈allowlist 대상")
    cmd = build_command(node.action, sysid, think, params=plan.get("params"))

    plan["command"] = cmd                                # Checker/Broker/Executor가 사용
    plan["technique"] = spec.get("technique", node.technique)
    return {"current_plan": plan}
