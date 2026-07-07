"""(6c) Policy Broker — read/write 분할 (§1.4(6)·AgenTRIM 2601.12449).

스텝별 최소권한·상태인지 게이팅. read는 자유, write는 등급상승(§route_to_hitl).
"""

from __future__ import annotations


def broker(state) -> dict:
    plan = state["current_plan"]
    if plan is None:
        return {}
    cmd = plan["command"]
    plan["access"] = "read" if cmd.risk_tier == "read" else "write"
    return {"current_plan": plan}
