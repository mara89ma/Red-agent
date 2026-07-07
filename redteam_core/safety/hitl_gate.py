"""(11) HITL 게이트 (§2.8) — 두 실행기 공용.

    • hitl_gate            — 동기 콜백(`state["approver"]`) 버전. stdlib 러너용.
    • hitl_gate_interrupt  — LangGraph `interrupt()` 버전. 그래프를 실제로 일시정지하고
                             운용자가 out-of-band(UI/API)로 승인할 때까지 대기 후 재개.

두 버전 모두 동일한 **승인 컨텍스트(dict)** 를 만든다 → approver/interrupt payload 계약 통일.
승인 + `physical_irreversible`일 때만 Gate가 단발 토큰을 발급(§2.5 ④ executor 2중 방어와 짝).
"""

from __future__ import annotations

import time


def _hitl_context(node) -> dict:
    """콜백 approver와 interrupt payload가 공유하는 승인 요청 컨텍스트."""
    irreversible = node.risk_tier == "physical_irreversible"
    return {
        "action": "approve_irreversible" if irreversible else "approve_write",
        "node_id": node.id,
        "atomic_action": node.action,
        "risk_tier": node.risk_tier,
        "reversibility": node.reversibility,
        "physical_irreversible": irreversible,
        "message": (f"[{node.risk_tier}] {node.action} 실행 전 운용자 승인 필요"
                    + (" — 물리 비가역(인간 전용)" if irreversible else "")),
    }


def _coerce_approved(decision) -> bool:
    """approver/resume 값이 bool·str·dict 무엇이든 승인 여부로 정규화."""
    if isinstance(decision, bool):
        return decision
    if isinstance(decision, str):
        return decision.strip().lower() in ("approved", "approve", "yes", "y", "true", "ok")
    if isinstance(decision, dict):
        if "approved" in decision:
            return bool(decision["approved"])
        return _coerce_approved(decision.get("decision", ""))
    return False


def _finalize(state, node, gate, approved: bool) -> dict:
    """승인/거부 확정 — 감사 기록 + (승인·비가역이면) 토큰 발급 + 상태 갱신."""
    node.approval = "approved" if approved else "denied"
    state["audit_log"].append({"event": "hitl", "node": node.id, "action": node.action,
                               "risk_tier": node.risk_tier, "decision": node.approval,
                               "ts": time.time()})
    if approved and node.risk_tier == "physical_irreversible":
        gate.issue_token(node.id, approver="operator", ttl_s=120.0)   # 단발·노드바인딩·만료
    return {"ptg": state["ptg"], "audit_log": state["audit_log"],
            "checker_verdict": state["checker_verdict"],
            "pending_approval": None, "_hitl_decision": node.approval}


def hitl_gate(state) -> dict:
    """동기 콜백 HITL(stdlib 러너). state['approver'](ctx)->결정."""
    node = state["ptg"][state["current_plan"]["node_id"]]
    gate = state["gate"]
    approver = state.get("approver") or (lambda ctx: "denied")
    node.approval = "pending"
    state["pending_approval"] = node.id
    decision = approver(_hitl_context(node))          # 인간 결정(데모: 콜백)
    return _finalize(state, node, gate, _coerce_approved(decision))


def hitl_gate_interrupt(state) -> dict:
    """LangGraph interrupt HITL — 그래프를 멈추고 승인 값이 resume될 때까지 대기."""
    from langgraph.types import interrupt      # 지연 import(langgraph 선택 의존성)

    node = state["ptg"][state["current_plan"]["node_id"]]
    gate = state["gate"]
    node.approval = "pending"
    state["pending_approval"] = node.id
    decision = interrupt(_hitl_context(node))   # ← 여기서 그래프 일시정지(체크포인트)
    return _finalize(state, node, gate, _coerce_approved(decision))
