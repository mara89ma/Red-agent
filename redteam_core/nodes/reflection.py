"""(8) Reflection/Loop-Detector — 실패분류·루프탐지 (§1.4·§2.5).

원자 노드 결과를 확정하고, 다음 원자 노드(continue) / 신규자산(rescan) /
완료·캡(stop)을 결정한다. 궤적 로그로 안전 진단(AgentDoG 2601.18491).
"""

from __future__ import annotations

from ..tools.ml_target import STAGED_ONLY_ACTIONS

_IRREVERSIBLE = {"takeoff", "disarm", "flight_terminate"}


def reflection(state) -> dict:
    plan = state["current_plan"]
    node = state["ptg"][plan["node_id"]]
    sc = state["scorecard"]
    verdict = state.get("checker_verdict", "ok")
    hitl = state.get("_hitl_decision")
    val = state.get("last_validation")

    # --- 노드 상태 확정 ----------------------------------------------------
    if verdict == "violation":
        node.status = "failed"
        node.findings.append("scope/구문 위반 — Checker 차단")
    elif hitl == "denied":
        node.status = "blocked"
        node.findings.append("HITL 인간 전용 게이트 도달 — 미실행(안전)")
        # achieved-state: 물리 비가역 능력이 '게이트 도달'로 검증됨(§2.9 실집행 아님)
        if node.action in _IRREVERSIBLE:
            sc.missionkill_capability_reached_gate = True
    elif state.get("_executed") is False and node.status == "blocked":
        if node.action in STAGED_ONLY_ACTIONS:
            pass                                         # executor가 이미 스테이징 게이트 기록
        else:
            node.findings.append("토큰 없음 — executor 거부(2중 방어)")
            if node.action in _IRREVERSIBLE:
                sc.missionkill_capability_reached_gate = True
    elif val is not None:
        node.status = "success" if val["verified"] else "failed"
        node.physical_state = val["evidence"]["truth_snapshot"]
        state["memory"].record_episode(node.task, node.action,
                                       "success" if val["verified"] else "failed")

    # 제어 획득 판정 (set_mode ∧ force_arm 모두 성공)
    ok = {n.action for n in state["ptg"].values() if n.status == "success"}
    if {"set_mode", "force_arm"} <= ok:
        sc.control_gained = True

    # HITL 카운트
    if hitl in ("approved", "denied"):
        sc.hitl_prompts += 1
        if hitl == "approved":
            sc.hitl_approved += 1

    # --- 큐 전진 + 라우팅 --------------------------------------------------
    if state["plan_queue"] and state["plan_queue"][0] == node.id:
        state["plan_queue"].pop(0)

    # 절차 메모리 효용 게이트(§2.3) — 킬체인 종료 시 playbook 성패를 반영.
    # 다음 engagement에서 planner가 이 효용을 참조해 재사용 여부를 판단한다(M3 DoD).
    if not state["plan_queue"]:
        abstract = state.get("_abstract_action")
        if abstract:
            success = any(n.status == "success" and n.action != "recon_heartbeat"
                          for n in state["ptg"].values())
            state["memory"].promote_playbook(abstract, success=success)

    # 루프 탐지 — 동일 노드 3회 이상 재방문 시 정지
    seen = state.setdefault("_visits", {})
    seen[node.id] = seen.get(node.id, 0) + 1
    if seen[node.id] >= 3:
        state["stop_reason"] = "loop_detected"

    if state["gate"].budget_exhausted():
        state["stop_reason"] = state.get("stop_reason") or "budget_exhausted"

    # reset per-step 플래그 — 반환으로 채널을 명시 클리어(LangGraph 안전)
    state["last_validation"] = None
    state.pop("_hitl_decision", None)
    state.pop("_executed", None)
    return {"ptg": state["ptg"], "plan_queue": state["plan_queue"],
            "stop_reason": state.get("stop_reason"), "_visits": seen,
            "scorecard": state["scorecard"], "last_validation": None,
            "_hitl_decision": None, "_executed": None}


def route_after_reflection(state) -> str:
    if state.get("stop_reason"):
        return "stop"
    if not state["plan_queue"]:
        return "stop"
    # 신규 호스트 발견 시 rescan (데모엔 없음)
    if state.get("_new_host"):
        state["_new_host"] = False
        return "rescan"
    return "continue"
