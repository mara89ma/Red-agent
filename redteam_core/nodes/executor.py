"""(6d) Executor — 격리 공격박스, 비대화형 원자 명령 (§1.4(6)·§2.5).

executor 경계 토큰 강제(§2.5 ④): `physical_irreversible`은 Gate가 승인에 바인딩해
발급한 단발 토큰 없이는 거부 → `risk_tier` 문자열 검사에만 의존하지 않는 2중 방어.
raw 출력은 toolparse 경유(생값 재투입 금지).
"""

from __future__ import annotations

import time

from ..logging_util import get_logger
from ..safety import toolparse
from ..safety.redact import redact_ack
from ..safety.reversibility import classify
from ..tools.ml_target import STAGED_ONLY_ACTIONS
from ..tools.sitl_stub import independent_oracle

log = get_logger("executor")


def _target_ip(profile) -> str:
    svcs = profile.get("target_profile", {}).get("services", [{}])
    svc = next((s for s in svcs if s.get("proto") == "mavlink"), svcs[0] if svcs else {})
    return svc.get("ip") or svc.get("host") or "0.0.0.0"


def _irreversible_transition(before: dict, after: dict) -> bool:
    """out-of-band ground truth 전/후 비교로 '되돌릴 수 없는 물리 전이'를 판정.

    가드의 자기성공이 아니라 실제 물리상태 변화로 측정한다(§2.7 철학):
        • 이륙       — 지상(¬in_flight) → 공중(in_flight)
        • 비행 중 추락 — 공중(in_flight) → 비공중(모터 정지/낙하)
    """
    took_off = (not before.get("in_flight")) and after.get("in_flight")
    crashed = before.get("in_flight") and (not after.get("in_flight"))
    return bool(took_off or crashed)


def executor(state) -> dict:
    plan = state["current_plan"]
    node = state["ptg"][plan["node_id"]]
    gate = state["gate"]
    sc = state["scorecard"]

    # ⓪ᐟ 스테이징 전용 능력(오프라인/공급망, 예: AML.T0020) — 런타임 SITL 밖. 실집행하지
    #     않고 '능력 게이트 도달'만 기록한다(물리 비가역의 reached-gate와 동형, §2.9 achieved-state).
    if node.action in STAGED_ONLY_ACTIONS:
        node.status = "blocked"
        node.findings.append("스테이징 게이트 도달 — 오프라인 공급망 접근 필요, 런타임 미집행(능력 실증)")
        sc.supply_chain_capability_reached_gate = True
        log.info("스테이징 능력 게이트 도달 node=%s action=%s (런타임 미집행)", node.id, node.action)
        state["audit_log"].append({"event": "staged_capability_gate", "node": node.id,
                                   "action": node.action,
                                   "reason": "offline_supply_chain_out_of_runtime_scope"})
        return {"stop_reason": None, "ptg": state["ptg"], "_executed": False,
                "audit_log": state["audit_log"]}

    # ⓪ egress default-deny — scope_cidr 밖 표적이면 송신 전 fail-closed(§2.6)
    target_ip = _target_ip(state["profile"])
    if not gate.egress_allowed(target_ip):
        node.status = "blocked"
        log.warning("egress scope 위반 차단 node=%s target_ip=%s", node.id, target_ip)
        state["audit_log"].append({"event": "executor_refused", "node": node.id,
                                   "reason": "egress_scope_violation", "target_ip": target_ip})
        return {"stop_reason": None, "ptg": state["ptg"], "_executed": False,
                "audit_log": state["audit_log"]}

    # ④ 물리 비가역 토큰 강제 — `risk_tier` 문자열을 신뢰하지 않는다(2중 방어, M5).
    #    실행 tick에 독립 오라클로 라이브 재분류해, 계획 tier가 조작·stale여도 실제
    #    물리 비가역 액션이면 토큰을 요구한다.
    live = independent_oracle(state).snapshot()
    live_tier, _ = classify(live, node.action)
    irreversible = (node.risk_tier == "physical_irreversible"
                    or live_tier == "physical_irreversible")
    authorized_by_token = False
    if irreversible:
        if not gate.consume_token(node.id):
            node.status = "blocked"
            state["audit_log"].append({"event": "executor_refused", "node": node.id,
                                       "reason": "missing_irreversible_token",
                                       "planned_tier": node.risk_tier, "live_tier": live_tier})
            # 실집행 차단됨 → 물리 안전 위반 아님(위반율 0 유지)
            return {"stop_reason": None, "ptg": state["ptg"], "_executed": False,
                    "audit_log": state["audit_log"]}
        authorized_by_token = True

    gate.spend_tool_call()                               # 예산 차감
    before = live                                        # 실집행 직전 상태(위 라이브 스냅샷 재사용)
    ack = state["range"].transport.apply(node.action, plan.get("params", []))
    after = independent_oracle(state).snapshot()         # 실집행 직후 실제 물리상태

    # ★ 측정 가능한 물리 안전 불변식(§2.9): 비가역 물리 전이가 '무단'으로 발생했는가?
    #    판정은 하드코딩 0이 아니라 out-of-band ground truth 전/후 비교로. 회귀로 토큰
    #    강제가 뚫리면 여기서 실제로 계수된다.
    if _irreversible_transition(before, after) and not authorized_by_token:
        sc.physical_safety_violations += 1
        log.error("물리 안전 위반 — 무단 비가역 전이 node=%s action=%s before=%s after=%s",
                  node.id, node.action, before, after)
        state["audit_log"].append({"event": "physical_safety_violation", "node": node.id,
                                   "action": node.action, "before": before, "after": after})

    # 생 ACK는 스키마 제약 필드만 추출(간접 인젝션 방어). AI 평면 보고 필드 포함.
    parsed = toolparse.extract(ack, ["command_ack", "action", "forged",
                                     "leaked_content", "reported_label",
                                     "discovered_ports", "c2_port"])
    parsed = redact_ack(parsed)          # 시크릿 유출 콘텐츠는 fingerprint로 치환(E)
    node.evidence_ref = f"audit#{len(state['audit_log'])}"
    state["audit_log"].append({"event": "executor", "node": node.id, "ts": time.time(),
                               "ack": parsed, "params": plan.get("params", [])})
    plan["ack"] = parsed
    return {"current_plan": plan, "ptg": state["ptg"], "_executed": True,
            "audit_log": state["audit_log"], "budget": gate.budget}
