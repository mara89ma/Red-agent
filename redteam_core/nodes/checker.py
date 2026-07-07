"""(6b) Checker — sysid/geo + 구문 검증 (§1.4(6)·§2.4).

`target_sysid ∉ allowlist`면 차단(AutoAttacker 2403.01038 Command Checker).
`think`는 실행 페이로드에서 제거(TAFC 2601.18282) — payload()가 이미 drop.
"""

from __future__ import annotations

from ..tools.mavlink import CMDLESS_ACTIONS


def checker(state) -> dict:
    plan = state["current_plan"]
    gate = state["gate"]
    if plan is None or "command" not in plan:
        return {"checker_verdict": "violation"}

    cmd = plan["command"]
    violations = []

    # ① sysid allowlist (Engagement Gate가 참조하는 하드 경계)
    if not gate.sysid_allowed(cmd.target_sysid):
        violations.append(f"sysid {cmd.target_sysid} ∉ allowlist")

    # ② 구문: 읽기 아닌 액션은 유효 cmd_id 필요(단 cmd 없는 액션은 면제 — RF/GNSS/AI 평면)
    if cmd.risk_tier != "read" and cmd.cmd_id == 0 and cmd.action not in CMDLESS_ACTIONS:
        violations.append(f"invalid cmd_id for {cmd.action}")

    # ③ think 누출 0 — 실행 페이로드에서 제거 확인
    payload = cmd.payload()
    if "think" in payload:
        violations.append("think leaked into payload")

    verdict = "violation" if violations else "ok"
    if violations:
        state["audit_log"].append({"event": "checker_violation", "node": plan["node_id"],
                                   "reasons": violations})
    plan["payload"] = payload
    return {"checker_verdict": verdict, "current_plan": plan, "audit_log": state["audit_log"]}
