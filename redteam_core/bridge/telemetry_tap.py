"""telemetry-tap — 관측된 MAVLink 트래픽 → UAV*_CL 로그 행 (③ 브릿지 1/2).

실 레인지에서 tap(10.50.0.40)은 mavlink-router의 tap_out(14552)을 구독해 pymavlink로
NDJSON을 만들고 Sentinel `UAV*_CL`에 적재한다. 여기서는 **감사 로그(=관측된 송신
기록)로부터 동일한 행을 재구성**한다 — tap은 공격자 코드가 아니라 *관측자*이므로
executor 내부가 아니라 audit_log(관측 가능 표면)에서 읽는다(설계상 디커플링 유지).

컬럼 바인딩·정상 sysid 집합은 `observables`(YAML, MD 근거)에서 온다.
차단/거부된 액션은 실제로 송신되지 않았으므로 행을 만들지 않는다(탐지 표면 없음).
"""

from __future__ import annotations

from ..mapping import attack_d3fend
from ..tools.mavlink import ATOMIC_ACTIONS


def tap_from_audit(audit_log: list, profile: dict, ts: str = "") -> list:
    """audit_log의 executor(성공)·recon 이벤트를 UAV*_CL 행으로 변환."""
    obs = profile.get("observables", {})
    tables = obs.get("detection_tables", {})
    ports = obs.get("ports", {})
    legit = set(obs.get("legit_source_sysids", [1, 254, 255]))
    ops = profile.get("ops", {})
    attacker_sysid = ops.get("attacker_source_sysid", 250)
    attacker_ip = ops.get("attacker_ip", "10.50.0.99")

    rows = []
    for e in audit_log:
        ev = e.get("event")
        if ev == "recon":
            fact = e.get("fact", {})
            rows.append(_row("UAVDatalinkConn_CL", "recon_heartbeat", ts, {
                "LocalPort": ports.get("los_mavlink", fact.get("port", 5790)),
                "PeerIp": attacker_ip,
                "State": "ESTABLISHED",
            }))
        elif ev == "executor" and e.get("ack", {}).get("command_ack") == "ACCEPTED":
            action = e.get("ack", {}).get("action") or ""
            # 읽기 계열은 인젝션이 아니며 연결은 recon 이벤트가 이미 기록 → 중복 방지
            if action in ("recon_heartbeat", "param_read", "telemetry_read"):
                continue
            binding = tables.get(action)
            if not binding:
                continue
            cmd_id = ATOMIC_ACTIONS.get(action, {}).get("cmd")
            params = e.get("params", [])
            cols = _columns(action, cmd_id, params, attacker_sysid, legit)
            rows.append(_row(binding["table"], action, ts, cols))
    return rows


def _columns(action, cmd_id, params, attacker_sysid, legit) -> dict:
    injected = attacker_sysid not in legit          # SourceSystemId∉{1,254,255} = 인젝션(A4)
    if action in ("set_mode", "force_arm"):
        cols = {"SourceSystemId": attacker_sysid, "Command": cmd_id,
                "SourceSystemIdAnomaly": injected}
        if action == "force_arm":
            cols["Param1"] = params[0] if params else 1
        return cols
    if action == "param_set_safety":
        return {"ParamId": "ARMING_CHECK", "ParamValueAfter": 0}
    if action == "gnss_spoof":
        return {"PosHorizVariance": 0.8, "FixType": 1}
    return {"SourceSystemId": attacker_sysid, "Command": cmd_id}


def _row(table, action, ts, cols) -> dict:
    m = attack_d3fend.lookup(action)
    row = {"_table": table, "_attack_action": action,
           "_technique": ",".join(m["attack_ics"]), "TimeGenerated": ts}
    row.update(cols)
    return row
