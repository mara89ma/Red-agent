"""soc_feeder — UAV*_CL 행 → SOC Alert (③ 브릿지 2/2).

실 배포에서는 Sentinel 분석 규칙(KQL)이 `UAV*_CL`을 인시던트→Alert로 변환한다
(SOC의 front door = `POST /alert`). 여기서는 그 변환을 에뮬레이트해 SOC가
삼킬 수 있는 Alert(JSON)를 만든다. Alert 스키마는 `agents/soc_agent.md §4` 기준.

SOC는 구축돼 있다고 가정 → 이 Alert가 RedTeam↔SOC의 **유일한 계약 산출물**이다.
"""

from __future__ import annotations


def rows_to_alert(rows: list, profile: dict, alert_id: str = "rt-0001") -> dict:
    obs = profile.get("observables", {})
    legit = obs.get("legit_source_sysids", [1, 254, 255])
    scenario = profile.get("engagement", {}).get("abstract_action", "A4").split("_")[0]

    techniques, signals, tables = [], [], set()
    for r in rows:
        tables.add(r["_table"])
        for t in r["_technique"].split(","):
            if t and t not in techniques:
                techniques.append(t)
        signals.append(_signal(r))

    injected = any(r.get("SourceSystemIdAnomaly") for r in rows)

    return {
        "id": alert_id,
        "scenario_id": "A4",
        "title": "A4 MAVLink 평문 인젝션 — 비인가 명령 주입(force-arm/mode)",
        "severity_baseline": "high" if injected else "medium",
        "mitre": techniques,
        "signals": signals,
        "iocs": [f"src_sysid={profile.get('ops', {}).get('attacker_source_sysid', 250)}",
                 f"peer_ip={profile.get('ops', {}).get('attacker_ip', '10.50.0.99')}"],
        "cves": [],
        "expected_detection": {
            # SOC Triage/Investigation이 대조할 탐지 규칙(무서명·비정상 sysid)
            "sentinel_rule": f"UAVOperator_CL | where SourceSystemId !in ({','.join(map(str, legit))})",
            "remediation": {"watchlist": "AllowedSourceSystemIds", "search_key": "SourceSystemId",
                            "type": "B"},
        },
        "defense_playbook": {
            "id": "PB-A4-INJECT",
            "actions": ["mavlink-router 5790 필터", "MAVLink2 서명 강제(D3-MAN)",
                        "비정상 sysid 세션 차단"],
            "failover": "LOS 차단 시 BLOS 세션 무결성 검증",
        },
        "_source_tables": sorted(tables),
    }


def _signal(r: dict) -> str:
    if r["_table"] == "UAVOperator_CL":
        anom = "∉legit" if r.get("SourceSystemIdAnomaly") else ""
        return f"UAVOperator_CL SourceSystemId={r.get('SourceSystemId')}{anom} Command={r.get('Command')}"
    if r["_table"] == "UAVDatalinkConn_CL":
        return f"UAVDatalinkConn_CL LocalPort={r.get('LocalPort')} PeerIp={r.get('PeerIp')}"
    if r["_table"] == "UAVConfigAudit_CL":
        return f"UAVConfigAudit_CL ParamId={r.get('ParamId')} ParamValueAfter={r.get('ParamValueAfter')}"
    if r["_table"] == "UAVTelemetry_CL":
        return f"UAVTelemetry_CL PosHorizVariance={r.get('PosHorizVariance')} FixType={r.get('FixType')}"
    return r["_table"]
