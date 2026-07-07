"""(1) Recon/Perceptor — 결정론 파서 우선 (§1.4(1)).

HEARTBEAT 파싱(autopilot/type/firmware/sysid/mode/armed/서명여부), 5790 LISTEN
확인. 파싱 불가만 LLM(데모엔 없음). 재스캔 시 사실 집합 결정론 재현(DoD).
표적발 데이터는 untrusted 태깅 후 **결정론 파싱**으로만 신뢰(tool-memory
conflict 2601.09760: 결정론 파싱 > LLM 추측).
"""

from __future__ import annotations

import time

from ..safety import channels


def recon(state) -> dict:
    profile = state["profile"]
    rng = state["range"]
    tp = profile.get("target_profile", {})
    svcs = tp.get("services") or [{}]
    svc = next((s for s in svcs if s.get("proto") == "mavlink"), svcs[0])  # datalink-los:5790
    hosts = tp.get("hosts") or [{}]

    raw = rng.telemetry.heartbeat()                     # untrusted 원시 HEARTBEAT
    tagged = channels.tag(channels.TOOL_OUTPUT, raw)    # 데이터일 뿐 지시 아님

    fact = {
        "host": hosts[0].get("id", "unknown-host"),
        "ip": svc.get("ip", "10.50.0.20"),
        "port": svc.get("port", 5790),
        "proto": svc.get("proto", "mavlink"),
        "auth": svc.get("auth", "none"),
        "sysid": raw["sysid"],
        "autopilot": raw["autopilot"],
        "mavlink_signing": raw["mavlink_signing"],
        "arming_check": raw["arming_check"],
        "provenance": "recon_heartbeat",
        "confidence": 1.0,
        "ts": time.time(),
    }

    # 타입화 메모리(semantic) — 버전화 저장
    mem = state["memory"]
    mem.set_fact("target_sysid", raw["sysid"])
    mem.set_fact("mavlink_signing", raw["mavlink_signing"])

    # 스코어카드 — 무인증 5790 도달 + 무서명(A4 진입 자명)
    sc = state["scorecard"]
    sc.reached_5790 = (svc.get("port") == 5790 and svc.get("auth") == "none")
    sc.unauth_confirmed = sc.reached_5790 and (raw["mavlink_signing"] is False)  # gitleaks:allow (불리언 로직, 시크릿 아님)

    state["audit_log"].append({"event": "recon", "fact": fact, "tagged_trusted": tagged["trusted"]})
    return {"facts": state["facts"] + [fact], "audit_log": state["audit_log"]}
