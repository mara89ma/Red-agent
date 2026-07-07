"""(5a) 정적 지식 RAG — MAVLink/PX4/ATT&CK-ICS/CVE (§2.4·§1.4(5)).

command_long 인자 환각 방지용 스펙 사전. **untrusted 태깅** — 검색만으로
상태변경을 인가하지 못한다(DoD: 검색≠인가).
"""

from __future__ import annotations

# 원자 액션 → MAVLink 스펙(파라미터 의미). Synthesizer가 인자 조립에 참조.
COMMAND_SPEC = {
    "set_mode":   {"cmd": 176, "params": {"p1": "base_mode(=1 custom)", "p2": "custom_mode"},
                   "technique": "T1692.001"},
    "force_arm":  {"cmd": 400, "params": {"p1": "1=arm", "p2": "0=safety-check"},
                   "technique": "T1692.001"},
    "takeoff":    {"cmd": 22, "params": {"p7": "alt_agl_m"}, "technique": "T1692.001"},
    "disarm":     {"cmd": 400, "params": {"p1": "0=disarm"}, "technique": "T0831"},
    "flight_terminate": {"cmd": 185, "params": {"p1": "1=terminate"}, "technique": "T0831"},
    "param_set_safety": {"cmd": -1, "params": {"id": "ARMING_CHECK|FS_*", "value": "0"},
                         "technique": "T0836"},
    "recon_heartbeat":  {"cmd": None, "params": {}, "technique": "T0840"},
    # 온보드-AI 평면(ATLAS AML) — cmd 없는 논리 공격. technique=정밀 AML ID.
    "ml_craft_adversarial": {"cmd": None, "params": {"patch": "adversarial artifact"},
                             "technique": "AML.T0043"},
    "ml_evade_perception":  {"cmd": None, "params": {"target_label": "clear"},
                             "technique": "AML.T0015"},
    "ml_prompt_inject":     {"cmd": None, "params": {"vector": "indirect via mission text"},
                             "technique": "AML.T0051"},
    "ml_extract_secret":    {"cmd": None, "params": {"query": "copilot secret exfil"},
                             "technique": "AML.T0057"},
    "ml_poison_training":   {"cmd": None, "params": {"feed": "model update / retrain data"},
                             "technique": "AML.T0020"},   # 스테이징 전용(런타임 미집행)
    # 잔여 ATT&CK-ICS 평면 — cmd 없는 논리/데이터링크 공격.
    "active_scan":          {"cmd": None, "params": {"range": "target services"},
                             "technique": "T1595"},
    "c2_common_port":       {"cmd": None, "params": {"port": "5790 (MAVLink)"},
                             "technique": "T0885"},
    "unauthorized_command": {"cmd": None, "params": {"target": "actuator/relay"},
                             "technique": "T0855"},
    "spoof_telemetry":      {"cmd": None, "params": {"report": "forged benign state"},
                             "technique": "T0856"},
    "disable_protection":   {"cmd": None, "params": {"protections": "FS_*/geofence"},
                             "technique": "T0837"},
    "satcom_mitm":          {"cmd": None, "params": {"link": "BLOS/SATCOM session"},
                             "technique": "T0830"},
}

TRUST = "untrusted"      # 모든 정적 KB 청크는 untrusted 태깅(§1.4(5))


def spec_for(action: str) -> dict:
    return dict(COMMAND_SPEC.get(action, {"cmd": None, "params": {}, "technique": ""}))
