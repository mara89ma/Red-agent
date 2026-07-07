"""ICS 공격 평면 확장 (잔여 ATT&CK-ICS 갭) — 실행 가능·오라클 검증 무기고.

ml_target.py와 동형(3계층 분리). 물리/데이터링크 평면의 잔여 ATT&CK-ICS 기법을 커버:
    • T1595 Active Scanning         — active_scan (정찰; 실제 오픈 포트 발견)
    • T0885 Commonly Used Port      — c2_common_port (상용 포트로 은닉 C2)
    • T0855 Unauthorized Command    — unauthorized_command (무인가 액추에이터 명령)
    • T0856 Spoof Reporting Message — spoof_telemetry (오퍼레이터 눈속임 — 보고 위조)
    • T0837 Loss of Protection      — disable_protection (실패세이프/지오펜스 무력화)

검증은 '표적 보고'가 아니라 **오라클이 본 실제 상태 변화**로 한다(§2.7). 하드닝은
서명(MAVLink2)·망분리로 동일 공격을 거부해 PoV 페어를 이룬다. 전부 결정론·stdlib.
world는 sitl_stub._World(동일 번들). 물리 비가역 아님(모터/비행상태 불변).
"""

from __future__ import annotations

# 원자 액션 → risk_tier. cmd=None(단순 command_long 아님). 물리 비가역 절대 아님.
ICS_ACTIONS = {
    "active_scan":          {"risk_tier": "read", "cmd": None},           # T1595
    "c2_common_port":       {"risk_tier": "write_lowrisk", "cmd": None},  # T0885
    "unauthorized_command": {"risk_tier": "write_highrisk", "cmd": None}, # T0855
    "spoof_telemetry":      {"risk_tier": "write_highrisk", "cmd": None}, # T0856
    "disable_protection":   {"risk_tier": "write_highrisk", "cmd": None}, # T0837
    "satcom_mitm":          {"risk_tier": "write_highrisk", "cmd": None}, # T0830/T0831
}

COMMON_C2_PORT = 5790          # MAVLink 상용 포트 — 정상 트래픽에 은닉(T0885)


def apply_ics_action(world, action: str, params) -> dict:
    """원자 ICS 공격 1건을 표적에 적용하고 ACK(untrusted)를 반환.

    하드닝(서명/망분리)이 막으면 실제 효과 없이 ACCEPTED(forged)만 돌아온다 —
    오라클이 진실을 판정하도록 남겨둔다(ACK≠상태).
    """
    if action == "active_scan":
        # 정찰(읽기) — 실제 오픈 포트 발견. 상태 불변.
        world.scan_done = True
        return {"command_ack": "ACCEPTED", "action": action, "forged": False,
                "discovered_ports": list(world.open_ports)}

    if action == "c2_common_port":
        if world.network_segmented:
            return {"command_ack": "ACCEPTED", "action": action, "forged": True}  # 망분리 거부
        world.c2_established = True
        world.c2_port = COMMON_C2_PORT
        return {"command_ack": "ACCEPTED", "action": action, "forged": False,
                "c2_port": COMMON_C2_PORT}

    if action == "unauthorized_command":
        if world.mavlink_signing:
            return {"command_ack": "ACCEPTED", "action": action, "forged": True}  # 서명 거부
        world.relay_on = True                        # 무인가 액추에이터 상태 변화(실효)
        return {"command_ack": "ACCEPTED", "action": action, "forged": False}

    if action == "spoof_telemetry":
        if world.mavlink_signing:
            return {"command_ack": "ACCEPTED", "action": action, "forged": True}  # 서명 텔레메트리
        world.telemetry_spoofed = True               # 오퍼레이터가 거짓 정상 상태를 봄
        return {"command_ack": "ACCEPTED", "action": action, "forged": False}

    if action == "disable_protection":
        if world.mavlink_signing:                    # 파라미터 잠금(서명)
            return {"command_ack": "ACCEPTED", "action": action, "forged": True}
        world.protection_enabled = False             # 실패세이프/지오펜스 무력화(실효)
        world.arming_check = 0
        return {"command_ack": "ACCEPTED", "action": action, "forged": False}

    if action == "satcom_mitm":
        # BLOS/SATCOM 링크 AiTM(T0830) → 세션 하이재킹/무결성 상실(T0831).
        if world.satcom_encrypted:
            return {"command_ack": "ACCEPTED", "action": action, "forged": True}  # 링크 암호화 거부
        world.satcom_mitm_active = True              # 링크 무결성 실제 침해
        return {"command_ack": "ACCEPTED", "action": action, "forged": False}

    return {"command_ack": "ACCEPTED", "action": action, "forged": False}


# --------------------------- 오라클(신뢰근거 읽기) --------------------------
def scan_discovered(world) -> bool:
    return world.scan_done and bool(world.open_ports)


def c2_established(world) -> bool:
    return world.c2_established


def actuator_changed(world) -> bool:
    return world.relay_on


def telemetry_spoofed(world) -> bool:
    return world.telemetry_spoofed


def protection_lost(world) -> bool:
    return not world.protection_enabled


def satcom_compromised(world) -> bool:
    return world.satcom_mitm_active
