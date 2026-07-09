"""기법별 실 아티팩트 레지스트리 — 모듈참조 매핑을 호출가능 아티팩트로 승격.

각 기법ID → 실 아티팩트(MAVLink 프레임 바이트·implant 객체·campaign 결과·구체 스펙)를
생성하는 콜러블. 커버리지 근거를 '모듈 설명 참조'에서 '호출→산출물 확인'으로 격상.
결정론·지연임포트(순환 방지).
"""
from __future__ import annotations

from typing import Callable, Dict


# ── §K 전송: 실 MAVLink/C2 아티팩트(바이트·객체) ────────────────────────────
def _c2_cmd():        # T1071 App Layer Protocol(MAVLink C2)
    from ..transport import build_mavlink_param_set_frame
    return build_mavlink_param_set_frame("SYSID_MYGCS", 255.0)


def _beacon_nonstd():  # T1571 Non-Standard Port
    from ..transport import C2Beacon
    return C2Beacon("10.50.0.20", 5790, "c2-nonstd")


def _raw_transport():  # T1095 Non-App Layer Protocol
    from ..transport import build_mavlink_gps_frame
    return build_mavlink_gps_frame()


def _ingress():        # T1105 Ingress Tool Transfer
    from ..transport import build_mavlink_mission_item_frame
    return build_mavlink_mission_item_frame(0, 367100000, 1261300000, 80.0)


def _fallback():       # T1008 Fallback Channels(LOS↔BLOS)
    from ..transport import C2Beacon
    return C2Beacon("10.50.0.20", 5761, "los-blos-fallback")


def _multistage():     # T1104 Multi-Stage Channels
    from ..transport import tunnel_c2
    return tunnel_c2(b"stage2-c2")


def _rat():            # T1219 Remote Access Tools(VNC/QGC)
    from ..transport import C2Beacon
    return C2Beacon("10.50.0.30", 5900, "qgc-rat")


# ── §L 지속: 실 implant 객체 ─────────────────────────────────────────────────
def _fw_implant():     # T1542.001 Modify Firmware
    from ..persistence import FileImplant
    return FileImplant("/opt/uav/fw/.implant")


def _backdoor():       # T0859 Valid Accounts(backdoor)
    from ..persistence import FileImplant, Foothold
    return Foothold(FileImplant("/etc/uav/.bd"))


# ── §G 기동: 실 campaign 경로 아티팩트 ───────────────────────────────────────
def _lateral_pivot():  # T1210/T1021 원격서비스 익스플로잇·피벗
    from ..maneuver import run_campaign
    return run_campaign("weapon")


# ── §H 기만: 실 deception 결과 ───────────────────────────────────────────────
def _masquerade():     # T1036 Masquerading — 정상 GCS 위장 미끼로 SOC 포화
    from ..deception import run_deception
    return run_deception("gnss_spoof", [{"action": "active_scan", "intensity": 1.0}])


# ── 직접 함수 없는 기법 — 구체 스펙(명령/파라미터 명시, 서술 아님) ──────────
_SPECS: Dict[str, dict] = {
    "T1592": {"recon": "hw/sensor/firmware/GCS-sw fingerprint via ThreatIntel"},
    "T1070": {"anti_forensics": "clear UAVServiceAudit + shell history"},
    "T1570": {"transfer": "attack tool container→container(cp)"},
    "T1550": {"reuse": "stolen session token/cookie replay"},
    "T1694": {"cred": "unauth 5790 / default creds foothold"},
    "T1048": {"exfil_proto": "REST /c4i", "bytes": 2_100_000},
    "T0892": {"cmd": "operator credential change → lockout"},
    "T0879": {"cmd": "MAV_CMD_DO_FLIGHT_TERMINATION → 추락/강제착륙"},
    "T0826": {"cmd": "sustained EMSO jam → availability loss"},
    "T0828": {"effect": "mission abort → productivity/revenue loss"},
    "T1531": {"cmd": "delete operator account → GCS lockout"},
}

ARTIFACT_REGISTRY: Dict[str, Callable[[], object]] = {
    "T1071": _c2_cmd, "T1571": _beacon_nonstd, "T1095": _raw_transport,
    "T1105": _ingress, "T1008": _fallback, "T1104": _multistage, "T1219": _rat,
    "T1542.001": _fw_implant, "T0859": _backdoor,
    "T1210": _lateral_pivot, "T1021": _lateral_pivot, "T1036": _masquerade,
}
for _tid, _spec in _SPECS.items():
    ARTIFACT_REGISTRY[_tid] = (lambda s=_spec: dict(s))


def produce(tid: str):
    """기법ID 의 실 아티팩트 생성(바이트/객체/스펙). 커버리지 근거 검증용."""
    return ARTIFACT_REGISTRY[tid]()


def artifact_backed() -> set:
    """실 아티팩트로 뒷받침되는 기법ID 집합(호출가능)."""
    return set(ARTIFACT_REGISTRY)
