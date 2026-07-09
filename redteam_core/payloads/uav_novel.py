"""UAV 특화 신규 시나리오 — APT 에뮬레이션에서 도출 (S60~S62, 공란 채움).

실 위협행위자·사건이 시사하나 기존에 단독 시나리오가 없던 UAV 공격을 정식 시나리오화.
각 craft 는 실 아티팩트(MAVLink 프레임·covert 프레임·센서폴트 시퀀스)를 생성. 결정론.

- S60 위성 링크 C2 하이재킹 (Turla G0010) — 위성 ISP 링크를 C2 인프라로 편승
- S61 GNSS 스푸핑 나포·강제착륙 (RQ-170, Iran 2011) — 좌표 walk-off 로 유도착륙
- S62 다중센서 협조 폴트·EKF 무력화 — EKF innovation 게이트 아래로 협조 스푸핑(은밀)
"""
from __future__ import annotations

from .exploits import ExploitPayload


def craft_satellite_c2_hijack() -> ExploitPayload:      # S60 (Turla)
    # 위성 세션 편승 C2 프레임(스펙) — 전송은 §K/§U 가 담당(분리 유지).
    frame = b"SATCOM:SATCOM-ISP-HIJACK:C2:BEACON;TASK"
    return ExploitPayload(
        "S60", "sat_c2",
        {"link": "위성 ISP 다운링크(합법 세션 편승)", "c2_frame": frame, "actor": "Turla G0010"},
        "T1090.002", "위성 인터넷 링크를 C2 인프라로 하이재킹(Turla식, C&C 은닉)")


def craft_gnss_capture() -> ExploitPayload:             # S61 (RQ-170)
    base_lat, base_lon = 367100000, 1261300000
    # 좌표를 유도착륙지점으로 서서히 이동(walk-off) — 급변 아니라 EKF 통과. 프레임화는 §K.
    walk = [(base_lat - i * 2500, base_lon - i * 2500) for i in range(6)]
    return ExploitPayload(
        "S61", "gnss_capture",
        {"walk_coords": walk, "steps": len(walk), "goal": "강제착륙/나포", "incident": "RQ-170 Iran 2011"},
        "T0831/T0827", "GNSS 스푸핑으로 좌표를 유도지점으로 walk-off 시켜 나포")


def craft_ekf_fault() -> ExploitPayload:                # S62 (EKF defeat)
    from ..simtest.sensors import run_sensor_fault
    faults = {}
    for sid in ("S56", "S57", "S58"):
        try:
            f = run_sensor_fault(sid, ramp_rate=0.05)
            faults[sid] = bool(getattr(f, "accepted", False))
        except Exception:
            faults[sid] = None
    accepted = [s for s, ok in faults.items() if ok]
    return ExploitPayload(
        "S62", "ekf_fault",
        {"sensors": ["imu", "baro", "mag"], "ekf_accepted": accepted, "ramp": "완만(게이트 통과)"},
        "T0835", "다중센서를 EKF innovation 게이트 아래로 협조 스푸핑해 은밀 무력화")


NOVEL_SCENARIOS = {
    "S60": craft_satellite_c2_hijack,
    "S61": craft_gnss_capture,
    "S62": craft_ekf_fault,
}
