"""Kill switch — 소프트(best-effort) RTL/LAND (§2.8 killswitch.py).

★ 이는 봉쇄가 아니다(advisor M5):
    RTL(20)은 건강한 GPS/EKF·home이 필요 → S1(GNSS 스푸핑)·JAM 하에선 실패할
    수 있고, 명령이 공격당하는 같은 링크로 나가며, 이미 집행된 비행중disarm/
    flight-term은 MAVLink로 복구 불가.

진짜 봉쇄 = 물리 계측 out-of-band: 레인지 안전요원 + 하드웨어 flight-termination
+ sim geofence. live면 필수.
"""

from __future__ import annotations

from ..tools.mavlink import CMD


def soft_rtl(state) -> dict:
    """종료 시 RTL/LAND 복귀 시도(best-effort). 성공 보장 없음."""
    transport = state["range"].transport
    ack = transport.apply("set_mode", [1, 6])   # RTL custom_mode
    return {"killswitch": {"attempted": CMD["RETURN_TO_LAUNCH"], "ack": ack,
                           "note": "best-effort; 물리 봉쇄는 out-of-band 안전요원/HW flight-term"}}
