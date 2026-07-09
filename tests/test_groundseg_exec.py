"""지상 세그먼트 실 실행 검증 — loopback 으로 실제 파일/UDP/HTTP 확인.

execute_real 이 '설명 문자열'이 아니라 실제 공격을 수행함을 증명한다.
"""
from __future__ import annotations

import http.server
import os
import socket
import threading

import pytest

from redteam_core.groundseg import execute_real, run_ground


def test_mission_file_actually_written(tmp_path, monkeypatch):
    monkeypatch.setenv("GROUND_TARGET_DIR", str(tmp_path))
    r = execute_real("S86")                       # GCS 악성 미션파일
    assert r["sent"] is True
    assert os.path.exists(r["path"])              # 실제 디스크에 파일 생성
    data = open(r["path"], "rb").read()
    assert b"passwd" in data and len(data) == r["bytes"]


def test_ntp_packet_actually_sent(monkeypatch):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); s.settimeout(2)
    port = s.getsockname()[1]
    monkeypatch.setenv("NTP_TARGET", f"127.0.0.1:{port}")
    r = execute_real("S95")                       # GDT NTP 스푸핑
    assert r["sent"] is True
    data, _ = s.recvfrom(64); s.close()
    assert len(data) == 48                        # 실제 48바이트 NTP 패킷 수신


def test_mavros_mavlink_actually_sent(monkeypatch):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); s.settimeout(2)
    port = s.getsockname()[1]
    monkeypatch.setenv("MAVLINK_ENDPOINT", f"127.0.0.1:{port}")
    r = execute_real("S92")                       # MAVROS 명령주입
    assert r["sent"] is True
    data, _ = s.recvfrom(256); s.close()
    assert len(data) > 0                          # 실제 MAVLink 프레임 수신


def test_fleet_api_http_actually_requested(monkeypatch):
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got["path"] = self.path
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.handle_request, daemon=True); t.start()
    monkeypatch.setenv("FLEET_API_URL", f"http://127.0.0.1:{port}/api/fleet/42")
    r = execute_real("S96")                       # 함대 API IDOR
    assert r["sent"] is True and r["status"] == 200
    t.join(timeout=3)
    assert got.get("path") == "/api/fleet/42"     # 실제 서버가 요청 수신


def test_no_target_fails_closed(monkeypatch):
    for k in ("GROUND_TARGET_DIR", "NTP_TARGET", "MAVLINK_ENDPOINT", "FLEET_API_URL"):
        monkeypatch.delenv(k, raising=False)
    assert execute_real("S86")["sent"] is False   # 표적 미설정 → 미전송(fail-closed)


def test_dry_run_never_transmits(monkeypatch):
    monkeypatch.setenv("GROUND_TARGET_DIR", "/tmp/rt_should_not_write")
    assert run_ground("S86", dry=True).transmitted is False   # dry=기본, 실행 안 함
    assert not os.path.exists("/tmp/rt_should_not_write/S86_evil.plan")
