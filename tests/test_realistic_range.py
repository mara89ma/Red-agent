"""실 상황 유사 통합 레인지 — loopback 표적에 실제 공격을 쏴 수신을 바이트로 검증.

dry-run 모델이 아니라 execute_real 로 실 파일/소켓/HTTP/ROS/RTSP 를 표적에 전달하고,
표적 쪽에서 실제로 받았는지 확인한다(가장 실제에 가까운 검증).
"""
from __future__ import annotations

import http.server
import os
import socket
import socketserver
import threading
from xmlrpc.server import SimpleXMLRPCServer

import pytest

from redteam_core.groundseg import execute_real as ground_exec
from redteam_core.information import execute_real as info_exec


@pytest.fixture(scope="module")
def range_targets(tmp_path_factory):
    """loopback 공격 레인지: 파일디렉토리·UDP·HTTP·ROS·RTSP 표적 기동 + env 설정."""
    ev = {"http": [], "udp": {}}
    tdir = tmp_path_factory.mktemp("range")
    os.environ["GROUND_TARGET_DIR"] = str(tdir)
    os.environ["INFO_TARGET_DIR"] = str(tdir)

    class H(http.server.BaseHTTPRequestHandler):
        def _rec(self, m):
            ev["http"].append(f"{m} {self.path}")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def do_GET(self): self._rec("GET")
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self._rec("POST")
        def log_message(self, *a): pass

    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    hp = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    os.environ["FLEET_API_URL"] = f"http://127.0.0.1:{hp}/api/fleet/42"
    os.environ["TELEMETRY_URL"] = f"http://127.0.0.1:{hp}/ingest"
    os.environ["C4I_URL"] = f"http://127.0.0.1:{hp}/c4i"

    socks = {}
    for env in ("MAVLINK_ENDPOINT", "NTP_TARGET", "RELAY_FORWARD"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0)); s.settimeout(3)
        os.environ[env] = f"127.0.0.1:{s.getsockname()[1]}"
        socks[env] = s

    rpc = SimpleXMLRPCServer(("127.0.0.1", 0), logRequests=False, allow_none=True)
    rpc.register_function(lambda c: [1, "", [[], [], []]], "getSystemState")
    rpc.register_function(lambda *a: [1, "", ["x"]], "registerPublisher")
    threading.Thread(target=rpc.serve_forever, daemon=True).start()
    os.environ["ROS_MASTER_URI"] = f"http://127.0.0.1:{rpc.server_address[1]}"

    ready = threading.Event()

    def _rtsp():
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(1); srv.settimeout(4)
        os.environ["RTSP_TARGET"] = f"127.0.0.1:{srv.getsockname()[1]}"
        ready.set()
        try:
            c, _ = srv.accept(); c.recv(128); c.sendall(b"RTSP/1.0 200 OK\r\n\r\n"); c.close()
        except Exception:
            pass
    threading.Thread(target=_rtsp, daemon=True).start(); ready.wait(2)

    yield {"dir": tdir, "ev": ev, "socks": socks}
    httpd.shutdown()


def test_ground_gcs_file_lands_on_disk(range_targets):
    """S86 GCS 악성 미션파일이 실제 표적 디렉토리에 생성되는가."""
    r = ground_exec("S86")
    assert r["sent"] and os.path.exists(r["path"])
    assert b"passwd" in open(r["path"], "rb").read()


def test_ground_mavros_mavlink_received(range_targets):
    """S92 MAVROS 명령이 실제 MAVLink UDP 로 표적에 도달하는가."""
    r = ground_exec("S92")
    assert r["sent"]
    data, _ = range_targets["socks"]["MAVLINK_ENDPOINT"].recvfrom(256)
    assert len(data) > 0


def test_ground_ntp_packet_received(range_targets):
    """S95 GDT NTP 스푸핑 48바이트 패킷이 표적에 도달하는가."""
    r = ground_exec("S95")
    assert r["sent"]
    data, _ = range_targets["socks"]["NTP_TARGET"].recvfrom(64)
    assert len(data) == 48


def test_ground_fleet_api_http_hit(range_targets):
    """S96 함대관리 API 인증우회 HTTP 요청이 표적 서버에 도달하는가."""
    r = ground_exec("S96")
    assert r["sent"] and r.get("status") == 200
    assert any("/api/fleet/42" in h for h in range_targets["ev"]["http"])


def test_ground_ros_master_xmlrpc(range_targets):
    """S90 무인증 ROS 마스터 XML-RPC 실 호출이 응답을 받는가."""
    r = ground_exec("S90")
    assert r["sent"] and "system_state" in r


def test_information_forged_report_written(range_targets):
    """S100 위조 SOCReport 가 실제 파일로 표적에 생성되는가."""
    r = info_exec("S100")
    assert r["sent"] and os.path.exists(r["path"])
    assert b"true_state" in open(r["path"], "rb").read()


def test_range_summary_real_delivery(range_targets):
    """레인지 종합: 파일·UDP·HTTP·ROS 표적 모두 실제 도달했는가."""
    # 위 테스트들이 표적에 전달 → 증거 존재 확인
    files = list(range_targets["dir"].iterdir())
    assert len(files) >= 2                         # 실 파일 생성됨
    assert range_targets["ev"]["http"]             # 실 HTTP 도달됨
