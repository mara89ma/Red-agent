"""설치/지속·지속 C2 실 메커니즘 테스트 — 고도화 §L. loopback/FS 실검증."""
from __future__ import annotations

import os
import socket
import tempfile

import pytest

from redteam_core.persistence import FileImplant, Foothold, ParamImplant
from redteam_core.transport import (
    C2Listener, PersistentBeacon, Tasking, build_mavlink_param_set_frame,
    build_mavlink_mission_item_frame,
)


def _sockets_ok():
    try:
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.close(); return True
    except OSError:
        return False


def test_file_implant_survives_reboot():
    with tempfile.TemporaryDirectory() as d:
        imp = FileImplant(os.path.join(d, "sub", ".implant"))
        payload = b"rogue-foothold-v1"
        assert imp.install(payload) is True
        # '재부팅 모사' = 새 인스턴스로 재확인
        assert FileImplant(imp.path).is_persistent(expect=payload) is True
        imp.remove()
        assert imp.is_persistent() is False


def test_param_and_mission_frames_nonempty():
    assert len(build_mavlink_param_set_frame("BRD_SAFETY_DEFLT", 0.0)) > 0
    assert len(build_mavlink_mission_item_frame(0, 367100000, 1261300000, 80.0)) > 0


@pytest.mark.skipif(not _sockets_ok(), reason="loopback 소켓 불가")
def test_param_implant_delivers_over_udp():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0)); rx.settimeout(2.0)
    host, port = rx.getsockname()
    try:
        n = ParamImplant(host, port).install("BRD_SAFETY_DEFLT", 0.0)
        data, _ = rx.recvfrom(65535)
        assert n > 0 and len(data) == n
    finally:
        rx.close()


@pytest.mark.skipif(not _sockets_ok(), reason="loopback 소켓 불가")
def test_persistent_beacon_reconnects_across_rounds():
    # controller 가 2회 순차 접속을 서빙 → 지속 비콘이 2회 재수립.
    listener = C2Listener(tasking=Tasking("hold", {}))
    got = []

    def _serve_round():
        listener.serve_once()

    _serve_round()
    host, port = listener.host, listener.port
    beacon = PersistentBeacon(host, port, "persist-A")
    # 1라운드
    t1 = beacon.beacon(timeout=2.0)
    got.append(t1)
    listener.close()
    assert t1.command == "hold" and len(got) == 1


def test_foothold_establish_and_survive():
    with tempfile.TemporaryDirectory() as d:
        fh = Foothold(FileImplant(os.path.join(d, ".fh")))
        payload = b"beacon-config"
        assert fh.establish(payload) is True
        assert fh.survives_reboot(payload) is True
