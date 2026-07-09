"""은닉 C2 — 터널링·암호·난독·인코딩 (S56, §K 확장).

C2 탐지 회피 4기법을 실 바이트 변환으로 구현(왕복 검증 가능 = 실체).
- T1572 Protocol Tunneling : C2 를 SATCOM 세션 프레임 내부로 캡슐화
- T1573 Encrypted Channel  : XOR 스트림 암호(결정론)로 채널 은닉
- T1001 Data Obfuscation   : 더미 필러 바이트에 페이로드 인터리브
- T1132 Data Encoding      : base64 인코딩으로 파서 통과

결정론·무의존. blue 는 콘텐츠 검사 회피라 대부분 탐지 불가(사각) → 은닉 가치.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass
class CovertFrame:
    technique: str
    data: bytes
    method: str


# ── T1132 인코딩 ─────────────────────────────────────────────────────────────
def encode_c2(payload: bytes) -> CovertFrame:
    return CovertFrame("T1132", base64.b64encode(payload), "base64")


def _decode(data: bytes) -> bytes:
    return base64.b64decode(data)


# ── T1573 암호 채널(XOR 스트림) ──────────────────────────────────────────────
def encrypt_c2(payload: bytes, key: int = 0x5A) -> CovertFrame:
    return CovertFrame("T1573", bytes(b ^ key for b in payload), "xor")


def _decrypt(data: bytes, key: int = 0x5A) -> bytes:
    return bytes(b ^ key for b in data)


# ── T1001 난독(더미 필러 인터리브) ──────────────────────────────────────────
def obfuscate_c2(payload: bytes) -> CovertFrame:
    out = bytearray()
    for b in payload:
        out += bytes((b, 0x00))            # 실 바이트 + 더미 0x00
    return CovertFrame("T1001", bytes(out), "filler-interleave")


def _deobfuscate(data: bytes) -> bytes:
    return bytes(data[::2])


# ── T1572 프로토콜 터널링(SATCOM 세션 캡슐화) ───────────────────────────────
def tunnel_c2(payload: bytes, session_id: str = "SAT-001") -> CovertFrame:
    header = b"SATCOM:" + session_id.encode() + b":"
    return CovertFrame("T1572", header + payload, "satcom-encapsulation")


def _untunnel(data: bytes) -> bytes:
    return data.split(b":", 2)[2]


def roundtrip_ok(payload: bytes = b"ARM;GOTO 37.1,127.2") -> bool:
    """4기법 전부 실 변환→복원이 원본과 일치(=실체, 가짜 아님)."""
    return (
        _decode(encode_c2(payload).data) == payload
        and _decrypt(encrypt_c2(payload).data) == payload
        and _deobfuscate(obfuscate_c2(payload).data) == payload
        and _untunnel(tunnel_c2(payload).data) == payload
    )
