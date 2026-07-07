"""레인지 팩토리 — range_mode에 따라 스텁 ↔ 실 pymavlink 자동 스왑.

    container | demo   → Range (인메모리 SITL 스텁, 의존성 0)
    sitl | hil | live  → MavlinkRange (실 pymavlink 3-seam)

노드 코드는 어느 쪽이든 동일 인터페이스(.ground_truth/.telemetry/.transport)만 쓰므로
스왑에 무지하다. `independent_oracle(state)`도 `state["range"].ground_truth`만 읽어 공통.
"""

from __future__ import annotations

from .sitl_stub import Range

_REAL_MODES = {"sitl", "hil", "live"}


def make_range(profile: dict, hardened: bool = False):
    """profile.engagement.range_mode를 보고 적절한 레인지 인스턴스를 만든다."""
    mode = str(profile.get("engagement", {}).get("range_mode", "container")).lower()
    if mode in _REAL_MODES:
        # 지연 import: pymavlink 없으면 여기서(연결 시점) 명확히 실패.
        from .mavlink_adapter import MavlinkRange
        return MavlinkRange.from_profile(profile, hardened=hardened)
    return Range.from_profile(profile, hardened=hardened)
