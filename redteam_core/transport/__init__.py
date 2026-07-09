"""transport — 실 전송 계층 (고도화 §K, 킬체인 3·6단계 본선 보강).

지금까지 전달(Delivery)·C2 는 결정론 '모델'뿐이었다(동언님 mavlink_adapter 는
NotImplementedError 스캐폴드). 이 층은 **실제로 소켓/HTTP 로 나가는 전송 코드**를
제공한다 — loopback 으로 실검증되고, uav-sim-env 실 엔드포인트는 env 로 연결(본선).

  - C2(6단계): TCP 비콘 채널(controller ↔ beacon) + 지속 비콘(자동 재접속), T0885.
  - 전달(3단계): UDP(mavlink-router: GPS/PARAM/MISSION 프레임) · HTTP(FastAPI 스텁).

법적/안전: 기본 표적은 loopback. 실 표적은 env(C2_HOST/MAVLINK_ENDPOINT/STUB_URL)로
명시 지정해야 하며, 시험창·허가 환경에서만 사용.
"""
from .c2_channel import C2Beacon, C2Listener, PersistentBeacon, Tasking
from .covert_c2 import (
    CovertFrame, encode_c2, encrypt_c2, obfuscate_c2, tunnel_c2, roundtrip_ok,
)
from .delivery import (
    build_mavlink_gps_frame, build_mavlink_mission_item_frame,
    build_mavlink_param_set_frame, http_deliver, udp_deliver,
)

__all__ = [
    "C2Beacon", "C2Listener", "PersistentBeacon", "Tasking",
    "build_mavlink_gps_frame", "build_mavlink_mission_item_frame",
    "build_mavlink_param_set_frame", "http_deliver", "udp_deliver",
]
