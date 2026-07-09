"""jadc2 — JADC2 융합 레이어 공격 (결정론 도메인).

JADC2의 진짜 가치는 '융합'이므로, 개별 센서가 아니라 **융합 레이어(상관)**를 노린다:
  - 다중센서 정합성 공격: 각 축은 그럴듯(임계 아래)한데 조합하면 거짓 신호를 동시에
    흘려, 상관기(AlertCorrelator)가 가짜 상관인시던트를 만들거나(FP) 진짜 사건을
    노이즈로 착각(FN)하게 유도.
  - 메시 저하 테스트: EW로 에이전트간 연결 일부가 끊긴 상태에서 SOC가 우아하게
    성능저하되는지(graceful degradation) vs 파국적 실패인지 검증.
"""
from .fusion import (
    SENSOR_AXES, mesh_degradation_test, multi_sensor_consistency_attack,
)

__all__ = ["SENSOR_AXES", "multi_sensor_consistency_attack", "mesh_degradation_test"]
