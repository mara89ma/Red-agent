"""bridge — RedTeam↔SOC 유일한 다리: 관측 트래픽 → UAV*_CL → SOC Alert (③).

에이전트와 SOC는 코드 결합하지 않는다(설계 원칙). 이 패키지는 공유 레인지의
telemetry-tap + Sentinel 분석규칙 역할을 인-프로세스로 에뮬레이트한다.
"""
from .telemetry_tap import tap_from_audit  # noqa: F401
from .soc_feeder import rows_to_alert  # noqa: F401
