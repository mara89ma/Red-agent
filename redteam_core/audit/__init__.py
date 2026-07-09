"""audit — 검증 강도 감사 (정직성 계층).

에이전트의 모든 능력을 '실제로 검증된 정도'로 분류해 자기기만 위험을 투명화한다:
  - real_exec     : loopback 으로 실 파일/소켓/HTTP 도달 확인(실행검증)
  - grounded_model: 실 임계값·외부표준·실코드 introspection 근거(모델이나 근거 있음)
  - self_model    : 전제를 코드에 박아 assert(실측 아님·자기충족)
"""
from .verification import TIERS, format_audit, verification_audit

__all__ = ["TIERS", "verification_audit", "format_audit"]
