"""information — 정보(7번째 합동기능) 공격: 리포팅/증거체인 표적.

정보가 독립 합동기능(JP 3-0)이면, 탐지 파이프라인이 아니라 **리포팅/증거체인 자체**가
독자적 고가치 표적이다. 탐지가 맞았든 틀렸든 상관없이 SOCReport·OscalEvidence·
RuleUpdate PR 본문을 조작해 '거짓 정보산출물'을 만든다.
= '기록/진실 그 자체'를 노리는 새 공격 축(S1~S99 어디에도 없던 카테고리, S100~S102).
"""
from .reporting import REPORT_TARGETS, attack_reporting_chain
from .executor import execute_real

__all__ = ["REPORT_TARGETS", "attack_reporting_chain", "execute_real"]
