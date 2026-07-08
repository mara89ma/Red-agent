"""maneuver — 기동/측면이동 (고도화 §G, 합동기능 Movement & Maneuver).

동언님 에이전트는 단발 효과 중심이라 '기동' 기능이 약했다. 이 층은 사이버 지형
(terrain)을 그래프로 모델링하고, 초기접근→측면이동→효과로 **기동**하며 경로가
막히면 재경로(reroute)한다. 대화 초기의 C1/C2 캠페인 킬체인을 지형 순회로 실현.

교리:
  - JP 3-12: 사이버공간 기동(논리·물리·페르소나 계층에서 위치적 우세 확보).
  - ATT&CK: Lateral Movement(TA0008)·Persistence(TA0003)·C2(TA0011).
  - 각 hop 은 §B RoE 게이트 + §E 적응교전 + §D 전투평가로 처리.
"""
from .terrain import ATTACKER, ASSETS, Edge, simple_paths
from .campaign import CampaignResult, HopResult, run_campaign

__all__ = ["ATTACKER", "ASSETS", "Edge", "simple_paths",
           "CampaignResult", "HopResult", "run_campaign"]
