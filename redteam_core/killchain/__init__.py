"""killchain — 7단계 킬체인 오케스트레이션 (고도화 §J).

부분/미수행 단계(전달·설치지속·C2)를 채워 사이버 킬체인을 end-to-end 로 완결한다.
정찰→무기화→전달→악용→설치/지속→C2→목표행동을 순서대로 수행하고, 각 단계의
수행/탐지/차단을 판정해 '완전 관통' 및 '은밀 관통' 여부를 낸다.

교리: Lockheed Cyber Kill Chain 7단계 + ATT&CK. 새 능력의 탐지는 blue 실제 룰
(S4/S21 펌웨어·정비 임플란트, S26 불량 라우터 C2)에 매핑 — D8 준수(공유 산출물).
"""
from .capabilities import C2_TECHNIQUES, PERSISTENCE_TECHNIQUES
from .chain import KillChainResult, StageResult, run_killchain

__all__ = ["C2_TECHNIQUES", "PERSISTENCE_TECHNIQUES",
           "KillChainResult", "StageResult", "run_killchain"]
