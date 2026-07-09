"""mission_command — 임무형 지휘 (Auftragstaktik / Mission Command).

최상위 오케스트레이터가 공격 시작 시 **사람에게서 미션 프로필을 1회** 받는다
(지휘관 의도·최종상태·제약·RoE 상한). 이후에는 **오케스트레이터가 자율 지휘**:
의도를 하위 목표로 분해→수단을 스스로 선택→RoE 상한 내 실행→적응. 추가 인간 개입
없음(= 분권 실행, 지휘관 의도 중심). 판정권은 여전히 모델 밖(RoE 게이트).
"""
from .commander import MissionProfile, run_mission_command

__all__ = ["MissionProfile", "run_mission_command"]
