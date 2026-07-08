"""tempo — 공격 템포/시간 모델링 (고도화 §P).

low-and-slow(저속·저강도, 임계 아래 누적) vs smash-and-grab(고속·고강도, 즉효·탐지)
의 시간-탐지 트레이드오프를 모델링한다. KPI 시간지표(time-to-effect·MTTD) 갭 보완.
교리: OODA 템포·persistent engagement. 결정론.
"""
from .pacing import TEMPO_PROFILES, pace, tempo_tradeoff

__all__ = ["TEMPO_PROFILES", "pace", "tempo_tradeoff"]
