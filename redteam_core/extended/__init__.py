"""extended — 빈 번호 채움 시나리오 (S22·S28·S63~S65·S74~S85).

재배정으로 비어있던 17개 번호를 도메인 적합 실제 공격 시나리오로 채운다.
테마: 공중 원본 보강 · 수동 정찰/수집 · 기체/페이로드 · 공급망(DevSecOps) · 미들웨어.
전부 blue 전용 탐지룰 미배포 = 사각지대(모델 판정 수준).
"""
from .scenarios import EXTENDED_SCENARIOS, run_extended, themes

__all__ = ["EXTENDED_SCENARIOS", "run_extended", "themes"]
