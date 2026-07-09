"""mosaic — Mosaic Warfare / Kill Web 구조적 회복탄력성 공격.

개별 타일이 아니라 **재조합 로직 자체**를 노린다:
  - 재조합 로직 공격: conditional edge 라우팅 / judge 앙상블 가중 집계를 표적.
  - judge 진짜 독립성 검증: '이질적'이라던 judge 들이 실은 같은 상위 RAG 소스를
    공유하면 다양성이 허상(common-mode failure) — 소스 하나 오염으로 전 judge 동시
    붕괴. 이걸 실제로 검증한다.
"""
from .recombination import (
    attack_recombination_logic, introspect_judges, verify_judge_independence,
)

__all__ = ["introspect_judges", "verify_judge_independence", "attack_recombination_logic"]
