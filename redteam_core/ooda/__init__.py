"""ooda — OODA Loop / Decision Advantage 재해석 (Boyd).

Boyd: Orient 가 인지부하의 핵심. 그래서:
  - Orient-phase denial: 최종판정을 속이려 하지 말고 Orient 자체를 마비 —
    모순 근거를 동시에 흘려 Investigation 불확실성을 극대화. (S5/S29 RAG 포이즈닝을
    'Orient 단계 거부'로 재서술 — 새 코드 없이 창의성)
  - OODA 속도경쟁: '적의 OODA 루프 안으로 들어간다' — red 가 SOC 의 Report/RuleUpdate
    가 닫히기 전에 Actions-on-Objective 를 완료하는 속도경쟁. red↔blue 공통 스코어보드.
"""
from .orient import ooda_race, orient_phase_denial

__all__ = ["orient_phase_denial", "ooda_race"]
