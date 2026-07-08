"""assessment — 폐루프 전투평가(BDA) 계층 (고도화 §A).

동언님 코어(scaffold/oracle/gate)는 "명령이 먹혔나"(자기 오라클)까지만 평가한다.
이 패키지는 JP 3-60 ⑥단계(전투평가)를 **방어자 반응**까지 확장한다: red 가 방출한
UAV*_CL 행을 blue 의 실제 S1~S28 룰 로직으로 평가해 "탐지됐나"를 관측하고,
탐지 임계를 이분 탐색해 blue 가상값 임계를 실측 보정한다.

교리 근거:
  - JP 3-12: OCO/DCO 임무·권한 분리(D8 유지) — pollack-ai 코드 미임포트.
  - JP 3-60: 전투평가 = 표적효과 + **적 반응** 평가 → 여기서 완성.
  - 관측은 '공유 산출물'(blue 룰 KQL: dah-sentinel-content)로만 = D8 준수.
"""
from .rules import DETECTION_RULES, RuleSpec, action_to_rule
from .bda import DetectionOutcome, assess_action
from .loop import CalibrationRecord, probe_boundary, run_closed_loop
from .combat import (
    CombatAssessment, ReattackRecommendation, assess_combat, run_engagement,
)
from .replan import CampaignResult, OBJECTIVES, adaptive_engage

__all__ = [
    "DETECTION_RULES", "RuleSpec", "action_to_rule",
    "DetectionOutcome", "assess_action",
    "CalibrationRecord", "probe_boundary", "run_closed_loop",
    "CombatAssessment", "ReattackRecommendation", "assess_combat", "run_engagement",
    "CampaignResult", "OBJECTIVES", "adaptive_engage",
]
