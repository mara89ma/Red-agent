"""융합 레이어 공격 — 다중센서 정합성 공격 + 메시 저하.

모델: 각 센서 축은 개별 탐지 임계(indiv)를 갖는다. 상관기(AlertCorrelator)는 정규화
편차의 합이 corr_threshold 를 넘으면 상관인시던트를 올린다. red 는 각 축을 개별 임계
아래로 유지(개별 미탐)하면서 상관 합만 조작한다.
  - FP(가짜 상관): 각 축 그럴듯한데 합쳐서 상관기가 거짓 인시던트 발화
  - FN(진짜를 노이즈로): 진짜 공격을 여러 축에 분산해 개별·상관 모두 임계 아래
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

# 축 → 개별 탐지 임계(정규화). 상관기는 여러 축의 정규화 편차 합을 본다.
SENSOR_AXES: Dict[str, float] = {
    "gnss": 1.0, "imu": 1.0, "telemetry": 1.0, "datalink": 1.0, "eo_ir": 1.0,
}
_CORR_THRESHOLD = 2.5          # 상관인시던트 발화 임계(축별 정규화 편차 합)


@dataclass
class FusionResult:
    mode: str                  # false_positive | false_negative
    per_axis: Dict[str, float]
    individually_stealthy: bool   # 모든 축이 개별 임계 아래
    corr_sum: float
    correlator_fires: bool
    success: bool
    note: str = ""


def multi_sensor_consistency_attack(magnitudes: Dict[str, float],
                                    mode: str = "false_positive") -> FusionResult:
    """정규화 편차(magnitude/indiv)로 개별 미탐 + 상관 조작.

    - false_positive: 개별 전부 미탐(<1.0)인데 상관합 ≥ 임계 → 거짓 상관 발화.
    - false_negative: 진짜 사건을 분산해 개별·상관 모두 임계 아래(노이즈로 위장).
    """
    per_axis = {a: round(magnitudes.get(a, 0.0) / SENSOR_AXES[a], 3) for a in SENSOR_AXES}
    indiv_stealthy = all(v < 1.0 for v in per_axis.values())
    corr_sum = round(sum(per_axis.values()), 3)
    fires = corr_sum >= _CORR_THRESHOLD
    if mode == "false_positive":
        success = indiv_stealthy and fires            # 개별 미탐 + 거짓 상관
        note = "각 축 그럴듯(개별 미탐)한데 조합=거짓 상관인시던트" if success else "미달"
    else:  # false_negative
        success = (not fires)                         # 진짜인데 상관 미발화=노이즈 위장
        note = "진짜 사건을 분산해 상관기가 노이즈로 착각" if success else "상관기가 잡음"
    return FusionResult(mode, per_axis, indiv_stealthy, corr_sum, fires, success, note)


@dataclass
class MeshResult:
    total_links: int
    severed: int
    available_axes: int
    min_axes_for_corr: int
    correlation_functional: bool
    graceful: bool
    verdict: str


def mesh_degradation_test(total_links: int = 5, severed: int = 2,
                          min_axes_for_corr: int = 2) -> MeshResult:
    """EW로 severed 개 링크 절단 → 남은 축으로 상관 가능한지·우아한 저하인지."""
    available = max(0, total_links - severed)
    functional = available >= min_axes_for_corr
    # 우아한 저하: 링크가 줄어도 최소 상관은 유지(=functional). 파국=상관 완전 실패.
    graceful = functional
    verdict = ("우아한 성능저하(상관 유지)" if graceful
               else "파국적 실패(상관 붕괴)=SOC 상황인식 상실")
    return MeshResult(total_links, severed, available, min_axes_for_corr,
                      functional, graceful, verdict)
