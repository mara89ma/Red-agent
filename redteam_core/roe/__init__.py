"""roe — RoE·교전권한·데컨플릭션 게이트 (고도화 §B, 미 DoD 사이버작전 교리 정박).

동언님 reversibility 게이트("해도 되나=안전")와 **직교**하는 축을 더한다:
"누가·어떤 교전권한으로·어떤 수칙 하에" 허가되나.

교리 근거:
  - SROE (CJCSI 3121.01): 자위권 vs 임무 RoE, 적극식별(PID), 교전권한.
  - JP 3-60: 지휘결심·화력할당(④), no-strike/제한표적(NSL/RTL).
  - CJCSM 3160: 부수효과추정(CDE) 방법론 → 등급↑이면 요구 권한↑.
  - JP 3-85 (JEMSO): 전자전(jam/gnss_spoof) 스펙트럼 데컨플릭션(JCEOI).
  - JP 3-09: 화력 데컨플릭션. DoDD 3000.09: 판정은 모델 밖(결정론).

판정은 LLM이 아니라 이 결정론 게이트에 있다(동언님 철학과 동형).
"""
from .authority import AuthorityLevel, required_authority
from .cde import CdeTier, estimate_cde
from .deconfliction import DeconflictionResult, check_deconfliction
from .roe_gate import RoeDecision, RoeVerdict, evaluate_roe, load_roe_profile

__all__ = [
    "AuthorityLevel", "required_authority",
    "CdeTier", "estimate_cde",
    "DeconflictionResult", "check_deconfliction",
    "RoeDecision", "RoeVerdict", "evaluate_roe", "load_roe_profile",
]
