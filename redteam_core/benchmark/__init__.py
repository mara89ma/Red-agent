"""benchmark — xbow식 능력 벤치마크 (§Y).

xbow validation-benchmarks 영감: 재현가능 챌린지 + 성공 오라클 + 난이도 티어로
에이전트의 실제 공격 능력을 **객관 채점**한다. 단, 우리 차별점은 성공 오라클을
'flag 캡처'가 아니라 **목표달성 AND blue 미탐지**(폐루프 탐지회피)로 둔다.

  - harness  : Challenge·Scoreboard·run_suite (오라클·탐지회피 채점)
  - suite     : UAV 도메인 챌린지 B1~B* (시나리오 S1~S55 기반, 난이도 1~3)
  - external  : 외부 벤치마크 어댑터(xbow·Cybench·garak seam)
"""
from .harness import Challenge, Scoreboard, run_challenge, run_suite
from .suite import UAV_BENCHMARKS
from .external import EXTERNAL_BENCHMARKS, external_status

__all__ = ["Challenge", "Scoreboard", "run_challenge", "run_suite",
           "UAV_BENCHMARKS", "EXTERNAL_BENCHMARKS", "external_status"]
