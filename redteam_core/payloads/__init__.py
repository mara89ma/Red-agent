"""payloads — ML 공격 페이로드 실 생성기 (고도화 §N, PyRIT/Garak 방식).

동언님 ml_target 은 페이로드가 '설명자(descriptor)' 스텁이었다. 이 층은 실제
공격 페이로드를 **결정론적으로 생성**한다 — LLM 자유생성이 아니라 큐레이션 시드
라이브러리 + 변형 컨버터(PyRIT seed+converter 모델). 대상은 팀 자체 SOC(pollack-ai)
방어 AI = 인가된 레드팀 적대 에뮬레이션.

  - S32 프롬프트 인젝션: `prompt_inject` (AML.T0051)
  - S33 모델 추출: `extraction` (AML.T0057)
  - S7 적대 패치: `adversarial` (AML.T0043)

안전: 대상은 시험창 내 자체 SOC. 페이로드는 공개 레드팀 시드 수준, 결정론.
"""
from .prompt_inject import CONVERTERS, generate_prompt_injections
from .extraction import generate_extraction_ladder
from .adversarial import generate_adversarial_specs
from .run import (
    PayloadOutcome, bypass_rate, run_adaptive, run_adversarial,
    run_model_extraction, run_prompt_injection,
)
from .adaptive import AdaptivePayload, AdaptivePayloadGenerator, SituationContext
from .archive import (
    ArchivePayload, craft_tar_slip, craft_tar_symlink, craft_zip_absolute, craft_zip_slip,
)
from .advanced import ADVANCED_SCENARIOS
from .collection import COLLECTION_SCENARIOS

__all__ = [
    "CONVERTERS", "generate_prompt_injections",
    "generate_extraction_ladder", "generate_adversarial_specs",
    "PayloadOutcome", "bypass_rate", "run_adaptive", "run_adversarial",
    "run_model_extraction", "run_prompt_injection",
    "AdaptivePayload", "AdaptivePayloadGenerator", "SituationContext",
]
