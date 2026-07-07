"""LLM 조언 seam (B10) — 선택적·조언 전용 주입점.

기본은 무-LLM(NullLLMClient). `REDTEAM_LLM_PROVIDER`로만 켜지며, 판정권은 절대
LLM에 없다(설계 D2). 판단은 B5 judge 앙상블에서 결정론 오라클의 veto 하에 조언으로만
합쳐진다.
"""

from .client import (  # noqa: F401
    HttpLLMClient,
    LLMClient,
    LLMResponse,
    NullLLMClient,
)
from .factory import build_llm_client, get_llm_client  # noqa: F401
