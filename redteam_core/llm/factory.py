"""LLM 클라이언트 팩토리 (B10) — 설정 → 구현 선택, 캐시.

`REDTEAM_LLM_PROVIDER`가 유일한 스위치다:
    • "none"(기본)   → NullLLMClient (네트워크 없음, 항상 기권 → 무-LLM 데모 보존)
    • "ollama"       → HttpLLMClient(로컬 http://localhost:11434, /api/chat, 키 불요)
    • "openai"/그외  → HttpLLMClient(OpenAI 호환 /v1/chat/completions, api_key 사용)

잘못된 설정(예: provider는 켰는데 base_url/model 미지정)은 크래시 대신 조용히
`available()==False`로 떨어져 결정론 경로가 이어받는다.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from ..logging_util import get_logger
from ..settings import get_settings
from .client import HttpLLMClient, LLMClient, NullLLMClient

log = get_logger("llm")

_OLLAMA_DEFAULT_URL = "http://localhost:11434"


def build_llm_client(settings=None) -> LLMClient:
    """설정으로부터 클라이언트를 만든다(비캐시). 테스트는 이걸 직접 부른다."""
    s = settings or get_settings()
    provider = (getattr(s, "llm_provider", "none") or "none").strip().lower()

    if provider in ("", "none", "off", "disabled"):
        return NullLLMClient()

    base = getattr(s, "llm_base_url", "") or ""
    model = getattr(s, "llm_model", "") or ""
    key_field = getattr(s, "llm_api_key", None)
    key = key_field.get_secret_value() if hasattr(key_field, "get_secret_value") else (key_field or "")

    if provider == "ollama":
        client = HttpLLMClient("ollama", base or _OLLAMA_DEFAULT_URL,
                               model or "llama3", api_style="ollama")
    else:  # openai 호환(azure/vllm/together 등 포함)
        client = HttpLLMClient(provider, base, model, api_style="openai", api_key=key)

    if not client.available():
        log.warning("LLM provider=%r 이지만 base_url/model 미설정 → 기권(NullLLMClient)", provider)
        return NullLLMClient()
    log.info("LLM 조언 활성: provider=%s model=%s", client.provider, model)
    return client


@lru_cache(maxsize=1)
def get_llm_client() -> LLMClient:
    """조언 LLM 클라이언트 싱글턴. 설정 변경 반영 시 `get_llm_client.cache_clear()`."""
    return build_llm_client()
