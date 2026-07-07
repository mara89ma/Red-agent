"""LLM 클라이언트 seam (B10) — **선택적·조언 전용** 주입점.

RedTeam 데모의 기본 전제는 여전히 '무-LLM'이다: 기본 클라이언트는 `NullLLMClient`
로, 네트워크를 절대 건드리지 않고 항상 **기권(abstain)** 한다. LLM은 운영자가
`REDTEAM_LLM_PROVIDER`를 명시할 때만 켜지는 opt-in seam이며, 그 판단은 언제나
**조언(advisory)** 에 그친다 — 안전 게이트/체커/ground-truth 오라클의 판정권을
절대 대체하지 않는다(설계 불변식 D2). 모든 호출은 graceful-degrade: 실패 시
`ok=False`로 조용히 기권하고 결정론 경로가 이어받는다.

의존성: 표준 라이브러리 `urllib`만 사용(Tier-0 무의존). Ollama 로컬(`/api/chat`)과
OpenAI 호환(`/v1/chat/completions`) 두 스타일을 지원한다.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from ..logging_util import get_logger

log = get_logger("llm")

_LOOPBACK = ("localhost", "127.0.0.1", "::1")


@dataclass
class LLMResponse:
    """LLM 호출 결과 봉투. 실패해도 예외 없이 `ok=False`로 회수된다."""

    text: Optional[str] = None
    ok: bool = False
    provider: str = "none"
    error: Optional[str] = None

    def __bool__(self) -> bool:                              # `if resp:` == 성공 여부
        return self.ok and self.text is not None


@runtime_checkable
class LLMClient(Protocol):
    """조언 LLM 계약 — 최소 표면. 구현은 반드시 예외를 삼키고 LLMResponse만 낸다."""

    provider: str

    def available(self) -> bool: ...

    def complete(self, prompt: str, *, system: Optional[str] = None,
                 max_tokens: int = 512, temperature: float = 0.0) -> LLMResponse: ...


class NullLLMClient:
    """기본 구현 — 네트워크 없음, 항상 기권. '무-LLM 기본'을 보장한다."""

    provider = "none"

    def available(self) -> bool:
        return False

    def complete(self, prompt: str, *, system: Optional[str] = None,
                 max_tokens: int = 512, temperature: float = 0.0) -> LLMResponse:
        return LLMResponse(text=None, ok=False, provider="none", error="llm_disabled")


def _host_of(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


class HttpLLMClient:
    """urllib 기반 조언 클라이언트(ollama|openai 스타일). 모든 실패는 기권으로 흡수.

    egress 규율(intel/feed와 동일): 루프백이 아닌 호스트는 **HTTPS 강제**. 로컬
    Ollama(`http://localhost:11434`)만 평문 허용.
    """

    def __init__(self, provider: str, base_url: str, model: str, *,
                 api_style: str = "openai", api_key: str = "", timeout: float = 8.0) -> None:
        self.provider = provider
        self._base = base_url.rstrip("/")
        self._model = model
        self._style = api_style                 # "openai" | "ollama"
        self._key = api_key
        self._timeout = timeout

    def available(self) -> bool:
        return bool(self._base and self._model)

    def _endpoint(self) -> str:
        if self._style == "ollama":
            return f"{self._base}/api/chat"
        return f"{self._base}/v1/chat/completions"

    def _check_scheme(self) -> Optional[str]:
        host = _host_of(self._base)
        if not self._base.startswith("https://") and host not in _LOOPBACK:
            return f"평문 HTTP 비루프백 거부: {self._base}"       # fail-closed
        return None

    def complete(self, prompt: str, *, system: Optional[str] = None,
                 max_tokens: int = 512, temperature: float = 0.0) -> LLMResponse:
        if not self.available():
            return LLMResponse(provider=self.provider, error="unconfigured")
        scheme_err = self._check_scheme()
        if scheme_err:
            log.warning("LLM egress 거부: %s", scheme_err)
            return LLMResponse(provider=self.provider, error=scheme_err)

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        if self._style == "ollama":
            body = {"model": self._model, "messages": messages, "stream": False,
                    "options": {"temperature": temperature}}
        else:
            body = {"model": self._model, "messages": messages,
                    "temperature": temperature, "max_tokens": max_tokens}

        req = urllib.request.Request(
            self._endpoint(), data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        if self._key and self._style != "ollama":
            req.add_header("Authorization", f"Bearer {self._key}")

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            text = self._extract(payload)
            if text is None:
                return LLMResponse(provider=self.provider, error="empty_response")
            return LLMResponse(text=text, ok=True, provider=self.provider)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            log.warning("LLM 호출 실패(기권): %s", exc)         # graceful-degrade
            return LLMResponse(provider=self.provider, error=str(exc))

    def _extract(self, payload: dict) -> Optional[str]:
        try:
            if self._style == "ollama":
                return payload["message"]["content"]
            return payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return None
