"""중앙 설정 — pydantic-settings 있으면 사용, 없으면 stdlib 폴백(무의존 보장).

방어측 pollack-ai `core/settings.py` 패턴 이식:
    • 단일 Settings 클래스, **모든 필드 기본값**(import는 절대 크래시 안 함),
    • 시크릿은 `SecretStr`로 마스킹(로그/덤프에 노출 금지),
    • `@lru_cache get_settings()` 싱글턴, 존재검증은 호출 시점에.

환경변수 접두사 `REDTEAM_` (예: `REDTEAM_LOG_LEVEL=DEBUG`). 공격 툴체인은
API 키(Shodan/VT/타깃 크리덴셜·미래 LLM)를 많이 다루므로 마스킹이 중요하다.
"""

from __future__ import annotations

import os
from functools import lru_cache

try:  # 선호: pydantic-settings (Tier 0 선택 의존)
    from pydantic import Field, SecretStr
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _HAS_PYDANTIC = True
except Exception:  # pragma: no cover - 폴백 경로(무의존 데모)
    _HAS_PYDANTIC = False


_SECRET_FIELDS = ("llm_api_key", "shodan_api_key", "virustotal_api_key")
_PLAIN_FIELDS = ("log_level", "default_profile", "apply_egress",
                 "budget_tool_calls", "hitl_deny_physical",
                 "llm_provider", "llm_base_url", "llm_model", "llm_judge_panel")


if _HAS_PYDANTIC:

    class Settings(BaseSettings):
        """pydantic 기반 설정(선호). 모든 필드 기본값 → import 무크래시."""

        model_config = SettingsConfigDict(env_prefix="REDTEAM_", env_file=".env",
                                          extra="ignore", case_sensitive=False)

        log_level: str = Field("INFO", description="루트 로그 레벨")
        default_profile: str = Field("engagement_profile.yaml",
                                     description="기본 engagement 프로파일 경로")
        apply_egress: bool = Field(False, description="OS 방화벽에 egress 실설치(root)")
        budget_tool_calls: int = Field(40, ge=1, le=100000,
                                       description="툴콜 예산(무한루프 방지)")
        hitl_deny_physical: bool = Field(True, description="물리 비가역 자동거부(인간 전용)")
        llm_provider: str = Field("none", description="advisory LLM 제공자(none|ollama|openai)")
        llm_base_url: str = Field("", description="LLM 엔드포인트 base URL(빈값=제공자 기본)")
        llm_model: str = Field("", description="LLM 모델명(빈값=제공자 기본)")
        llm_judge_panel: int = Field(3, ge=1, le=9, description="judge LLM skeptic 패널 크기")
        llm_api_key: SecretStr = Field(default=SecretStr(""), description="LLM API 키")
        shodan_api_key: SecretStr = Field(default=SecretStr(""), description="Shodan 키")
        virustotal_api_key: SecretStr = Field(default=SecretStr(""), description="VT 키")

else:

    class SecretStr:  # 최소 폴백 — get_secret_value + 마스킹된 repr
        __slots__ = ("_v",)

        def __init__(self, value: str = "") -> None:
            self._v = str(value)

        def get_secret_value(self) -> str:
            return self._v

        def __bool__(self) -> bool:
            return bool(self._v)

        def __repr__(self) -> str:
            return "SecretStr('**********')" if self._v else "SecretStr('')"

        __str__ = __repr__

    def _envbool(key: str, default: bool) -> bool:
        return os.getenv(key, str(default)).strip().lower() in ("1", "true", "yes", "on")

    class Settings:  # type: ignore[no-redef]
        """stdlib 폴백 설정. 환경변수 `REDTEAM_*`를 읽고 기본값 제공."""

        def __init__(self) -> None:
            g = os.getenv
            self.log_level = g("REDTEAM_LOG_LEVEL", "INFO")
            self.default_profile = g("REDTEAM_DEFAULT_PROFILE", "engagement_profile.yaml")
            self.apply_egress = _envbool("REDTEAM_APPLY_EGRESS", False)
            self.budget_tool_calls = int(g("REDTEAM_BUDGET_TOOL_CALLS", "40"))
            self.hitl_deny_physical = _envbool("REDTEAM_HITL_DENY_PHYSICAL", True)
            self.llm_provider = g("REDTEAM_LLM_PROVIDER", "none")
            self.llm_base_url = g("REDTEAM_LLM_BASE_URL", "")
            self.llm_model = g("REDTEAM_LLM_MODEL", "")
            self.llm_judge_panel = int(g("REDTEAM_LLM_JUDGE_PANEL", "3"))
            self.llm_api_key = SecretStr(g("REDTEAM_LLM_API_KEY", ""))
            self.shodan_api_key = SecretStr(g("REDTEAM_SHODAN_API_KEY", ""))
            self.virustotal_api_key = SecretStr(g("REDTEAM_VIRUSTOTAL_API_KEY", ""))


@lru_cache(maxsize=1)
def get_settings() -> "Settings":
    """설정 싱글턴. 환경변수 변경 반영이 필요하면 `get_settings.cache_clear()`."""
    return Settings()


def settings_summary(settings: "Settings | None" = None) -> dict:
    """로그/리포트용 마스킹 덤프 — 시크릿은 절대 값 노출 안 함."""
    s = settings or get_settings()
    out = {f: getattr(s, f, None) for f in _PLAIN_FIELDS}
    for f in _SECRET_FIELDS:
        v = getattr(s, f, None)
        has = bool(v.get_secret_value()) if hasattr(v, "get_secret_value") else bool(v)
        out[f] = "***set***" if has else "***unset***"
    return out
