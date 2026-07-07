"""설정·로깅 테스트 (B3/B4).

    B4  get_settings 싱글턴 · 모든 필드 기본값 · env 오버라이드 · SecretStr 마스킹.
    B3  get_logger 가 redteam.* 로거를 반환하고 크래시하지 않음.
"""

import logging

from redteam_core.logging_util import get_logger
from redteam_core.settings import get_settings, settings_summary


class TestSettings:
    def test_singleton(self):
        assert get_settings() is get_settings()

    def test_defaults_present(self):
        s = get_settings()
        assert s.log_level == "INFO"
        assert s.budget_tool_calls == 40
        assert s.hitl_deny_physical is True
        assert s.llm_provider == "none"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("REDTEAM_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("REDTEAM_BUDGET_TOOL_CALLS", "7")
        get_settings.cache_clear()
        s = get_settings()
        assert s.log_level == "DEBUG"
        assert s.budget_tool_calls == 7
        get_settings.cache_clear()                 # 다른 테스트에 누수 방지

    def test_secret_is_masked(self, monkeypatch):
        monkeypatch.setenv("REDTEAM_LLM_API_KEY", "topsecret-value")
        get_settings.cache_clear()
        s = get_settings()
        assert s.llm_api_key.get_secret_value() == "topsecret-value"
        assert "topsecret-value" not in repr(s.llm_api_key)     # 마스킹
        get_settings.cache_clear()

    def test_summary_masks_secrets(self, monkeypatch):
        monkeypatch.setenv("REDTEAM_SHODAN_API_KEY", "abc123")
        get_settings.cache_clear()
        out = settings_summary()
        assert out["shodan_api_key"] == "***set***"
        assert out["llm_api_key"] == "***unset***"
        assert "abc123" not in str(out)
        get_settings.cache_clear()


class TestLogging:
    def test_get_logger_namespaced(self):
        lg = get_logger("unittest")
        assert isinstance(lg, logging.Logger)
        assert lg.name == "redteam.unittest"

    def test_logger_has_handler_once(self):
        a = get_logger("dup")
        b = get_logger("dup")
        assert a is b
        assert len(a.handlers) == 1                # 중복 부착 없음
