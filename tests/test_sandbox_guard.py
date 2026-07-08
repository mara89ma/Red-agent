"""detonate-before-live 가드 (§T→§Q 배선) 테스트 — 결정론·무의존."""
from __future__ import annotations

from redteam_core.sandbox import SandboxPolicy, ai_spec, caldera_spec, guarded

_SCOPE = SandboxPolicy(allowed_cidrs=["10.50.0.0/24"])


def test_guard_blocks_out_of_scope_target():
    called = []
    r = guarded({"name": "x", "network": [("203.0.113.66", 80)]},
                lambda: called.append(1) or {"mode": "real"}, _SCOPE)
    assert r["mode"] == "blocked_by_sandbox" and called == []      # 실행 안 됨


def test_guard_allows_in_scope_target():
    called = []
    def _live():
        called.append(1); return {"mode": "real"}
    r = guarded({"name": "x", "network": [("10.50.0.20", 80)]}, _live, _SCOPE)
    assert r["mode"] == "real" and called == [1]                  # 실행됨


def test_guard_blocks_malicious_payload():
    r = guarded({"name": "impl", "files": [(".implant", b"x")]},
                lambda: {"mode": "real"}, _SCOPE)
    assert r["mode"] == "blocked_by_sandbox" and r["verdict"] == "malicious"


def test_ai_spec_parses_target():
    assert ai_spec("prompt_injection", "http://10.50.0.30:8000")["network"] == [("10.50.0.30", 8000)]


def test_caldera_spec_parses_url():
    assert caldera_spec("C1", "http://10.50.0.40:8888")["network"] == [("10.50.0.40", 8888)]


def test_ai_attack_fallback_unchanged_without_env():
    from redteam_core.integrations.ai_attack import run_ai_attack
    assert run_ai_attack("prompt_injection")["mode"] == "fallback"   # env 없으면 폴백(가드 미개입)


def test_caldera_fallback_unchanged_without_env():
    from redteam_core.integrations.caldera import run_operation
    assert run_operation("C1")["mode"] == "fallback"
