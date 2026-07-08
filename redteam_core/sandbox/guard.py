"""detonate-before-live 가드 — §Q 실도구 실행 전 §T 샌드박스 안전검사.

실 도구(PyRIT/Garak·Caldera)·실 페이로드를 라이브 실행하기 전에 샌드박스에서
폭파해, **격리 봉인 + 스코프 내 egress + non-malicious** 일 때만 실행을 허용한다.
그렇지 않으면 fail-closed(실행 차단). 스코프는 engagement_profile scope_cidr(인가 팀).
"""
from __future__ import annotations

import pathlib
from typing import Callable, Tuple
from urllib.parse import urlparse

from .detonate import DetonationReport, DetonationSandbox, SandboxPolicy


def default_policy() -> SandboxPolicy:
    """engagement_profile.yaml 의 scope_cidr 로 egress allowlist 구성(폴백 기본망)."""
    cidrs = ["10.50.0.0/24"]
    try:
        from ..engagement.gate import load_gate
        p = pathlib.Path(__file__).resolve().parents[2] / "engagement_profile.yaml"
        _, profile = load_gate(str(p))
        cidrs = profile.get("authorization", {}).get("scope_cidr", cidrs)
    except Exception:
        pass
    return SandboxPolicy(allowed_cidrs=cidrs)


def _endpoint(url: str, default_port: int):
    u = urlparse(url if "://" in url else "http://" + url)
    return u.hostname or "", (u.port or default_port)


def ai_spec(technique: str, target_url: str) -> dict:
    host, port = _endpoint(target_url, 443)
    return {"name": f"ai:{technique}", "network": [(host, port)] if host else []}


def caldera_spec(chain_id: str, url: str) -> dict:
    host, port = _endpoint(url, 8888)
    return {"name": f"caldera:{chain_id}", "network": [(host, port)] if host else []}


def guard(spec: dict, policy: SandboxPolicy = None) -> Tuple[bool, DetonationReport]:
    """샌드박스 폭파 → (실행 허용 여부, 리포트). 허용=봉인+스코프내+non-malicious."""
    report = DetonationSandbox(policy or default_policy()).detonate(spec)
    safe = report.contained and not report.egress_blocked and report.verdict != "malicious"
    return safe, report


def guarded(spec: dict, live_fn: Callable[[], dict], policy: SandboxPolicy = None) -> dict:
    """안전하면 live_fn 실행, 아니면 fail-closed(실행 차단)."""
    safe, report = guard(spec, policy)
    if not safe:
        return {"mode": "blocked_by_sandbox", "artifact": report.artifact,
                "verdict": report.verdict, "egress_blocked": report.egress_blocked,
                "indicators": report.indicators}
    return live_fn()
