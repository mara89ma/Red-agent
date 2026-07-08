"""Metasploit 연동 — MCP/RPC seam (§Q).

env MSF_MCP_URL(Metasploit MCP 게이트웨이) 또는 MSF_RPC_HOST/PORT/PASSWORD(msfrpcd)
지정 시 실 연동, 아니면 결정론 폴백. 우리 시나리오를 msf 모듈에 매핑.

안전: 실 모듈 실행은 §T 샌드박스 guarded(격리·스코프내·non-malicious) 통과 시에만
(fail-closed). 미설정=dry(실행할 모듈·옵션만 반환).
"""
from __future__ import annotations

import os
from typing import Optional

# 우리 시나리오 → Metasploit 모듈(IT/인프라 인접 위주). UAV 특화는 msf 커버 밖.
SCENARIO_MSF = {
    "S6": ("auxiliary/scanner/http/http_login", {"RHOSTS": "", "USERPASS_FILE": ""}),
    "S23": ("auxiliary/dos/http/slowloris", {"RHOSTS": ""}),
    "S25": ("auxiliary/dos/tcp/synflood", {"RHOST": ""}),
    "S34": ("auxiliary/scanner/portscan/tcp", {"RHOSTS": ""}),
    "S39": ("auxiliary/dos/wifi/deauth", {"CHANNEL": "6", "ADDR_DST": ""}),
    "S36": ("auxiliary/server/capture/http", {}),
}


def _mcp() -> str:
    return os.environ.get("MSF_MCP_URL", "")


def _rpc() -> tuple:
    return (os.environ.get("MSF_RPC_HOST", ""), int(os.environ.get("MSF_RPC_PORT", "55553") or 55553),
            os.environ.get("MSF_RPC_PASSWORD", ""))


def available() -> bool:
    if _mcp():
        return True                              # MCP 게이트웨이 URL 지정
    host, _p, pw = _rpc()
    if host and pw:
        try:
            __import__("pymetasploit3")
            return True
        except Exception:
            return False
    return False


def status() -> dict:
    mode = "mcp" if _mcp() else ("rpc" if available() else "fallback")
    return {"available": available(), "endpoint": _mcp() or (_rpc()[0] or None),
            "mode": "real" if available() else "fallback", "transport": mode,
            "mapped_scenarios": len(SCENARIO_MSF)}


def run_module(msf_module: str, options: dict) -> dict:
    """msf 모듈 실행. 실연동 시 §T 샌드박스 통과 후 MCP/RPC, 아니면 dry 플랜."""
    if available():
        from ..sandbox import guarded
        ep = _mcp() or _rpc()[0]
        from urllib.parse import urlparse
        u = urlparse(ep if "://" in ep else "http://" + ep)
        spec = {"name": f"msf:{msf_module}", "network": [(u.hostname or ep, u.port or 55553)]}
        return guarded(spec, lambda: _run_real(msf_module, options))
    return {"mode": "fallback(dry)", "module": msf_module, "options": options,
            "note": "MSF_MCP_URL/MSF_RPC_* 미설정 → 실행 플랜만"}


def run_scenario(scenario_id: str) -> dict:
    if scenario_id not in SCENARIO_MSF:
        return {"mode": "unmapped", "scenario": scenario_id,
                "note": "msf 미매핑(UAV 특화는 §U execute 사용)"}
    mod, opts = SCENARIO_MSF[scenario_id]
    return {"scenario": scenario_id, **run_module(mod, dict(opts))}


def _run_real(msf_module: str, options: dict) -> dict:  # pragma: no cover
    """실 MCP/RPC 실행 경로(게이트웨이/서버 있을 때만). 여기선 미실행."""
    # MCP: POST {MSF_MCP_URL}/tools/run_module. RPC: pymetasploit3 MsfRpcClient.
    return {"mode": "real", "module": msf_module, "options": options,
            "transport": "mcp" if _mcp() else "rpc"}
