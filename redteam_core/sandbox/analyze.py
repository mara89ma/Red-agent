"""익스플로잇 정적 분석기 — Web/API·Linux 권한상승 탐지 (§T 확장, S48~S52).

red 익스플로잇(§N exploits)을 실행 없이 정적 분석해 악성 지표·판정을 낸다. blue
Sentinel(UAV 도메인)이 못 보는 IT 계층을 §T 가 방어 seam 으로 커버. IDOR 처럼
탐지기 없는 것은 blind_spot 로 표기(= blue 방어 공백).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class AnalyzeReport:
    scenario: str
    kind: str
    indicators: List[str] = field(default_factory=list)
    verdict: str = "benign"        # benign | suspicious | malicious
    blind_spot: bool = False       # 탐지기 없음(blue 방어 공백)


_WEBSHELL_EXT = (".php", ".jsp", ".jspx", ".aspx", ".phtml")
_WEBSHELL_SIG = (b"system(", b"exec(", b"eval(", b"passthru(", b"<?php", b"shell_exec")
_ESCAPE_KEYS = ("privileged", "hostPath", "docker.sock", "SYS_ADMIN", "hostPID", "hostNetwork")


def _upload(p) -> AnalyzeReport:
    r = AnalyzeReport(p.scenario, p.kind)
    name, data = p.data
    if name.lower().endswith(_WEBSHELL_EXT) or any(s in data for s in _WEBSHELL_SIG):
        r.indicators.append(f"웹셸 업로드: {name}")
        r.verdict = "malicious"
    if data[:1] == b"\x80" and (b"system" in data or b"os\n" in data or b"posix" in data or b"subprocess" in data):
        r.indicators.append("역직렬화(pickle) RCE 가젯")
        r.verdict = "malicious"
    return r


def _escape(p) -> AnalyzeReport:
    r = AnalyzeReport(p.scenario, p.kind)
    blob = str(p.data)
    hits = [k for k in _ESCAPE_KEYS if k in blob]
    if hits:
        r.indicators.append(f"컨테이너 escape 지표: {hits}")
        r.verdict = "malicious"
    return r


def _suid(p) -> AnalyzeReport:
    r = AnalyzeReport(p.scenario, p.kind)
    binary, cmd = p.data
    from ..payloads.exploits import _GTFO_SUID
    if binary in _GTFO_SUID:
        r.indicators.append(f"GTFOBins SUID 권한상승: {binary}")
        r.verdict = "malicious"
    return r


def _cron(p) -> AnalyzeReport:
    r = AnalyzeReport(p.scenario, p.kind)
    path, _ = p.data
    if "cron" in path or path.startswith("/etc"):
        r.indicators.append(f"cron/시스템 경로 쓰기(지속성·권한상승): {path}")
        r.verdict = "malicious"
    return r


def _idor(p) -> AnalyzeReport:
    # 전용 탐지기 없음 → blue 방어 공백(사각지대).
    return AnalyzeReport(p.scenario, p.kind, indicators=["API IDOR — Sentinel 미탐지(사각지대)"],
                         verdict="benign", blind_spot=True)


def _keyword(p, keys, label) -> AnalyzeReport:
    r = AnalyzeReport(p.scenario, p.kind)
    blob = str(p.data)
    if any(k in blob for k in keys):
        r.indicators.append(label)
        r.verdict = "malicious"
    return r


def _destruction(p):
    return _keyword(p, ("rm -rf", "rm ", "wipe", "shred", "delete"), "데이터 파괴(로그·임무·SAR)")


def _rootkit(p):
    return _keyword(p, ("ld.so.preload", "insmod", ".ko", "hook", "hide"), "rootkit 설치(은폐)")


def _fw_mode(p):
    return _keyword(p, ("bootloader", "246", "reboot"), "FW 업데이트 모드 강제(제어 중단)")


def _auth_modify(p):
    return _keyword(p, ("always-pass", "return True", "verify"), "인증 로직 변조(백도어)")


def _exfil_alt(p):
    r = AnalyzeReport(p.scenario, p.kind)
    ch = p.data.get("channel") if isinstance(p.data, dict) else ""
    r.indicators.append(f"대체매체 유출({ch}) — blue 용량/페이로드 미포착(사각)")
    r.verdict = "suspicious"; r.blind_spot = True       # 전용 로그 없음
    return r


def _theft(p):
    return _keyword(p, ("EO/IR", "SAR", "copy", "targets"), "작전정보(영상·표적) 탈취")


def _collection(p):
    # 수동 수집 — red 는 수행하나 blue 전용 로그 없음 → 정직하게 blind_spot.
    r = AnalyzeReport(p.scenario, p.kind)
    r.indicators.append(f"{p.technique} 수동 수집 — blue 로그 없음(사각지대)")
    r.verdict = "suspicious"; r.blind_spot = True
    return r


def _recon(p):
    r = AnalyzeReport(p.scenario, p.kind)
    r.indicators.append(f"{p.technique} 정찰 — 예방통제(격리) 대상, blue 탐지 제한(사각)")
    r.verdict = "suspicious"; r.blind_spot = True
    return r


_DISPATCH = {"upload": _upload, "escape": _escape,
             "suid": _suid, "cron": _cron, "idor": _idor,
             "destruction": _destruction, "rootkit": _rootkit, "fw_mode": _fw_mode,
             "auth_modify": _auth_modify, "exfil_alt": _exfil_alt, "theft": _theft,
             "collection": _collection, "recon": _recon}


def analyze(payload) -> AnalyzeReport:
    return _DISPATCH.get(payload.kind, lambda p: AnalyzeReport(p.scenario, p.kind))(payload)
