"""Web/API·Linux 권한상승 S48~S52 생성·분석·배선 테스트. 결정론·무의존."""
from __future__ import annotations

from redteam_core.payloads.exploits import (
    EXPLOIT_SCENARIOS, run_exploit,
    craft_idor, craft_webshell, craft_pickle,
    craft_suid, craft_container_escape, craft_cron_hijack,
)
from redteam_core.sandbox import analyze


def test_s48_idor_blind_spot():
    r = analyze(craft_idor())
    assert r.scenario == "S48" and r.blind_spot is True     # blue 방어 공백


def test_s49_webshell_malicious():
    r = analyze(craft_webshell("imagery.php"))
    assert r.verdict == "malicious" and any("웹셸" in i for i in r.indicators)


def test_s49_pickle_deserialization_malicious():
    r = analyze(craft_pickle())
    assert r.verdict == "malicious" and any("역직렬화" in i for i in r.indicators)


def test_s50_suid_gtfobins_malicious():
    r = analyze(craft_suid("find"))
    assert r.scenario == "S50" and r.verdict == "malicious"


def test_s51_container_escape_malicious():
    for v in ("privileged", "hostpath", "docker_sock", "hostpid"):
        r = analyze(craft_container_escape(v))
        assert r.verdict == "malicious", v


def test_s52_cron_hijack_malicious():
    r = analyze(craft_cron_hijack())
    assert r.scenario == "S52" and r.verdict == "malicious"


def test_run_exploit_wiring():
    # 배선: 레지스트리 전 시나리오가 run_exploit 로 실행되고 판정을 낸다.
    assert set(EXPLOIT_SCENARIOS) == {"S48", "S49", "S50", "S51", "S52"}
    for sid in EXPLOIT_SCENARIOS:
        out = run_exploit(sid)
        assert out["scenario"] == sid and out["blue_detected"] is None
    assert run_exploit("S48")["blind_spot"] is True                  # IDOR 사각지대
    assert run_exploit("S51")["sandbox_verdict"] == "malicious"      # escape §T 탐지
