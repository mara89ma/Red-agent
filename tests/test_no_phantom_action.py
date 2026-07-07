"""no-phantom-action 가드 (F) — T3MP3ST no-phantom-tools 이식(공격판).

원칙 "advertised = wired": 무기고/커버리지에 실린 기법은 실제 실행 가능해야 한다.
MAP·playbook·static_kb가 참조하는 모든 액션이 canonical ATOMIC_ACTIONS에 등록됐는지,
그리고 등록된 액션이 classify에서 조용히 fail-closed 기본값으로 떨어지지 않는지 잠근다
(phantom 능력 = 거짓 커버리지 방지).
"""

from redteam_core.mapping.attack_d3fend import MAP
from redteam_core.rag.playbook import PLAYBOOKS
from redteam_core.rag.static_kb import COMMAND_SPEC
from redteam_core.safety.reversibility import classify
from redteam_core.tools.mavlink import ATOMIC_ACTIONS

_ATOMIC = set(ATOMIC_ACTIONS)
# 지상에서 physical_irreversible이 정당한 액션(나머지가 그리 분류되면 phantom classify 의심).
_EXPECTED_IRREVERSIBLE = {"takeoff", "flight_terminate"}


def test_map_actions_all_executable():
    """MAP에 실린 모든 액션(=커버리지 무기고)이 실제 등록 원자 액션이어야 한다."""
    phantom = sorted(set(MAP) - _ATOMIC)
    assert phantom == [], f"MAP에 실행 불가 phantom 액션: {phantom}"


def test_playbook_actions_all_executable():
    pb_actions = {a for pb in PLAYBOOKS.values() for (a, _p, _e) in pb["steps"]}
    phantom = sorted(pb_actions - _ATOMIC)
    assert phantom == [], f"playbook에 phantom 액션: {phantom}"


def test_static_kb_actions_all_executable():
    phantom = sorted(set(COMMAND_SPEC) - _ATOMIC)
    assert phantom == [], f"static_kb에 phantom 액션: {phantom}"


def test_no_registered_action_silently_failcloses():
    """등록 액션은 classify에 명시 분기가 있어야 — 미등록만 fail-closed 기본으로 떨어져야."""
    for action in _ATOMIC:
        tier, _gate = classify({"in_flight": False}, action)
        if action in _EXPECTED_IRREVERSIBLE:
            assert tier == "physical_irreversible", f"{action} 는 비가역이어야"
        else:
            assert tier != "physical_irreversible", \
                f"{action} 가 fail-closed 기본으로 떨어짐(classify 분기 누락 = phantom 의심)"


def test_unknown_action_is_failclosed():
    tier, gate = classify({"in_flight": False}, "totally_made_up_phantom_action")
    assert tier == "physical_irreversible" and gate == "human_only"
