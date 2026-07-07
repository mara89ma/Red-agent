"""(4) Planner/Reasoner — 추상 액션 계획 + 원자 전개 (§1.4(4)·§1.6).

추상 액션(hijack)은 **계획 단위**로만 존재하고, Planner가 즉시 **원자 PTG 노드
시퀀스로 전개**한다(§1.6 핵심 불변식). 각 원자 노드가 독립 risk_tier·reversibility
보유. receding-horizon: 한 번에 1 스텝만 커밋(FLARE 2601.22311).

facts→PTG 적재는 planner의 첫 책무(§2.5 주석).
"""

from __future__ import annotations

from ..graph.state import PTGNode
from ..rag import playbook
from ..safety.reversibility import reversibility_of


def _expand_playbook(state) -> None:
    """추상 액션을 원자 PTG 노드로 전개해 plan_queue에 적재(1회)."""
    profile = state["profile"]
    gate = state["gate"]
    hosts = profile.get("target_profile", {}).get("hosts") or [{}]
    sysid = hosts[0].get("sysid", 1)

    abstract = profile.get("engagement", {}).get("abstract_action", "A4_force_arm_takeoff")
    pb = playbook.expand(abstract)                       # untrusted playbook
    # 절차 메모리 참조 — 재engagement에서 이미 효용이 증명된 playbook인지(§2.3, M3 DoD).
    proc = state["memory"].procedural.get(abstract, {"utility": 0.0, "uses": 0})
    state["_abstract_action"] = abstract
    state["_playbook_reused"] = proc["uses"] > 0

    # per-target 권고(B7/B6/B8) — 이제 계획에 배선한다(인과 lift).
    # 빈 스토어(첫 run)면 skip 공집합 → 무영향(벤치 불변). 재engagement에서 이 타깃에
    # trusted-FAIL로 입증된 무익 액션의 '시도'만 생략(=미실행이라 항상 더 안전).
    skip = _learned_skip(state, profile)
    state["_skipped_by_learning"] = []

    for i, (action, params, effect) in enumerate(pb["steps"]):
        nid = f"n{i}"
        tier = _base_tier(action)
        node = PTGNode(
            id=nid,
            task=f"{pb['scenario']}:{action}",
            technique=pb["technique"],
            action=action,
            scope_ok=gate.sysid_allowed(sysid),          # Engagement Gate 검증
            risk_tier=tier,                              # 계획시 잠정값 — 실행 직전 라이브 재분류(§2.5)
            reversibility=reversibility_of(tier),
            expected_effect=dict(effect),
            rollback_note="send RTL(20)" if tier != "read" else None,
        )
        node.preconditions = {"params": list(params)}
        state["ptg"][nid] = node
        # ★ 학습 배선: trusted-FAIL 무익 액션은 미시도(예산·노출 절감). recon 제외,
        #    proven은 절대 스킵 안 함(proven-wins). 게이트 불변 — 스킵은 '미실행'일 뿐.
        if action in skip and action != "recon_heartbeat":
            node.status = "skipped"
            node.findings.append("학습: 이 타깃에 trusted-FAIL(오라클 검증) 무익 → 미시도(예산·노출 절감)")
            state["_skipped_by_learning"].append(action)
            continue                                     # plan_queue 미적재 = 실행 안 함
        state["plan_queue"].append(nid)

    state["memory"].procedural.setdefault(abstract, {"utility": 0.0, "uses": 0})
    state["_expanded"] = True


def _learned_skip(state, profile) -> set:
    """학습이 '이 타깃에 무익'으로 입증한 스킵 대상 집합(안전 배선).

    skip = trusted-FAIL 회수(오라클 검증 실패) − proven_actions(proven-wins).
    빈 스토어면 공집합 → 단일 run 동작 불변. `recommend()`는 실패해도 공집합 반환.
    주의(설계 bound): 타깃이 hardened→vuln로 바뀌어도 target_id가 같으면 stale skip이
    남을 수 있어, 스킵은 리포트에 명시(감사·가역)하고 recon은 절대 스킵하지 않는다.
    """
    eg, tg = state.get("experience_gate"), state.get("target_gate")
    if not (eg and tg):
        state["_target_recommend"] = {}
        return set()
    try:
        from ..learning.fingerprint import resolve_target_id
        from ..learning.outcome import recommend
        tid, _ = resolve_target_id(profile)
        rec = recommend(tid, eg, tg)
        state["_target_recommend"] = rec
        return set(rec.get("skip_actions", [])) - set(rec.get("proven_actions", []))
    except Exception:
        state["_target_recommend"] = {}
        return set()


def _base_tier(action: str) -> str:
    from ..tools.mavlink import ATOMIC_ACTIONS
    return ATOMIC_ACTIONS.get(action, {"risk_tier": "physical_irreversible"})["risk_tier"]


def _diag(state) -> dict:
    """_expand_playbook가 in-place로 쓴 진단 키를 반환에 실어 LangGraph 채널로 흘린다.

    미반영 시 reflection(procedural 승격)·reporter·ablate가 stdlib에선 보이지만
    LangGraph에선 못 보는 러너 간 괴리가 생긴다(미선언·미반환 채널은 유실).
    """
    return {k: state.get(k) for k in (
        "_abstract_action", "_playbook_reused", "_skipped_by_learning", "_target_recommend")
        if k in state}


def planner(state) -> dict:
    if not state.get("_expanded"):
        _expand_playbook(state)

    if not state["plan_queue"]:
        return {"current_plan": None, "plan_queue": state["plan_queue"],
                "ptg": state["ptg"], "_expanded": state.get("_expanded", False),
                **_diag(state)}

    nid = state["plan_queue"][0]                          # peek (reflection이 pop)
    node = state["ptg"][nid]
    node.status = "in_progress"
    plan = {
        "node_id": nid,
        "action": node.action,
        "params": node.preconditions.get("params", []),
        "expected_effect": dict(node.expected_effect),
    }
    # 변경한 컨테이너(ptg/plan_queue/_expanded) + 진단 키를 모두 반환 → LangGraph 채널 반영
    return {"current_plan": plan, "ptg": state["ptg"], "plan_queue": state["plan_queue"],
            "_expanded": state.get("_expanded", False), **_diag(state)}
