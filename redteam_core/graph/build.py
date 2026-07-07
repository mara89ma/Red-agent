"""(graph) StateGraph 와이어링 + 조건부 엣지 (§2.5).

게이트는 **전개된 원자 노드마다·실행 직전·라이브 상태로** 재분류한다(§1.6·C1/C2).
route_to_hitl은 SOC의 Approval 게이트와 동형 — 판정·승인 권한을 결정론 규칙에
두고 LLM에 안 준다. 단 UAV는 물리 비가역성 때문에 ①라이브 재분류 ②TOCTOU
fail-closed ③토큰 강제의 3중 방어를 추가한다.

langgraph가 설치돼 있으면 StateGraph로 컴파일하고, 없으면 동일 라우팅을 순수
stdlib 러너(RedTeamGraph)로 실행한다 — 데모가 의존성 없이 돈다.
"""

from __future__ import annotations

from ..logging_util import get_logger
from ..nodes.recon import recon
from ..nodes.planner import planner
from ..nodes.synthesizer import synthesizer
from ..nodes.checker import checker
from ..nodes.broker import broker
from ..nodes.executor import executor
from ..nodes.summarizer import summarizer
from ..nodes.validator import validator
from ..nodes.reflection import reflection, route_after_reflection
from ..nodes.reporter import reporter
from ..safety.hitl_gate import hitl_gate, hitl_gate_interrupt
from ..safety.reversibility import classify
from ..tools.sitl_stub import independent_oracle

log = get_logger("graph")


# --- 조건부 엣지 판정 함수 (결정론) ---------------------------------------
def route_after_checker(state) -> str:
    return "ok" if state.get("checker_verdict") == "ok" else "violation"


def route_to_hitl(state) -> str:
    node = state["ptg"][state["current_plan"]["node_id"]]     # 전개된 *원자* 노드
    # ① 캐시 금지 — 실행 tick에 독립 오라클로 라이브 물리상태 재취득
    live = independent_oracle(state).snapshot()               # {armed, in_flight, alt}
    tier, gate = classify(live, node.action)                  # §1.7 결정 테이블 재실행
    # ② TOCTOU: 계획 분류와 라이브 분류가 다르면 fail-closed(라이브로 갱신)
    if tier != node.risk_tier:
        state["audit_log"].append({"event": "toctou_reclassify", "node": node.id,
                                   "planned": node.risk_tier, "live": tier})
        node.risk_tier = tier
        from ..safety.reversibility import reversibility_of
        node.reversibility = reversibility_of(tier)
    # ③ 예산 소진 → 승인 경유 정지
    if state["gate"].budget_exhausted():
        return "needs_approval"
    needs = (gate in ("hitl", "human_only")
             or tier in ("write_highrisk", "physical_irreversible")
             or node.reversibility == "irreversible")
    return "needs_approval" if needs else "auto"


def route_after_hitl(state) -> str:
    return "approved" if state.get("_hitl_decision") == "approved" else "denied"


# --- 순수 stdlib 러너 (langgraph 미설치 시) --------------------------------
class RedTeamGraph:
    """LangGraph StateGraph와 동일한 노드·엣지를 결정론적으로 실행."""

    def invoke(self, state, max_ticks: int = 50) -> dict:
        _merge(state, recon(state))                          # START → recon

        ticks = 0
        while ticks < max_ticks:
            ticks += 1
            _merge(state, planner(state))
            if state.get("current_plan") is None:
                state["stop_reason"] = state.get("stop_reason") or "plan_exhausted"
                break

            _merge(state, synthesizer(state))
            _merge(state, checker(state))

            if route_after_checker(state) == "violation":
                _merge(state, reflection(state))             # 위반 → 실행 생략
            else:
                _merge(state, broker(state))
                if route_to_hitl(state) == "needs_approval":
                    _merge(state, hitl_gate(state))
                    if route_after_hitl(state) == "approved":
                        _merge(state, executor(state))
                        _merge(state, summarizer(state))
                        _merge(state, validator(state))
                        _merge(state, reflection(state))
                    else:  # denied → 실행 생략(안전)
                        _merge(state, reflection(state))
                else:  # auto
                    _merge(state, executor(state))
                    _merge(state, summarizer(state))
                    _merge(state, validator(state))
                    _merge(state, reflection(state))

            nxt = route_after_reflection(state)
            if nxt == "stop":
                break
            if nxt == "rescan":
                _merge(state, recon(state))

        _merge(state, reporter(state))                       # → reporter → END
        return state


def _merge(state, delta) -> None:
    if delta:
        state.update(delta)


def build_graph(use_langgraph: bool = True):
    """기본 = LangGraph(interrupt HITL + 체크포인트). 미설치/오류 시 stdlib 러너로 강등.

    langgraph가 있으면 실제 StateGraph를 컴파일하고, 없으면 동일 라우팅의 순수 stdlib
    러너(RedTeamGraph)로 우아하게 폴백 → 무의존성 실행 보장.
    """
    if use_langgraph:
        try:
            return _build_langgraph()
        except Exception as exc:  # langgraph 미설치/버전 불일치 등
            log.info("LangGraph 미사용(%s: %s) → stdlib 러너로 강등",
                     type(exc).__name__, exc)
    return RedTeamGraph()


class _InProcessSerde:
    """식별자 보존 in-process serde — 체크포인트에 '직렬화 대신 객체 참조'를 저장한다.

    이유: 상태에 라이브 객체(Gate 토큰 상태·Range의 실 SITL 소켓·TypedMemory·콜백)가
    흐른다. 라이브 소켓은 본질적으로 msgpack 직렬화 불가. LangGraphRunner는 단일 프로세스
    구동이므로 참조로 넘기면 in-place 변형·객체 식별성이 그대로 보존된다.

    한계: 프로세스 재시작을 넘는 durable resume는 지원 안 함(그때는 서비스들을 config로
    재주입하고 소켓을 재연결해야 함 — 실 운용 확장 지점).
    """

    def __init__(self):
        self._store: dict = {}

    def dumps(self, obj) -> bytes:
        key = str(id(obj))
        self._store[key] = obj
        return key.encode()

    def loads(self, data: bytes):
        return self._store[data.decode()]

    def dumps_typed(self, obj):
        key = str(id(obj))
        self._store[key] = obj
        return ("obj", key.encode())

    def loads_typed(self, data):
        _, b = data
        return self._store[b.decode()]


class LangGraphRunner:
    """컴파일된 StateGraph를 감싸 interrupt 재개 루프를 자동 구동.

    run.py는 `.invoke(state)`만 호출하면 된다 — HITL interrupt가 뜨면 state['approver']로
    결정을 받아 `Command(resume=...)`로 그래프를 재개한다(실 운용은 이 자리에 UI/API).
    """

    def __init__(self, compiled):
        self._g = compiled

    def invoke(self, state, max_interrupts: int = 64):
        from langgraph.types import Command

        approver = state.get("approver") or (lambda ctx: "denied")
        name = str(state.get("profile", {}).get("engagement", {}).get("name", "redteam"))
        thread = f"{name}-{id(state)}"          # invoke마다 고유(체크포인터 스레드 충돌 방지)
        config = {"configurable": {"thread_id": thread}, "recursion_limit": 200}

        result = self._g.invoke(state, config=config)
        guard = 0
        while result.get("__interrupt__") and guard < max_interrupts:
            guard += 1
            payload = result["__interrupt__"][0].value       # hitl_gate_interrupt의 _hitl_context
            decision = approver(payload)                      # 운용자 승인(데모: 콜백)
            result = self._g.invoke(Command(resume=decision), config=config)
        return result


def _build_langgraph():
    from langgraph.graph import StateGraph, START, END  # type: ignore
    from langgraph.checkpoint.memory import MemorySaver  # type: ignore
    from .state import RTState

    g = StateGraph(RTState)
    for name, fn in [("recon", recon), ("planner", planner), ("synth", synthesizer),
                     ("checker", checker), ("broker", broker),
                     ("hitl", hitl_gate_interrupt),          # ★ interrupt 기반 HITL
                     ("executor", executor), ("summarizer", summarizer),
                     ("validator", validator), ("reflection", reflection),
                     ("reporter", reporter)]:
        g.add_node(name, fn)

    g.add_edge(START, "recon")
    g.add_edge("recon", "planner")
    g.add_edge("planner", "synth")
    g.add_edge("synth", "checker")
    g.add_conditional_edges("checker", route_after_checker,
                            {"ok": "broker", "violation": "reflection"})
    g.add_conditional_edges("broker", route_to_hitl,
                            {"needs_approval": "hitl", "auto": "executor"})
    g.add_conditional_edges("hitl", route_after_hitl,
                            {"approved": "executor", "denied": "reflection"})
    g.add_edge("executor", "summarizer")
    g.add_edge("summarizer", "validator")
    g.add_edge("validator", "reflection")
    g.add_conditional_edges("reflection", route_after_reflection,
                            {"continue": "planner", "rescan": "recon", "stop": "reporter"})
    g.add_edge("reporter", END)
    # interrupt에는 체크포인터가 필수. 라이브 객체 보존을 위해 in-process serde 사용.
    return LangGraphRunner(g.compile(checkpointer=MemorySaver(serde=_InProcessSerde())))
