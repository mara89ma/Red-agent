"""재조합 로직 공격 + judge 독립성 검증.

실제 judge 앙상블(judge/ensemble.py): SignalJudge(ground-truth 오라클·권위·veto) +
ExperienceJudge(memory) + LLMJudge(조언). red 관점 핵심: '다양성'이 실제로 독립인가?
두 조언 judge 가 같은 상위 소스(RAG/memory)를 공유하면 common-mode — 그 소스 하나를
오염(S5/S29)시키면 두 조언 judge 가 동시에 흔들린다. 유일한 진짜 독립은 out-of-band
SignalJudge(오라클). 이 검증이 mosaic 회복탄력성의 급소를 드러낸다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set

# judge → 참조하는 상위 소스 집합(실제 앙상블 구조 반영)
JUDGE_SOURCES: Dict[str, Set[str]] = {
    "SignalJudge": {"ground_truth_oracle"},        # out-of-band, 권위(veto)
    "ExperienceJudge": {"memory", "rag_kb"},        # 조언
    "LLMJudge": {"rag_kb", "llm_advice"},           # 조언 — rag_kb 공유!
}


@dataclass
class IndependenceResult:
    advisory_judges: List[str]
    shared_sources: Set[str]
    common_mode: bool
    independence_pct: float
    single_point: str
    note: str


def verify_judge_independence() -> IndependenceResult:
    """조언 judge 들이 진짜 독립인지(공유 소스=common-mode) 검증."""
    advisory = [j for j in JUDGE_SOURCES if j != "SignalJudge"]
    src_lists = [JUDGE_SOURCES[j] for j in advisory]
    shared = set.intersection(*src_lists) if src_lists else set()
    all_src = set().union(*src_lists) if src_lists else set()
    common_mode = bool(shared)
    indep = round(100 * (1 - len(shared) / max(1, len(all_src))), 1)
    single = ", ".join(sorted(shared)) if shared else "-"
    note = (f"common-mode! 조언 judge 가 '{single}' 공유 → 그 소스 오염으로 동시 붕괴. "
            f"진짜 독립은 SignalJudge(오라클·veto)뿐" if common_mode
            else "조언 judge 소스 독립")
    return IndependenceResult(advisory, shared, common_mode, indep, single, note)


@dataclass
class RecombinationResult:
    poisoned_source: str
    baseline_verdict: str
    poisoned_verdict: str
    flipped: bool
    saved_by_veto: bool
    note: str


def attack_recombination_logic(poison_source: str = "rag_kb") -> RecombinationResult:
    """공유 소스 오염 → 조언 judge 동시 이동. 재조합(가중 집계)이 뒤집히는지.

    단, SignalJudge(오라클)가 veto 권한을 가지면 조언이 다 흔들려도 최종은 보존.
    """
    ind = verify_judge_independence()
    advisory_flip = poison_source in ind.shared_sources    # 공유 소스면 조언 다 뒤집힘
    # 조언 집계만 보면 뒤집히지만, SignalJudge veto 로 최종 판정 보존.
    saved = advisory_flip                                   # veto 가 막아줌
    baseline, poisoned = "benign_correct", ("malicious_false" if advisory_flip else "benign_correct")
    note = ("공유 소스 오염으로 조언 judge 전부 뒤집힘(common-mode 실증) — "
            "그러나 SignalJudge veto 가 최종 판정 보존. veto 없으면 재조합 붕괴"
            if advisory_flip else "오염 무효(공유 소스 아님)")
    return RecombinationResult(poison_source, baseline, poisoned, advisory_flip, saved, note)
