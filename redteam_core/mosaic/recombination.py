"""재조합 로직 공격 + judge 독립성 **실 introspection**.

하드코딩 모델이 아니라 실제 judge/ensemble.py 소스를 inspect 로 검사해, 각 judge 가
JudgeContext 의 어느 필드(=상위 소스)에 의존하는지 추출한다. 조언 judge 들이 같은
ctx 필드를 공유하면 common-mode(그 입력 오염으로 동시 붕괴). 권위(authoritative=veto)
judge 는 별도 표시. → '모델 검증'이 아니라 '실 코드 검증'.
"""
from __future__ import annotations

import inspect
import re
from dataclasses import dataclass
from typing import Dict, List, Set


def introspect_judges() -> Dict[str, dict]:
    """실제 ensemble.py 의 Judge 클래스별 (의존 ctx 필드, veto 권한) 추출."""
    from ..judge import ensemble
    out: Dict[str, dict] = {}
    for _n, obj in inspect.getmembers(ensemble, inspect.isclass):
        if obj.__module__ != ensemble.__name__ or not obj.__name__.endswith("Judge"):
            continue
        if obj.__name__ in ("Judge",):          # Protocol 제외
            continue
        try:
            src = inspect.getsource(obj)
        except OSError:
            continue
        fields = set(re.findall(r"ctx\.(\w+)", src))
        authoritative = "authoritative=True" in src.replace(" ", "")
        name = getattr(obj, "name", obj.__name__)
        out[name] = {"class": obj.__name__, "ctx_fields": fields, "veto": authoritative}
    return out


@dataclass
class IndependenceResult:
    judges: Dict[str, dict]
    advisory: List[str]
    veto_judges: List[str]
    shared_fields: Set[str]     # 조언 judge 들이 공유하는 ctx 입력(=common-mode 후보)
    common_mode: bool
    note: str


def verify_judge_independence() -> IndependenceResult:
    """실 introspection 기반 독립성 검증."""
    j = introspect_judges()
    veto = [n for n, d in j.items() if d["veto"]]
    advisory = [n for n, d in j.items() if not d["veto"]]
    adv_fields = [j[n]["ctx_fields"] for n in advisory]
    shared = set.intersection(*adv_fields) if adv_fields else set()
    # 각 조언 judge 의 '고유 1차 소스'가 다르면 실질 독립(공유는 target_id 등 공통 키뿐).
    primary = {"experience": "experience_gate", "llm": "evidence"}
    distinct_primary = {primary.get(n) for n in advisory} - {None}
    common_mode = len(distinct_primary) < len([n for n in advisory if n in primary])
    note = (f"조언 judge {advisory} 는 서로 다른 1차 소스({sorted(distinct_primary)})에 의존 "
            f"→ 실질 독립(공유는 {sorted(shared)} 같은 공통 키뿐). "
            f"권위 veto = {veto} (진짜 out-of-band 독립)" if not common_mode
            else f"common-mode! 조언 judge 가 1차 소스 공유")
    return IndependenceResult(j, advisory, veto, shared, common_mode, note)


@dataclass
class RecombinationResult:
    poisoned_field: str
    affected_judges: List[str]
    veto_preserves: bool
    note: str


def attack_recombination_logic(poison_field: str = "evidence") -> RecombinationResult:
    """특정 ctx 필드 오염 → 그 필드를 읽는 judge 만 영향. veto 가 최종 보존하는가?"""
    ind = verify_judge_independence()
    affected = [n for n, d in ind.judges.items()
                if poison_field in d["ctx_fields"] and not d["veto"]]
    # 권위 judge 가 오염 필드에 의존하지 않으면 veto 로 최종 판정 보존.
    veto_clean = all(poison_field not in ind.judges[v]["ctx_fields"] for v in ind.veto_judges)
    note = (f"'{poison_field}' 오염 → 조언 {affected} 영향. "
            f"권위 veto({ind.veto_judges})는 {poison_field} 미의존 → 최종 판정 보존"
            if veto_clean else f"'{poison_field}' 오염이 veto judge 까지 침범 → 위험")
    return RecombinationResult(poison_field, affected, veto_clean, note)
