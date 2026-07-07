"""per-target 프로파일 (B7) — merge-accumulate + playbook 효과 점수, 서명.

pollack `core/actors.py`/`playbook_outcome.py`의 공격판(역전). 타깃별로 관측 방어,
시도 기법, kill_chain(슬라이딩 윈도우 캡), 그리고 **pb_scores**(액션/playbook별
러닝 평균 효과)를 누적한다. 쓰기·읽기 모두 서명 검증(변조 방지).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Optional, Protocol

_KILL_CHAIN_CAP = 20


class Signer(Protocol):
    def sign(self, payload: str) -> str: ...
    def verify(self, payload: str, signature: str) -> bool: ...


class Sha256Signer:
    """데모 서명(무결성). 실배포는 HMAC/서명키로 교체(seam)."""

    def __init__(self, salt: str = "redteam-target-v1") -> None:
        self._salt = salt

    def sign(self, payload: str) -> str:
        return hashlib.sha256((self._salt + payload).encode()).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        return self.sign(payload) == signature


@dataclass
class TargetProfile:
    target_id: str
    observed_defenses: dict = field(default_factory=dict)
    techniques_attempted: list = field(default_factory=list)
    kill_chain: list = field(default_factory=list)
    pb_scores: dict = field(default_factory=dict)      # action -> {avg_effect, n}
    signature: str = ""

    def _signable(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "signature"}
        return json.dumps(body, sort_keys=True, ensure_ascii=False)


class TargetProfileStore(Protocol):
    def get(self, target_id: str) -> Optional[TargetProfile]: ...
    def put(self, profile: TargetProfile) -> None: ...


class InMemoryTargetStore:
    def __init__(self) -> None:
        self._d: dict = {}

    def get(self, target_id: str) -> Optional[TargetProfile]:
        return self._d.get(target_id)

    def put(self, profile: TargetProfile) -> None:
        self._d[profile.target_id] = profile


class TargetProfileGate:
    """유일한 쓰기 경로 — merge-accumulate + 서명. 읽기는 서명 검증."""

    def __init__(self, store: TargetProfileStore, signer: Signer) -> None:
        self._store = store
        self._signer = signer

    def _load_or_new(self, target_id: str) -> TargetProfile:
        p = self._store.get(target_id)
        if p is None:
            return TargetProfile(target_id=target_id)
        if not self._signer.verify(p._signable(), p.signature):
            # 변조 의심 → 새 프로파일로 시작(오염 전파 차단)
            return TargetProfile(target_id=target_id)
        return p

    def _commit(self, p: TargetProfile) -> None:
        p.signature = self._signer.sign(p._signable())
        self._store.put(p)

    def observe_defenses(self, target_id: str, defenses: dict) -> None:
        p = self._load_or_new(target_id)
        p.observed_defenses.update({k: v for k, v in defenses.items() if v is not None})
        self._commit(p)

    def record_attempt(self, target_id: str, action: str, technique: str,
                       effect: float) -> None:
        """액션 시도를 반영 — pb_scores 러닝 평균 + kill_chain + 기법 집합."""
        p = self._load_or_new(target_id)
        if technique and technique not in p.techniques_attempted:
            p.techniques_attempted.append(technique)
        p.kill_chain.append(action)
        if len(p.kill_chain) > _KILL_CHAIN_CAP:
            p.kill_chain = p.kill_chain[-_KILL_CHAIN_CAP:]
        sc = p.pb_scores.setdefault(action, {"avg_effect": 0.0, "n": 0})
        n = sc["n"]
        sc["avg_effect"] = (sc["avg_effect"] * n + effect) / (n + 1)
        sc["n"] = n + 1
        self._commit(p)

    def get(self, target_id: str) -> Optional[TargetProfile]:
        p = self._store.get(target_id)
        if p is None:
            return None
        return p if self._signer.verify(p._signable(), p.signature) else None


def new_target_gate() -> TargetProfileGate:
    """기본(인메모리) 타깃 게이트. 영속 백엔드는 store를 교체(seam)."""
    return TargetProfileGate(InMemoryTargetStore(), Sha256Signer())
