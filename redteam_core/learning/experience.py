"""경험 메모리 (B6) — 게이트·서명·dedup + 비대칭 신뢰.

pollack `core/experience.py`의 공격판. "어떤 (target, technique, action)이 통했나"를
학습한다. 오염 방지 정책은 **단일 쓰기 게이트**가 강제:
    • INCONCLUSIVE(게이트 도달 등 효과 미확정)는 버린다,
    • **suppression 학습**(FAIL로 향후 시도를 건너뛰는 위험 방향)은 **신뢰 provenance**
      (out-of-band validator/human)만 허용 — 오탐 억제로 놓치는 사고 방지,
    • fingerprint로 dedup(같은 경험 재관측 시 중복 저장 안 함),
    • 각 레코드 서명(SHA-256; HMAC은 seam).

읽기 게이트는 서명 재검증 + 비대칭 신뢰: "무엇이 통했나"(안전 방향) 회수는 아무
provenance나 허용, "무엇을 건너뛸까"(위험 방향) 회수는 신뢰 provenance만.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .target_profile import Sha256Signer, Signer

CONFIRMED_SUCCESS = "CONFIRMED_SUCCESS"
CONFIRMED_FAIL = "CONFIRMED_FAIL"
INCONCLUSIVE = "INCONCLUSIVE"

TRUSTED_PROVENANCE = {"validator", "human"}     # out-of-band ground truth


@dataclass
class ExperienceRecord:
    target_id: str
    technique: str
    action: str
    verdict: str
    effect: float = 0.0
    provenance: str = "validator"
    signature: str = ""

    def fingerprint(self) -> str:
        """의미 동일성 해시 — timestamp/provenance/effect/signature 제외(재관측 dedup)."""
        basis = f"{self.target_id}|{self.technique}|{self.action}|{self.verdict}"
        return hashlib.sha256(basis.encode()).hexdigest()


class ExperienceStore(Protocol):
    def all(self) -> list: ...
    def add(self, record: ExperienceRecord) -> None: ...


class InMemoryExperienceStore:
    def __init__(self) -> None:
        self._recs: list = []

    def all(self) -> list:
        return list(self._recs)

    def add(self, record: ExperienceRecord) -> None:
        self._recs.append(record)


class MemoryWriteGate:
    """유일한 영속 경로 — 오염 방지 정책 강제."""

    def __init__(self, store: ExperienceStore, signer: Signer) -> None:
        self._store = store
        self._signer = signer

    def write(self, record: ExperienceRecord) -> bool:
        if record.verdict == INCONCLUSIVE:
            return False                                     # 효과 미확정 → 버림
        if record.verdict == CONFIRMED_FAIL and record.provenance not in TRUSTED_PROVENANCE:
            return False                                     # suppression은 신뢰 provenance만
        fp = record.fingerprint()
        if any(r.fingerprint() == fp for r in self._store.all()):
            return False                                     # dedup
        record.signature = self._signer.sign(fp)
        self._store.add(record)
        return True


class MemoryReadGate:
    """서명 재검증 + 비대칭 신뢰 회수."""

    def __init__(self, store: ExperienceStore, signer: Signer) -> None:
        self._store = store
        self._signer = signer

    def _valid(self, r: ExperienceRecord) -> bool:
        return self._signer.verify(r.fingerprint(), r.signature)

    def recall(self, target_id: str, want: str = "success") -> list:
        """want='success'(안전): 통한 것 회수(아무 provenance). want='failure'(위험):
        건너뛸 것 회수(신뢰 provenance만)."""
        target_verdict = CONFIRMED_SUCCESS if want == "success" else CONFIRMED_FAIL
        out = []
        for r in self._store.all():
            if r.target_id != target_id or r.verdict != target_verdict:
                continue
            if not self._valid(r):
                continue                                     # 서명 불일치 → 무시(변조)
            if want == "failure" and r.provenance not in TRUSTED_PROVENANCE:
                continue                                     # 위험 방향 신뢰 강제
            out.append(r)
        return out


@dataclass
class _Gates:
    write: MemoryWriteGate
    read: MemoryReadGate
    store: ExperienceStore = field(default=None)  # type: ignore


def new_experience_gates() -> _Gates:
    """기본(인메모리) 경험 쓰기/읽기 게이트 쌍. 스토어 공유는 영속 seam."""
    store = InMemoryExperienceStore()
    signer = Sha256Signer(salt="redteam-exp-v1")
    return _Gates(write=MemoryWriteGate(store, signer),
                  read=MemoryReadGate(store, signer), store=store)
