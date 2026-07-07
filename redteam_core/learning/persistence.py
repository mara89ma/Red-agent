"""학습 스토어 영속 백엔드 (2a) — JSON 파일 seam.

경험(B6)·타깃 프로파일(B7) 스토어는 Protocol 뒤에 있어(InMemory* 기본) 백엔드 스왑이
설계상 seam이었다. 여기서 그 seam을 실체화한다: 동일 Protocol을 구현하는 JSON 파일
백엔드 + 프로세스 간 자기개선을 잇는 게이트 팩토리.

서명은 스토어 밖(게이트의 Signer)에 있고 salt가 고정이라, 재적재해도 서명이 그대로
검증된다(변조 레코드는 읽기에서 걸러짐 — 영속화로도 오염 내성 유지). 순수 stdlib(json).
서명이 붙은 뒤에 직렬화하므로 파일에 저장된 값은 그대로 신뢰 검증 대상이 된다.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict

from .experience import (InMemoryExperienceStore, MemoryReadGate, MemoryWriteGate,
                         Sha256Signer, _Gates)
from .experience import ExperienceRecord
from .target_profile import Sha256Signer as TargetSigner
from .target_profile import TargetProfile, TargetProfileGate


def _atomic_write(path: str, payload) -> None:
    """임시파일 → rename으로 부분쓰기(크래시 시 손상) 방지."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class JsonExperienceStore:
    """ExperienceStore Protocol의 JSON 파일 구현 — all()/add()."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._recs: list = []
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            self._recs = []                              # 파일 자체 손상 → 빈 시작(오염 차단)
            return
        # 레코드 단위 복원 — 한 건이 스키마 불일치라도 나머지 누적 학습을 버리지 않는다.
        out = []
        for d in raw if isinstance(raw, list) else []:
            try:
                out.append(ExperienceRecord(**d))
            except TypeError:
                continue                                 # 개별 불량 레코드만 건너뜀
        self._recs = out

    def all(self) -> list:
        return list(self._recs)

    def add(self, record: ExperienceRecord) -> None:
        self._recs.append(record)
        _atomic_write(self._path, [asdict(r) for r in self._recs])


class JsonTargetStore:
    """TargetProfileStore Protocol의 JSON 파일 구현 — get()/put()."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._d: dict = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            self._d = {}                                 # 파일 자체 손상 → 빈 시작
            return
        out = {}
        for k, v in (raw.items() if isinstance(raw, dict) else []):
            try:
                out[k] = TargetProfile(**v)
            except TypeError:
                continue                                 # 개별 불량 프로파일만 건너뜀
        self._d = out

    def get(self, target_id: str):
        return self._d.get(target_id)

    def put(self, profile: TargetProfile) -> None:
        self._d[profile.target_id] = profile
        _atomic_write(self._path, {k: asdict(v) for k, v in self._d.items()})


def new_persistent_experience_gates(path: str) -> _Gates:
    """JSON 파일 백엔드 경험 게이트 쌍. 동일 path를 여러 프로세스/run에 주면 자기개선 영속."""
    store = JsonExperienceStore(path)
    signer = Sha256Signer(salt="redteam-exp-v1")         # InMemory 기본과 동일 salt(서명 호환)
    return _Gates(write=MemoryWriteGate(store, signer),
                  read=MemoryReadGate(store, signer), store=store)


def new_persistent_target_gate(path: str) -> TargetProfileGate:
    """JSON 파일 백엔드 타깃 프로파일 게이트."""
    return TargetProfileGate(JsonTargetStore(path), TargetSigner())
