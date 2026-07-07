"""피드 기반 계약 — Protocol + 공용 fetch(HTTPS-only·백오프·SHA-256) + 시드 로더.

네트워크는 stdlib `urllib`만 쓴다(Tier 0 무의존). 서드파티 HTTP 클라이언트·STIX
파서 의존을 두지 않는다 — 공격 툴은 린하고 신뢰 가능해야 한다.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from ..logging_util import get_logger

log = get_logger("intel")

_SEED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")


@dataclass
class FeedSnapshot:
    """정규화된 피드 스냅샷 — 변경추적용 sha256 포함."""
    source: str                     # "attack-ics" | "atlas" | "cisa-kev"
    fetched_via: str                # "seed" | "live"
    sha256: str
    records: list = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.records)


@runtime_checkable
class FeedTool(Protocol):
    """모든 피드 어댑터의 계약. 오프라인이 기본(결정론)."""
    source: str

    def fetch(self, offline: bool = True) -> FeedSnapshot:
        ...


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_with_retry(url: str, attempts: int = 3, backoff_s: float = 0.5,
                     timeout_s: float = 15.0) -> bytes:
    """HTTPS-only GET. 5xx/네트워크 오류에 지수 백오프 재시도. 실패 시 예외.

    HTTP(비-TLS)는 거부한다(중간자·무결성). 호출측이 예외를 잡아 시드로 폴백한다.
    """
    if not url.lower().startswith("https://"):
        raise ValueError(f"HTTPS-only 정책 위반: {url!r}")
    last_exc: Optional[Exception] = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "redteam-intel/1.0"})
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 (https 강제)
                return resp.read()
        except Exception as exc:  # urllib.error.HTTPError/URLError 등
            last_exc = exc
            if i < attempts - 1:
                time.sleep(backoff_s * (2 ** i))
    raise RuntimeError(f"fetch 실패({url}): {last_exc}")


def load_seed(filename: str) -> list:
    """오프라인 시드 JSON을 로드. 네트워크 없이 결정론 동작을 보장."""
    path = os.path.join(_SEED_DIR, filename)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
