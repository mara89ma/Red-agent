"""MITRE ATLAS 피드 — AI/ML 공격 기법(AML.T*).

LLM 계층 레드팀(B10) 커버리지 산정 근거. 라이브 소스가 YAML이면 stdlib만으로는
파싱 불가하므로(무의존 정책), JSON이 아닌 경우 조용히 시드로 폴백한다.
"""

from __future__ import annotations

import json

from .feed_base import FeedSnapshot, load_seed, log, sha256_bytes
from .feed_base import fetch_with_retry


class AtlasFeed:
    source = "atlas"
    # atlas-data는 주로 YAML로 배포됨 — JSON 미러가 없으면 라이브는 시드로 폴백.
    LIVE_URLS = (
        "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/atlas.json",
    )
    SEED_FILE = "atlas.json"

    def _seed(self) -> FeedSnapshot:
        recs = load_seed(self.SEED_FILE)
        digest = sha256_bytes(json.dumps(recs, sort_keys=True).encode())
        return FeedSnapshot(self.source, "seed", digest, recs)

    def _live(self) -> FeedSnapshot:
        raw = fetch_with_retry(self.LIVE_URLS[0])
        data = json.loads(raw.decode("utf-8"))          # YAML이면 여기서 실패 → 폴백
        recs = []
        for tech in data.get("techniques", []):
            tid = tech.get("id") or tech.get("object-id")
            if tid:
                recs.append({"id": tid, "name": tech.get("name", ""),
                             "tactics": tech.get("tactics", [])})
        if not recs:
            raise ValueError("ATLAS 파싱 결과 없음")
        return FeedSnapshot(self.source, "live", sha256_bytes(raw),
                            sorted(recs, key=lambda r: r["id"]))

    def fetch(self, offline: bool = True) -> FeedSnapshot:
        if offline:
            return self._seed()
        try:
            return self._live()
        except Exception as exc:
            log.warning("atlas 라이브 실패(%s) → 시드 폴백", exc)
            return self._seed()
