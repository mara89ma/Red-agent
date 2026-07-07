"""CISA KEV 피드 — 알려진 악용 CVE. 표적 스택 계획·초기접근 우선순위 근거.

라이브는 CISA의 공식 JSON. 실패 시 오프라인 시드로 폴백.
"""

from __future__ import annotations

import json

from .feed_base import FeedSnapshot, load_seed, log, sha256_bytes
from .feed_base import fetch_with_retry


class KevFeed:
    source = "cisa-kev"
    LIVE_URLS = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    SEED_FILE = "kev.json"

    def _seed(self) -> FeedSnapshot:
        recs = load_seed(self.SEED_FILE)
        digest = sha256_bytes(json.dumps(recs, sort_keys=True).encode())
        return FeedSnapshot(self.source, "seed", digest, recs)

    def _live(self) -> FeedSnapshot:
        raw = fetch_with_retry(self.LIVE_URLS[0])
        data = json.loads(raw.decode("utf-8"))
        recs = [{"cve": v.get("cveID"), "vendor": v.get("vendorProject"),
                 "product": v.get("product"), "name": v.get("vulnerabilityName")}
                for v in data.get("vulnerabilities", []) if v.get("cveID")]
        if not recs:
            raise ValueError("KEV 파싱 결과 없음")
        return FeedSnapshot(self.source, "live", sha256_bytes(raw), recs)

    def fetch(self, offline: bool = True) -> FeedSnapshot:
        if offline:
            return self._seed()
        try:
            return self._live()
        except Exception as exc:
            log.warning("cisa-kev 라이브 실패(%s) → 시드 폴백", exc)
            return self._seed()
