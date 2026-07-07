"""MITRE ATT&CK (Enterprise + ICS) 피드 — 원시 STIX 직접 pull.

mitreattack-python 같은 래퍼 의존 없이 mitre/cti 원시 STIX 번들에서 기법 ID·이름·
전술만 안전 추출한다(공급망 표면 최소화). 라이브 실패 시 오프라인 시드로 폴백.
"""

from __future__ import annotations

import json

from .feed_base import FeedSnapshot, load_seed, log, sha256_bytes
from .feed_base import fetch_with_retry


def parse_stix(bundle_bytes: bytes) -> list:
    """STIX 번들 → [{'id','name','tactics'}]. attack-pattern만, revoked/deprecated 제외."""
    data = json.loads(bundle_bytes.decode("utf-8"))
    out = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack"):
                tid = ref.get("external_id")
                break
        if not tid:
            continue
        tactics = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") in ("mitre-attack", "mitre-ics-attack")]
        out.append({"id": tid, "name": obj.get("name", ""), "tactics": tactics})
    return out


class AttackFeed:
    source = "attack-ics"
    LIVE_URLS = (
        "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    )
    SEED_FILE = "attack_ics.json"

    def _seed(self) -> FeedSnapshot:
        recs = load_seed(self.SEED_FILE)
        digest = sha256_bytes(json.dumps(recs, sort_keys=True).encode())
        return FeedSnapshot(self.source, "seed", digest, recs)

    def _live(self) -> FeedSnapshot:
        raw_all = b""
        merged: dict = {}
        for url in self.LIVE_URLS:
            raw = fetch_with_retry(url)
            raw_all += raw
            for rec in parse_stix(raw):
                merged[rec["id"]] = rec           # id 기준 dedup(enterprise∪ics)
        recs = sorted(merged.values(), key=lambda r: r["id"])
        return FeedSnapshot(self.source, "live", sha256_bytes(raw_all), recs)

    def fetch(self, offline: bool = True) -> FeedSnapshot:
        if offline:
            return self._seed()
        try:
            return self._live()
        except Exception as exc:
            log.warning("attack-ics 라이브 실패(%s) → 시드 폴백", exc)
            return self._seed()
