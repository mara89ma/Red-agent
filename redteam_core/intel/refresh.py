"""라이브 피드 갱신 CLI — 세 피드를 pull해 로컬 캐시에 기록(변경추적).

    python -m redteam_core.intel.refresh          # 라이브 pull → intel/cache/*.json

인가·네트워크 하에서만. 실패 시 각 피드는 시드로 폴백하며 그 사실을 로그로 남긴다.
sha256로 이전 스냅샷과 비교해 변경 여부를 알린다.
"""

from __future__ import annotations

import json
import os

from .attack_feed import AttackFeed
from .atlas_feed import AtlasFeed
from .feed_base import log
from .kev_feed import KevFeed

_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")


def refresh(offline: bool = False) -> dict:
    """모든 피드를 갱신하고 캐시에 기록. 이전 캐시와 sha256 비교로 변경 감지."""
    os.makedirs(_CACHE_DIR, exist_ok=True)
    summary = {}
    for feed in (AttackFeed(), AtlasFeed(), KevFeed()):
        snap = feed.fetch(offline=offline)
        path = os.path.join(_CACHE_DIR, f"{feed.source}.json")
        prev_sha = None
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    prev_sha = json.load(fh).get("sha256")
            except Exception:
                prev_sha = None
        changed = snap.sha256 != prev_sha
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"source": snap.source, "fetched_via": snap.fetched_via,
                       "sha256": snap.sha256, "records": snap.records},
                      fh, ensure_ascii=False, indent=2)
        summary[feed.source] = {"via": snap.fetched_via, "count": snap.count,
                                "changed": changed, "sha256": snap.sha256[:12]}
        log.info("피드 갱신 %s via=%s n=%d changed=%s",
                 snap.source, snap.fetched_via, snap.count, changed)
    return summary


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="TI 피드 갱신")
    ap.add_argument("--offline", action="store_true", help="시드만 사용(네트워크 미접속)")
    args = ap.parse_args()
    summary = refresh(offline=args.offline)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
