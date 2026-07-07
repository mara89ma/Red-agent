"""위협 인텔 피드 (B9) — 정적 매핑을 라이브 카탈로그로.

방어측 pollack-ai `tools/feed_base.py` + STIX/ATLAS/KEV 어댑터 패턴을 공격측으로
이식. 목적: 기법 선택·**공격 커버리지** 산정을 위한 ATT&CK-ICS/ATLAS 카탈로그와
CISA KEV(CVE) 인텔.

원칙(방어측과 동일):
    • HTTPS-only + 지수 백오프 재시도 + SHA-256 변경추적,
    • 원시 STIX 직접 pull(공급망 표면 최소화 — mitreattack-python 미사용),
    • **오프라인 시드 폴백** — 네트워크 없이도 결정론 동작(Tier 0 무의존, stdlib urllib만).
"""

from .feed_base import FeedSnapshot, FeedTool, fetch_with_retry, load_seed  # noqa: F401
