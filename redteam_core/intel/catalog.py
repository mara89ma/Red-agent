"""통합 기법 카탈로그 + 공격 커버리지 산정.

세 피드를 합쳐 ATT&CK-ICS/ATLAS 기법 카탈로그를 만들고, 에이전트의 '무기고'
(=mapping/attack_d3fend.py가 실행 가능한 기법 집합)가 카탈로그를 얼마나 커버하는지
계산한다. 방어측 coverage.py의 공격판 — 미커버 기법 = 능력 개발 우선순위.
"""

from __future__ import annotations

import argparse
import json

from ..mapping.attack_d3fend import MAP
from ..tools.ml_target import STAGED_ONLY_ACTIONS
from .attack_feed import AttackFeed
from .atlas_feed import AtlasFeed
from .kev_feed import KevFeed


def arsenal_techniques() -> set:
    """에이전트가 실제 실행 가능한 기법 ID 집합(원자 액션 매핑에서 도출)."""
    ids: set = set()
    for entry in MAP.values():
        ids.update(entry.get("attack_ics", []))
    return ids


def staged_techniques() -> set:
    """무기고엔 있으나 **런타임 미검증(스테이징 전용)** 기법 — 정직한 커버리지 표기용.

    스테이징 전용 액션(오프라인/공급망, 예: AML.T0020)은 '능력 게이트 도달'로만 실증되고
    런타임 오라클 검증이 없다. covered에 포함되되 이 집합으로 별도 표시한다.
    """
    ids: set = set()
    for action in STAGED_ONLY_ACTIONS:
        ids.update(MAP.get(action, {}).get("attack_ics", []))
    return ids


def build_catalog(offline: bool = True) -> dict:
    return {
        "attack": AttackFeed().fetch(offline),
        "atlas": AtlasFeed().fetch(offline),
        "kev": KevFeed().fetch(offline),
    }


def coverage(offline: bool = True, catalog: dict | None = None) -> dict:
    cat = catalog or build_catalog(offline)
    arsenal = arsenal_techniques()
    tech_records = cat["attack"].records + cat["atlas"].records
    catalog_ids = {r["id"] for r in tech_records}
    tactics_by_id = {r["id"]: (r.get("tactics") or []) for r in tech_records}

    covered = sorted(arsenal & catalog_ids)
    gaps = sorted(catalog_ids - arsenal)
    uncatalogued = sorted(arsenal - catalog_ids)      # 무기고엔 있으나 카탈로그에 없음
    staged = sorted(staged_techniques() & catalog_ids)   # covered지만 런타임 미검증
    runtime_verified = sorted(set(covered) - set(staged))

    gap_by_tactic: dict = {}
    for tid in gaps:
        for tac in (tactics_by_id.get(tid) or ["(none)"]):
            gap_by_tactic.setdefault(tac, []).append(tid)

    return {
        "sources": {k: {"via": v.fetched_via, "count": v.count, "sha256": v.sha256[:12]}
                    for k, v in cat.items()},
        "arsenal_size": len(arsenal),
        "catalog_size": len(catalog_ids),
        "covered": covered,
        "coverage_pct": round(len(covered) / len(catalog_ids), 3) if catalog_ids else 0.0,
        "runtime_verified": runtime_verified,          # 오라클 검증 가능(진짜 실행)
        "staged": staged,                              # 능력 도달만(런타임 미검증) — 정직 표기
        "runtime_coverage_pct": round(len(runtime_verified) / len(catalog_ids), 3)
        if catalog_ids else 0.0,
        "gaps": gaps,
        "gap_by_tactic": gap_by_tactic,
        "arsenal_uncatalogued": uncatalogued,
        "kev_intel_count": cat["kev"].count,
    }


def lookup(technique_id: str, offline: bool = True) -> dict | None:
    cat = build_catalog(offline)
    for r in cat["attack"].records + cat["atlas"].records:
        if r["id"] == technique_id:
            return r
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="공격 기법 커버리지 리포트")
    ap.add_argument("--live", action="store_true", help="라이브 피드 시도(실패 시 시드 폴백)")
    ap.add_argument("--json", action="store_true", help="JSON 출력")
    args = ap.parse_args()

    cov = coverage(offline=not args.live)
    if args.json:
        print(json.dumps(cov, ensure_ascii=False, indent=2))
        return

    print("=" * 66)
    print("공격 기법 커버리지 (ATT&CK-ICS + ATLAS)")
    print("=" * 66)
    for src, meta in cov["sources"].items():
        print(f"  {src:<10} via={meta['via']:<5} n={meta['count']:<4} sha={meta['sha256']}")
    print("-" * 66)
    print(f"무기고={cov['arsenal_size']}  카탈로그={cov['catalog_size']}  "
          f"커버리지={cov['coverage_pct'] * 100:.1f}% "
          f"(런타임검증 {cov['runtime_coverage_pct'] * 100:.1f}%)")
    print(f"커버={cov['covered']}")
    if cov["staged"]:
        print(f"스테이징(능력도달·런타임 미검증)={cov['staged']}")
    print("\n미커버(능력 개발 우선순위) — 전술별:")
    for tac, ids in sorted(cov["gap_by_tactic"].items()):
        print(f"  {tac:<26} {ids}")
    print(f"\nKEV 인텔 {cov['kev_intel_count']}건 로드됨")


if __name__ == "__main__":
    main()
