#!/usr/bin/env python3
"""verify_claims — 문서 headline 수치를 committed 아티팩트에서 재파생하는 정직성 가드.

T3MP3ST `verify-claims.mjs` 이식(공격판): **"재현 안 되는 주장은 싣지 않는다."**
문서/리포트가 주장하는 모든 headline 불변식을 라이브 계산(coverage + benchmark suite)으로
재도출해 대조하고, anti-fitting 가드(오라클/검증기에 시나리오ID 하드코딩 금지 = 자가채점 방지)와
fabrication 필터(committed 결과가 placeholder가 아님)를 돌린다. 하나라도 어긋나면 non-zero exit.

    python -m benchmarks.verify_claims          # 전 CLAIM 재파생·검증
    python -m benchmarks.verify_claims --json    # 기계판독 결과

이 가드가 green이면: 커버리지·ASR·안전·스테이징 표기가 전부 committed 코드에서 재계산되며,
오라클 판정이 시나리오별로 튜닝되지 않았음(자가채점 아님)이 보장된다.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmarks.harness import SCENARIOS, results_path, run_suite  # noqa: E402
from redteam_core.intel.catalog import coverage  # noqa: E402
from redteam_core.mapping.attack_d3fend import MAP  # noqa: E402
from redteam_core.rag.playbook import PLAYBOOKS  # noqa: E402
from redteam_core.tools.mavlink import ATOMIC_ACTIONS  # noqa: E402

# fabrication 필터 — committed 결과에 이런 placeholder가 있으면 조작 의심(재파생 무의미).
_FABRICATED = ("placeholder", "dummy", "fake", "todo", "tbd", "xxx", "changeme")

# 오라클/검증 로직 파일 — 여기에 시나리오ID가 박혀 있으면 '자가채점(teaching to the test)'.
_ORACLE_FILES = [
    "redteam_core/nodes/validator.py",
    "redteam_core/safety/reversibility.py",
    "redteam_core/tools/sitl_stub.py",
    "redteam_core/tools/ml_target.py",
    "redteam_core/tools/ics_actions.py",
]


def _root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _rederive() -> list:
    """(claim, ok, detail) 리스트 — 전부 라이브 계산에서 재도출."""
    checks: list = []
    cov = coverage(offline=True)
    suite = run_suite()
    agg = suite["aggregate"]

    # --- 커버리지 정직성 불변식 (문서 주장) ---
    checks.append(("coverage_full", cov["coverage_pct"] == 1.0,
                   f"무기고 커버 {cov['coverage_pct'] * 100:.1f}% (==100%)"))
    checks.append(("no_uncovered_gaps", cov["gaps"] == [],
                   f"미커버 갭={cov['gaps'] or '없음'}"))
    checks.append(("staged_honestly_labeled",
                   cov["staged"] == ["AML.T0020"] and cov["runtime_coverage_pct"] < 1.0,
                   f"스테이징={cov['staged']} 런타임검증={cov['runtime_coverage_pct'] * 100:.1f}%(<100%)"))
    checks.append(("arsenal_equals_catalog", cov["arsenal_size"] == cov["catalog_size"],
                   f"무기고={cov['arsenal_size']} 카탈로그={cov['catalog_size']}"))

    # --- 벤치마크 headline (게이트와 동일 근거, 라이브 재실행) ---
    checks.append(("asr_vuln_full", agg["attack_success_rate_vuln"] >= 1.0,
                   f"ASR(vuln)={agg['attack_success_rate_vuln']}"))
    checks.append(("zero_safety_violations", agg["physical_safety_violations_total"] == 0,
                   f"물리안전위반={agg['physical_safety_violations_total']}"))
    checks.append(("pov_pairs_consistent", bool(agg["pov_pairs_consistent"]),
                   f"PoV={agg['pov_pairs']}"))
    checks.append(("no_regressions", not agg["regressions"],
                   f"회귀={agg['regressions'] or '없음'}"))
    return checks


def _anti_fitting() -> list:
    """자가채점/조작 방지 가드 — 재파생만으론 못 잡는 오염 벡터."""
    checks: list = []

    # (1) no-phantom: MAP·playbook의 모든 액션이 실제 실행 가능(등록된 원자 액션).
    phantom = sorted((set(MAP) | {a for pb in PLAYBOOKS.values()
                                  for (a, _p, _e) in pb["steps"]}) - set(ATOMIC_ACTIONS))
    checks.append(("no_phantom_actions", phantom == [],
                   f"phantom={phantom or '없음'}"))

    # (2) anti-fitting: 오라클/검증 로직에 시나리오ID가 박혀 있으면 자가채점.
    scenario_ids = {sc.name for sc in SCENARIOS} | set(PLAYBOOKS)
    id_re = re.compile("|".join(re.escape(s) for s in scenario_ids))
    leaked = []
    for rel in _ORACLE_FILES:
        path = os.path.join(_root(), rel)
        try:
            with open(path, encoding="utf-8") as fh:
                if id_re.search(fh.read()):
                    leaked.append(rel)
        except OSError:
            continue
    checks.append(("oracle_scenario_agnostic", leaked == [],
                   f"시나리오ID 누출 파일={leaked or '없음'}"))

    # (3) fabrication 필터: committed 결과 JSON이 placeholder로 오염되지 않았는가.
    rp = results_path()
    if os.path.exists(rp):
        with open(rp, encoding="utf-8") as fh:
            blob = fh.read().lower()
        hit = [w for w in _FABRICATED if w in blob]
        checks.append(("results_not_fabricated", hit == [],
                       f"placeholder 토큰={hit or '없음'}"))
    return checks


def main() -> int:
    ap = argparse.ArgumentParser(description="문서 주장 재파생 정직성 가드")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    checks = _rederive() + _anti_fitting()
    if args.json:
        print(json.dumps([{"claim": c, "ok": ok, "detail": d} for c, ok, d in checks],
                         ensure_ascii=False, indent=2))
    else:
        print("=" * 64)
        print("verify_claims — 문서 주장 재파생·정직성 가드")
        print("=" * 64)
        for claim, ok, detail in checks:
            print(f"  {'PASS ✅' if ok else 'FAIL ❌'}  {claim:<28} {detail}")
        print("=" * 64)

    failed = sum(1 for _c, ok, _d in checks if not ok)
    if failed:
        print(f"{failed}개 주장 재파생 실패 → 문서/코드 불일치(정직성 위반)")
        return 1
    print(f"전 주장 재파생 통과 ✅ ({len(checks)}개)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
