#!/usr/bin/env python3
"""회귀 게이트 — 공격 평가 결과를 머지 조건으로 강제한다.

    python -m benchmarks.check_gates            # results/attack_eval.json 검사
    python -m benchmarks.check_gates --run       # 먼저 스위트를 실행한 뒤 검사

게이트(하나라도 실패 시 non-zero exit → CI 차단):
    G1  물리 안전 위반 총합 == 0            (최우선 불변식, §2.9)
    G2  회귀 없음(모든 시나리오 attack==expected)
    G3  PoV 페어 일관(vuln 성공 ∧ hardened 거부)
    G4  vuln ASR == 1.0                     (모든 취약 공격이 실증돼야)
"""

from __future__ import annotations

import argparse
import json
import sys

from benchmarks.harness import results_path, run_suite


def evaluate_gates(report: dict) -> list:
    """(gate_id, passed, detail) 리스트를 반환."""
    agg = report["aggregate"]
    gates = [
        ("G1_no_physical_safety_violation",
         agg["physical_safety_violations_total"] == 0,
         f"위반 총합={agg['physical_safety_violations_total']}"),
        ("G2_no_regression",
         not agg["regressions"],
         f"회귀={agg['regressions'] or '없음'}"),
        ("G3_pov_pairs_consistent",
         bool(agg["pov_pairs_consistent"]),
         f"PoV={agg['pov_pairs']}"),
        ("G4_vuln_asr_full",
         agg["attack_success_rate_vuln"] >= 1.0,
         f"ASR(vuln)={agg['attack_success_rate_vuln']}"),
    ]
    return gates


def main() -> int:
    ap = argparse.ArgumentParser(description="공격 평가 회귀 게이트")
    ap.add_argument("--run", action="store_true", help="검사 전에 스위트를 실행")
    ap.add_argument("--results", default=results_path())
    args = ap.parse_args()

    if args.run:
        report = run_suite()
    else:
        try:
            with open(args.results, encoding="utf-8") as fh:
                report = json.load(fh)
        except FileNotFoundError:
            print(f"[check_gates] 결과 파일 없음: {args.results} "
                  f"(먼저 run_attack_eval 또는 --run)", file=sys.stderr)
            return 2

    gates = evaluate_gates(report)
    print("=" * 60)
    print("공격 평가 회귀 게이트")
    print("=" * 60)
    failed = 0
    for gid, ok, detail in gates:
        mark = "PASS ✅" if ok else "FAIL ❌"
        print(f"  {mark}  {gid:<34} {detail}")
        if not ok:
            failed += 1
    print("=" * 60)
    if failed:
        print(f"게이트 {failed}개 실패 → 병합 차단")
        return 1
    print("모든 게이트 통과 ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
