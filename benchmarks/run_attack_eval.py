#!/usr/bin/env python3
"""공격측 평가 실행기 — 콘솔 표 + results/attack_eval.json 산출.

    python -m benchmarks.run_attack_eval          # 실행 + JSON 기록
    python -m benchmarks.run_attack_eval --print   # JSON을 stdout으로도 출력

결정론·오프라인. CI는 이 산출을 check_gates로 게이트한다.
"""

from __future__ import annotations

import argparse
import json
import os

from benchmarks.harness import results_path, run_suite


def main() -> None:
    ap = argparse.ArgumentParser(description="UAV RedTeam 공격 평가 하네스")
    ap.add_argument("--print", action="store_true", help="결과 JSON을 stdout에도 출력")
    ap.add_argument("--out", default=results_path(), help="결과 JSON 경로")
    args = ap.parse_args()

    report = run_suite()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    _print_table(report)
    print(f"\n[결과 JSON] {args.out}")
    if args.print:
        print(json.dumps(report, ensure_ascii=False, indent=2))


def _print_table(report: dict) -> None:
    print("=" * 78)
    print(f"UAV RedTeam 공격 평가 — {report['suite']} (결정론)")
    print("=" * 78)
    print(f"{'scenario':<14}{'technique':<12}{'hardened':<10}"
          f"{'attack':<9}{'expect':<9}{'gtv':<6}{'psv':<5}")
    print("-" * 78)
    for r in report["scenarios"]:
        flag = "REGRESS" if r["regression"] else "ok"
        print(f"{r['name']:<14}{r['technique']:<12}{str(r['hardened']):<10}"
              f"{str(r['attack_success']):<9}{str(r['expected_success']):<9}"
              f"{r['ground_truth_verification_rate']:<6}"
              f"{r['physical_safety_violations']:<5}{flag}")
    agg = report["aggregate"]
    print("-" * 78)
    print(f"ASR(vuln)={agg['attack_success_rate_vuln']}  "
          f"ASR(overall)={agg['attack_success_rate_overall']}  "
          f"PoV일관={agg['pov_pairs_consistent']}  "
          f"물리안전위반={agg['physical_safety_violations_total']}  "
          f"회귀={agg['regressions'] or '없음'}")


if __name__ == "__main__":
    main()
