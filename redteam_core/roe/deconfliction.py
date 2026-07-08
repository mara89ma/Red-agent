"""데컨플릭션 — 우군(fratricide 방지)·화력·스펙트럼(JCEOI).

교리:
  - JP 3-09 화력 데컨플릭션 + no-strike/제한표적(NSL/RTL, JP 3-60).
  - JP 3-85 JEMSO: 전자전은 아군 스펙트럼 사용과 충돌 → JCEOI 주파수 할당·
    데컨플릭션 승인 없이는 방사 금지.
동언님 gate 의 sysid allowlist(우군)를 재사용·확장한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

# 전자전(스펙트럼 방사) 액션 — 스펙트럼 데컨플릭션 필수.
_EW_ACTIONS = {"jam", "gnss_spoof"}


@dataclass
class DeconflictionResult:
    ok: bool
    conflicts: List[str] = field(default_factory=list)   # 위반 사유(사람이 읽는)


def check_deconfliction(action: str, target: dict, profile: dict) -> DeconflictionResult:
    conflicts: List[str] = []
    sysid = target.get("sysid")

    # 우군/보호 자산 = fratricide 위험(no-strike).
    no_strike = set(profile.get("no_strike_list", []))
    if sysid in no_strike:
        conflicts.append(f"fratricide: sysid {sysid} in no_strike_list")

    # 제한표적(RTL) — 특별승인 없이 교전 불가.
    if sysid in set(profile.get("restricted_targets", [])):
        conflicts.append(f"restricted target: sysid {sysid} (RTL)")

    # 스펙트럼 데컨플릭션(EW) — JCEOI 승인 없으면 방사 금지.
    if action in _EW_ACTIONS:
        spec = profile.get("spectrum", {})
        if not spec.get("jceoi_deconflicted", False):
            conflicts.append(f"spectrum: {action} requires JCEOI deconfliction (JP 3-85)")

    return DeconflictionResult(ok=not conflicts, conflicts=conflicts)
