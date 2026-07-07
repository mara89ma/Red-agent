"""MAVLink 툴 스키마 (§2.4).

`think`-augmented 인자 추론(TAFC 2601.18282) — 실행 전 think 제거되어 감사
로그로만 보존. 대규모 스키마 전체 주입 금지 → 카테고리 우선 라우팅(TOOLQP
2601.07782). Checker가 `target_sysid ∉ allowlist`면 차단.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

# MAV_CMD 상수
CMD = {
    "ARM_DISARM": 400,
    "DO_SET_MODE": 176,
    "NAV_TAKEOFF": 22,
    "DO_FLIGHTTERMINATION": 185,
    "RETURN_TO_LAUNCH": 20,
    "NAV_LAND": 21,
    "PARAM_SET": -1,          # 실제론 별도 PARAM_SET 메시지. 여기선 pseudo cmd_id.
}

# 원자 액션(추상 액션이 전개되는 단위) — 각각 C2 ability 1:1 (§1.6·§2.4).
ATOMIC_ACTIONS = {
    "recon_heartbeat":  {"risk_tier": "read", "cmd": None},
    "param_read":       {"risk_tier": "read", "cmd": None},
    "set_mode":         {"risk_tier": "write_lowrisk", "cmd": CMD["DO_SET_MODE"]},
    "force_arm":        {"risk_tier": "write_highrisk", "cmd": CMD["ARM_DISARM"]},
    "param_set_safety": {"risk_tier": "write_highrisk", "cmd": CMD["PARAM_SET"]},
    "mission_upload":   {"risk_tier": "write_highrisk", "cmd": None},
    "takeoff":          {"risk_tier": "physical_irreversible", "cmd": CMD["NAV_TAKEOFF"]},
    "disarm":           {"risk_tier": "physical_irreversible", "cmd": CMD["ARM_DISARM"]},
    "flight_terminate": {"risk_tier": "physical_irreversible", "cmd": CMD["DO_FLIGHTTERMINATION"]},
    "gnss_spoof":       {"risk_tier": "write_highrisk", "cmd": None},
    "jam":              {"risk_tier": "write_highrisk", "cmd": None},
}

# 확장 평면 원자 액션(ATLAS AML + 잔여 ATT&CK-ICS)을 canonical 레지스트리에 병합 —
# planner/_base_tier·build_command이 물리 액션과 동일하게 tier를 조회한다.
from .ics_actions import ICS_ACTIONS  # noqa: E402
from .ml_target import ML_ACTIONS  # noqa: E402

ATOMIC_ACTIONS.update(ML_ACTIONS)
ATOMIC_ACTIONS.update(ICS_ACTIONS)

# cmd_id 없는(=MAVLink command_long이 아닌) 액션 — Checker의 cmd_id 검증 면제 대상.
CMDLESS_ACTIONS = {"mission_upload", "gnss_spoof", "jam", *ML_ACTIONS, *ICS_ACTIONS}

# ArduPilot flight mode 번호 (custom_mode)
FLIGHT_MODE = {"STABILIZE": 0, "GUIDED": 4, "AUTO": 3, "RTL": 6, "LAND": 9}


@dataclass
class MavlinkCommand:
    """think-augmented 명령. Checker/Broker/HITL이 메타를 사용한다."""

    think: str                       # 인자 추론 근거 — 실행 전 제거, 감사 로그로만 보존
    action: str
    cmd_id: int
    target_sysid: int
    target_compid: int = 1
    params: List[float] = field(default_factory=lambda: [0.0] * 7)
    risk_tier: str = "read"
    requires_hitl: bool = False

    def payload(self) -> dict:
        """실행 페이로드 — `think`는 제거된다(감사만, §2.4)."""
        return {
            "cmd_id": self.cmd_id,
            "target_sysid": self.target_sysid,
            "target_compid": self.target_compid,
            "params": list(self.params),
            "action": self.action,
        }


def build_command(action: str, sysid: int, think: str, params=None) -> MavlinkCommand:
    """정적 KB(rag/static_kb.py) 스펙에 맞춰 원자 명령을 조립한다(인자 환각 방지)."""
    spec = ATOMIC_ACTIONS.get(action, {"risk_tier": "physical_irreversible", "cmd": None})
    p = list(params) if params else [0.0] * 7
    return MavlinkCommand(
        think=think,
        action=action,
        cmd_id=spec["cmd"] if spec["cmd"] is not None else 0,
        target_sysid=sysid,
        params=p,
        risk_tier=spec["risk_tier"],
    )
