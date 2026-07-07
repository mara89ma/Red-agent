"""(0) Engagement Gate — 비-LLM 신뢰근거 (§2.6).

profile YAML → net/sysid allowlist·예산 카운터·물리 비가역 토큰 발급정책.
프롬프트가 아니라 **네트워크/툴 계층에서** 강제한다. 시험창 밖이면 fail-closed.

물리 비가역 토큰: 평시 미발급. HITL 승인 시에만 단발·노드바인딩·만료시각 토큰
발급 → executor 경계가 소비(§2.5 ④). `risk_tier` 문자열 검사에만 의존하지 않는
2중 방어.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from ..logging_util import get_logger
from ..safety.egress import EgressController

log = get_logger("gate")


class FailClosed(RuntimeError):
    """시험창 밖·scope 위반 등 — 안전 기본값으로 정지."""


class Gate:
    def __init__(self, scope: dict, budget: dict, live: bool = False):
        self.scope = scope
        self.budget = dict(budget)
        self.live = live
        self._tokens: dict = {}          # node_id -> {by, expires, used}
        self.egress = EgressController(list(scope.get("scope_cidr", [])))
        self._sysid_allowlist = set(scope.get("target_sysids", []))

    # --- scope 강제 (Checker/Executor가 참조) ------------------------------
    def sysid_allowed(self, sysid: int) -> bool:
        """allowlist 밖 sysid로의 MAVLink는 계층에서 차단(§2.6 DoD)."""
        return sysid in self._sysid_allowlist

    def egress_allowed(self, ip: str) -> bool:
        """default-deny 애플리케이션 계층 가드. OS 방화벽은 EgressController가 설치."""
        return self.egress.allowed(ip)

    # --- 물리 비가역 토큰 (§2.5 ④ · §2.6) ----------------------------------
    def issue_token(self, node_id: str, approver: str, ttl_s: float = 120.0) -> None:
        """hitl_gate가 '승인' 시에만 호출. 단발·노드바인딩·만료."""
        self._tokens[node_id] = {"by": approver, "expires": time.time() + ttl_s, "used": False}

    def consume_token(self, node_id: str) -> bool:
        """executor 경계에서 1회 검증·소모. 없거나 만료·재사용이면 거부."""
        t = self._tokens.get(node_id)
        if not t or t["used"] or time.time() > t["expires"]:
            return False
        t["used"] = True
        return True

    def spend_tool_call(self) -> None:
        self.budget["tool_calls"] = self.budget.get("tool_calls", 0) - 1

    def budget_exhausted(self) -> bool:
        return self.budget.get("tool_calls", 0) <= 0


def _safe_yaml_load(path: str) -> dict:
    """프로파일 로드. pyyaml 미설치는 예상된 폴백(무음), 실제 로드 실패는 경고.

    과거엔 단일 `except Exception`이 파싱 실패까지 삼켜 잘못된 YAML이 조용히
    기본 프로파일로 강등됐다 — 이제 실패 원인을 stderr로 알린다.
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        return _DEFAULT_PROFILE          # pyyaml 없음 — 정상 폴백(데모는 무의존)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError("프로파일 최상위가 매핑(dict)이 아님")
        return data
    except Exception as exc:
        log.warning("프로파일 로드 실패(%s: %s: %s) → 기본 프로파일로 폴백",
                    path, type(exc).__name__, exc)
        return _DEFAULT_PROFILE


def _parse_ts(raw: str) -> Optional[datetime]:
    """ISO8601 타임스탬프 파싱. tz 미표기는 UTC로 간주. 실패 시 None."""
    try:
        dt = datetime.fromisoformat(raw.strip())
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def within_window(profile: dict, now: Optional[datetime] = None) -> bool:
    """비행시험창 검증 — fail-closed.

    `test_window`가 비었거나 `"..."`/`"always"`면 데모/컨테이너 레인지로 보고 통과.
    그 외에는 `"<start_iso>/<end_iso>"` 형식으로 보고 **실제 현재 시각과 비교**한다.
    창이 지정됐으나 파싱 불가하거나 현재 시각이 창 밖이면 False(fail-closed) —
    과거 구현은 양쪽 분기 모두 True를 반환해 시험창 강제가 무력화돼 있었다.
    """
    win = profile.get("authorization", {}).get("test_window", "")
    if not win or win in ("...", "always"):
        return True
    if "/" not in win:
        return False                     # 창이 지정됐으나 형식 불명 → fail-closed
    start_raw, end_raw = win.split("/", 1)
    start, end = _parse_ts(start_raw), _parse_ts(end_raw)
    if start is None or end is None:
        return False                     # 파싱 불가 → fail-closed
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return start <= current <= end


def load_gate(profile_path: str, apply_egress: bool = False) -> "tuple[Gate, dict]":
    """profile YAML을 파싱하고 Gate를 초기화. (gate, profile) 반환.

    apply_egress=True + root면 OS 방화벽(nft/iptables)에 default-deny 규칙 실제 설치.
    아니면 simulated(앱 계층 가드가 강제). live 모드는 강제 적용을 권장.
    """
    p = _safe_yaml_load(profile_path)
    auth = p.get("authorization", {})
    ops = p.get("ops", {})
    if not within_window(p):
        raise FailClosed("test_window 밖 — fail-closed")
    live = p.get("engagement", {}).get("range_mode") == "live"
    gate = Gate(scope=auth, budget=ops.get("budget", {"tool_calls": 40}), live=live)
    gate.egress.enforce(apply=apply_egress or live)            # default-deny 설치/시뮬레이트
    return gate, p


# 폴백 프로파일 (pyyaml 미설치 시). engagement_profile.yaml과 동일 의미.
_DEFAULT_PROFILE = {
    "engagement": {"name": "UAV 자율 레드팀 (uav-sim-env / KUS-FS)", "range_mode": "container"},
    "authorization": {
        "scope_cidr": ["10.50.0.0/24"],
        "target_sysids": [1],
        "out_of_scope": ["opensand_control_plane", "sentinel_backend"],
        "test_window": "always",
        "credentials": "datalink_foothold",
    },
    "constraints": {
        "blast_radius": "read_only",
        "data_sensitivity": "high",
        "egress_policy": "default-deny",
        "physical_safety": "geofence + flight-termination = 인간 전용",
    },
    "target_profile": {
        "hosts": [{"id": "av-muav", "ip": "10.50.0.10", "role": "fc",
                   "stack": "ardupilot", "sysid": 1}],
        "services": [{"host": "datalink-los", "ip": "10.50.0.20", "port": 5790,
                      "proto": "mavlink", "auth": "none"}],
        "datalink": {"los": {"router": "mavlink-router"}, "blos": {"emulator": "opensand"},
                     "mavlink_signing": False, "arming_check": 0},
    },
    "sim": {"home": {"lat": 36.0000, "lon": 127.0000},
            "initial": {"mode": "STABILIZE", "armed": False, "in_flight": False},
            "takeoff_alt_m": 10.0},
    "ops": {"autonomy_level": "autonomous",
            "budget": {"tokens": 200000, "wallclock_s": 900, "tool_calls": 40}},
}
