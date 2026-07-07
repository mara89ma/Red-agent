"""실 pymavlink 3-seam 어댑터 (range_mode: sitl|hil|live).

스텁(sitl_stub.py)과 **동일 인터페이스**를 구현해 노드 코드 변경 없이 스왑된다:
    • MavlinkTransport  (쓰기 seam)   — .apply(action, params) -> ACK dict
    • MavlinkTelemetry  (관측 seam)   — .heartbeat(), .global_position()  [untrusted]
    • GroundTruthOracle (진위 seam)   — .snapshot()/.motors_armed()/.flight_mode()/
                                        .altitude_agl()/.position()   [out-of-band 신뢰근거]

★ 신뢰근거 원칙(§2.7): 물리 상태(고도·위치)는 **Gazebo/HIL**(공격 경로 밖)이 root-of-trust.
  논리 상태(armed·mode)는 SITL 내부 sim-state를 *별도 링크*로 읽는 **비적대 가정 보조**
  (표적발 HEARTBEAT는 위조 가능하므로 검증 근거로 쓰지 않는다).

pymavlink는 선택 의존성 — 미설치 시 import 시점이 아니라 연결 시점에 명확히 실패한다.
실 SITL/Gazebo가 있어야 실제로 동작한다(스캐폴드는 코드 경로만 완성).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .mavlink import CMD, FLIGHT_MODE


def _require_pymavlink():
    try:
        from pymavlink import mavutil  # type: ignore
        return mavutil
    except Exception as exc:  # pragma: no cover - 실 환경에서만
        raise RuntimeError(
            "range_mode=sitl|hil|live 에는 pymavlink가 필요합니다: pip install pymavlink"
        ) from exc


# 역매핑: MAV_RESULT 코드 → 문자열 (COMMAND_ACK 해석)
def _ack_str(result: int) -> str:
    return {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED",
            3: "UNSUPPORTED", 4: "FAILED", 5: "IN_PROGRESS"}.get(result, f"RESULT_{result}")


# --------------------------------------------------------------------------
# (쓰기 seam) 격리 공격박스 → datalink-los:5790 실 MAVLink 인젝션
# --------------------------------------------------------------------------
class MavlinkTransport:
    def __init__(self, conn_str: str, target_sysid: int, target_compid: int = 1,
                 source_system: int = 250, timeout_s: float = 3.0):
        self._mavutil = _require_pymavlink()
        self._conn_str = conn_str
        self._sysid = target_sysid
        self._compid = target_compid
        self._src = source_system
        self._timeout = timeout_s
        self._m = None

    def _link(self):
        if self._m is None:
            self._m = self._mavutil.mavlink_connection(self._conn_str, source_system=self._src)
            self._m.wait_heartbeat(timeout=self._timeout)
        return self._m

    def apply(self, action: str, params) -> dict:
        """원자 명령 1건을 실제로 전송하고 COMMAND_ACK를 반환. ACK≠물리상태(§1.0)."""
        m = self._link()
        p = (list(params) + [0.0] * 7)[:7]

        if action == "param_set_safety":
            # PARAM_SET: params=[<param_id 인덱스 없음>] → 실제론 이름 필요. 스캐폴드는 예시.
            # 관례상 preconditions.param_name/value로 확장. 여기선 ARMING_CHECK=0 예시.
            m.mav.param_set_send(self._sysid, self._compid, b"ARMING_CHECK",
                                 0.0, self._mavutil.mavlink.MAV_PARAM_TYPE_INT32)
            return {"command_ack": "ACCEPTED", "action": action, "forged": False}

        if action in ("gnss_spoof", "jam"):
            # RF/GNSS는 MAVLink command_long이 아니라 SDR/네트워크 계층. 별도 도구 필요.
            raise NotImplementedError(f"{action}: SDR/RF 도구 연동 필요(command_long 아님)")

        cmd_id = CMD_FOR.get(action)
        if cmd_id is None:
            # recon/param_read 등 쓰기 아님 — no-op ACK
            return {"command_ack": "ACCEPTED", "action": action, "forged": False}

        m.mav.command_long_send(self._sysid, self._compid, cmd_id, 0,
                                p[0], p[1], p[2], p[3], p[4], p[5], p[6])
        ack = m.recv_match(type="COMMAND_ACK", blocking=True, timeout=self._timeout)
        result = _ack_str(ack.result) if ack is not None else "NO_ACK"
        return {"command_ack": result, "action": action, "forged": False}


# 원자 액션 → MAV_CMD id (command_long 용). None이면 command_long 아님.
CMD_FOR = {
    "set_mode": CMD["DO_SET_MODE"],
    "force_arm": CMD["ARM_DISARM"],
    "disarm": CMD["ARM_DISARM"],
    "takeoff": CMD["NAV_TAKEOFF"],
    "flight_terminate": CMD["DO_FLIGHTTERMINATION"],
}


# --------------------------------------------------------------------------
# (관측 seam) read-only pymavlink — 표적 보고값(untrusted, 비교용)
# --------------------------------------------------------------------------
class MavlinkTelemetry:
    def __init__(self, conn_str: str, timeout_s: float = 3.0):
        self._mavutil = _require_pymavlink()
        self._conn_str = conn_str
        self._timeout = timeout_s
        self._m = None

    def _link(self):
        if self._m is None:
            self._m = self._mavutil.mavlink_connection(self._conn_str)
            self._m.wait_heartbeat(timeout=self._timeout)
        return self._m

    def heartbeat(self) -> dict:
        m = self._link()
        hb = m.recv_match(type="HEARTBEAT", blocking=True, timeout=self._timeout)
        armed = bool(hb.base_mode & self._mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED) if hb else False
        return {
            "autopilot": "ArduPilot",
            "type": "MUAV",
            "sysid": m.target_system,
            "base_mode_armed": armed,
            "custom_mode": hb.custom_mode if hb else 0,
            # 무서명 여부는 MAVLink signing 협상 상태로 판정(간이): 서명 미사용이면 False
            "mavlink_signing": bool(getattr(m.mav, "signing", None) and m.mav.signing.secret_key),
            "arming_check": None,   # 파라미터 read로 확인해야 함(스캐폴드는 미조회)
        }

    def global_position(self) -> tuple:
        m = self._link()
        gp = m.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=self._timeout)
        if gp is None:
            return (0.0, 0.0)
        return (gp.lat / 1e7, gp.lon / 1e7)


# --------------------------------------------------------------------------
# (진위 seam) out-of-band ground truth — Gazebo(물리) + SITL sim-state(논리 보조)
# --------------------------------------------------------------------------
class GroundTruthOracle:
    """물리=Gazebo(root-of-trust) · 논리=SITL SIM_STATE(별도 링크, 비적대 보조)."""

    def __init__(self, gz_backend: Optional[object], simstate_conn: Optional[str],
                 timeout_s: float = 3.0):
        self._gz = gz_backend                 # GazeboBackend | None
        self._simstate_conn = simstate_conn   # SITL sim-state 전용 별도 MAVLink 링크
        self._timeout = timeout_s
        self._m = None

    def _sim_link(self):
        if self._simstate_conn is None:
            return None
        if self._m is None:
            mavutil = _require_pymavlink()
            self._m = mavutil.mavlink_connection(self._simstate_conn)
        return self._m

    # 물리 상태 — Gazebo가 진실. Gazebo 없으면 SITL SIM_STATE로 폴백(비적대 가정).
    def altitude_agl(self) -> float:
        if self._gz is not None:
            return float(self._gz.model_altitude_agl())
        return self._simstate_altitude()

    def position(self) -> tuple:
        if self._gz is not None:
            return tuple(self._gz.model_position_latlon())
        m = self._sim_link()
        ss = m.recv_match(type="SIMSTATE", blocking=True, timeout=self._timeout) if m else None
        return (ss.lat / 1e7, ss.lng / 1e7) if ss else (0.0, 0.0)

    def _simstate_altitude(self) -> float:
        m = self._sim_link()
        ss = m.recv_match(type="SIMSTATE", blocking=True, timeout=self._timeout) if m else None
        return float(ss.alt) if ss else 0.0

    # 논리 상태 — 표적발 HEARTBEAT 아님. SITL 내부 상태(별도 링크) = 비적대 가정 보조.
    def motors_armed(self) -> bool:
        m = self._sim_link()
        if m is None:
            return False
        mavutil = self._require()
        hb = m.recv_match(type="HEARTBEAT", blocking=True, timeout=self._timeout)
        return bool(hb.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED) if hb else False

    def flight_mode(self) -> int:
        m = self._sim_link()
        if m is None:
            return FLIGHT_MODE["STABILIZE"]
        hb = m.recv_match(type="HEARTBEAT", blocking=True, timeout=self._timeout)
        return hb.custom_mode if hb else FLIGHT_MODE["STABILIZE"]

    def _require(self):
        from pymavlink import mavutil  # type: ignore
        return mavutil

    def snapshot(self) -> dict:
        return {"armed": self.motors_armed(), "mode": self.flight_mode(),
                "alt_rel": self.altitude_agl(), "in_flight": self.altitude_agl() > 0.5}


# --------------------------------------------------------------------------
# 실 레인지 번들 — 스텁 Range와 동일 프로퍼티(.ground_truth/.telemetry/.transport)
# --------------------------------------------------------------------------
@dataclass
class MavlinkRange:
    conn_str: str                       # 예: "tcp:10.50.0.20:5790"
    target_sysid: int = 1
    simstate_conn: Optional[str] = None  # SITL sim-state 전용 링크 (논리 ground truth 보조)
    gz_backend: Optional[object] = None  # Gazebo 백엔드 (물리 root-of-trust)
    hardened: bool = False               # 실 레인지에선 별도 하드닝 인스턴스로 표현
    _transport: Optional[MavlinkTransport] = field(default=None, repr=False)
    _telemetry: Optional[MavlinkTelemetry] = field(default=None, repr=False)
    _ground_truth: Optional[GroundTruthOracle] = field(default=None, repr=False)

    @property
    def transport(self) -> MavlinkTransport:
        if self._transport is None:
            self._transport = MavlinkTransport(self.conn_str, self.target_sysid)
        return self._transport

    @property
    def telemetry(self) -> MavlinkTelemetry:
        # 캐시: tick마다 새 연결/wait_heartbeat churn 방지. 읽기는 매 호출 fresh.
        if self._telemetry is None:
            self._telemetry = MavlinkTelemetry(self.conn_str)
        return self._telemetry

    @property
    def ground_truth(self) -> GroundTruthOracle:
        # 캐시: executor/route_to_hitl가 tick마다 여러 번 접근 → 재연결 churn 방지.
        if self._ground_truth is None:
            self._ground_truth = GroundTruthOracle(self.gz_backend, self.simstate_conn)
        return self._ground_truth

    @classmethod
    def from_profile(cls, profile: dict, hardened: bool = False) -> "MavlinkRange":
        tp = profile.get("target_profile", {})
        hosts = tp.get("hosts", [{}])
        svcs = tp.get("services", [{}])
        svc = next((s for s in svcs if s.get("proto") == "mavlink"), svcs[0] if svcs else {})
        ip = svc.get("ip") or svc.get("host") or "127.0.0.1"
        port = svc.get("port", 5790)
        proto = "tcp" if str(svc.get("transport", "tcp")) == "tcp" else "udp"
        conn = f"{proto}:{ip}:{port}"

        sim = profile.get("sim", {})
        gt = sim.get("ground_truth", {})
        from .gazebo_backend import from_config as gz_from_config
        gz = gz_from_config(gt, sim.get("home", {}))   # 물리 root-of-trust (backend=gazebo면)
        return cls(
            conn_str=conn,
            target_sysid=hosts[0].get("sysid", 1) if hosts else 1,
            simstate_conn=gt.get("simstate_conn"),     # 예: "udp:127.0.0.1:5762" (논리 보조)
            gz_backend=gz,
            hardened=hardened,
        )
