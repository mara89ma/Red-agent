"""인메모리 SITL/Gazebo 레인지 스텁 (데모용).

세 계층을 분리한다 — 이것이 Validator 설계의 핵심(§1.0 통찰2, §2.7):
    • SimGroundTruth   — 공격 경로 밖 **신뢰근거**(Gazebo 물리상태·HIL 계측).
    • TargetTelemetry  — 표적발 보고값(untrusted). ACK/HEARTBEAT는 위조 가능.
    • ExecutorTransport — 명령을 실제 물리에 적용. ACK를 반환(위조 옵션 포함).

실배포에서는 SimGroundTruth가 `uav-sim-env` compose의 Gazebo 상태·레인지
계측으로, TargetTelemetry가 pymavlink read-only 세션으로 대체된다.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from . import ics_actions, ml_target
from .mavlink import FLIGHT_MODE


@dataclass
class _World:
    """레인지의 단일 진실. 공격 경로 밖(out-of-band)에서만 읽힌다.

    모든 필드는 프로파일 seed로 채워진다(Range.from_profile). 기본값은
    프로파일 부재 시 폴백일 뿐 — 환경 정보는 코드가 아니라 YAML이 권위.
    """

    sysid: int = 1                   # 표적 sysid (profile.target_profile.hosts[].sysid)
    armed: bool = False
    custom_mode: int = FLIGHT_MODE["STABILIZE"]
    alt_agl: float = 0.0
    in_flight: bool = False
    lat: float = 0.0                 # 실제 물리 위도 (profile.sim.home.lat) — ground truth
    lon: float = 0.0                 # 실제 물리 경도 (profile.sim.home.lon) — ground truth
    takeoff_alt_m: float = 10.0      # takeoff 목표 고도 (profile.sim.takeoff_alt_m)
    arming_check: int = 0            # 표적 사실 (profile.target_profile.datalink.arming_check)
    mavlink_signing: bool = False    # 표적 사실 (profile.target_profile.datalink.mavlink_signing)
    # GNSS 스푸핑 상태(S1). 성공한 스푸핑은 '믿는 위치'만 틀어놓고 실제 위치는 불변.
    gps_spoofed: bool = False        # 스푸핑 주입이 실제로 먹혔는가
    believed_lat: Optional[float] = None   # 드론이 *믿는* 위도(스푸핑 시 실제와 괴리)
    believed_lon: Optional[float] = None
    gnss_antispoof: bool = False     # 하드닝: 다중센서 융합/인증으로 스푸핑 거부

    # --- 온보드-AI 표적 평면(A: ATLAS 능력 확장) — 오라클이 실제 모델 결정을 읽는다 ----
    ml_robust: bool = False                 # 하드닝: 적대적 견고 모델+입력검증+출력필터
    ml_perception_truth: str = ml_target.DEFAULT_PERCEPTION_TRUTH   # 실제 대상(장애물)
    ml_perception_output: str = ml_target.DEFAULT_PERCEPTION_TRUTH  # 모델이 출력/행동하는 값
    ml_adversarial_crafted: bool = False    # AML.T0043 스테이징 완료 여부
    ml_llm_secret: str = ml_target.DEFAULT_LLM_SECRET   # 코파일럿 시크릿(오라클 진실)
    ml_llm_protected: bool = True           # 코파일럿 가드레일 온전 여부
    ml_llm_injected: bool = False           # AML.T0051 인젝션이 실제로 결정을 바꿨는가
    ml_llm_leaked_value: Optional[str] = None   # 실제로 빠져나간 값(디코이면 시크릿≠)

    # --- 잔여 ATT&CK-ICS 평면 — 오라클이 실제 상태 변화를 읽는다 -----------------
    open_ports: list = field(default_factory=lambda: [5790])   # 실제 오픈 포트(정찰 진실)
    scan_done: bool = False                 # T1595 정찰 수행 여부
    c2_established: bool = False             # T0885 상용 포트 C2 확립
    c2_port: Optional[int] = None
    network_segmented: bool = False         # 하드닝: 망분리 → C2 차단
    relay_on: bool = False                  # T0855 무인가 명령의 실제 액추에이터 변화
    telemetry_spoofed: bool = False         # T0856 보고 위조가 실제로 먹혔는가
    protection_enabled: bool = True         # T0837 실패세이프/지오펜스 보호 온전 여부
    satcom_encrypted: bool = False          # 하드닝: BLOS 링크 암호화/상호인증 → MITM 거부
    satcom_mitm_active: bool = False        # T0830 SATCOM AiTM이 실제로 성립했는가


class SimGroundTruth:
    """공격 경로가 닿지 않는 신뢰근거 오라클 (Gazebo/HIL). §2.7."""

    def __init__(self, world: _World):
        self._w = world

    def snapshot(self) -> dict:
        return {"armed": self._w.armed, "mode": self._w.custom_mode,
                "alt_rel": self._w.alt_agl, "in_flight": self._w.in_flight}

    def motors_armed(self) -> bool:
        return self._w.armed

    def flight_mode(self) -> int:
        return self._w.custom_mode

    def altitude_agl(self) -> float:
        return self._w.alt_agl

    def position(self) -> tuple:
        return (self._w.lat, self._w.lon)

    # --- 온보드-AI 오라클(공격 경로 밖 실제 모델 결정) -----------------------
    def perception_evaded(self) -> bool:
        return ml_target.perception_evaded(self._w)

    def perception_output(self) -> str:
        return ml_target.perception_output(self._w)

    def perception_truth(self) -> str:
        return ml_target.perception_truth(self._w)

    def adversarial_crafted(self) -> bool:
        return ml_target.adversarial_crafted(self._w)

    def llm_injected(self) -> bool:
        return ml_target.llm_injected(self._w)

    def secret_leaked(self) -> bool:
        return ml_target.secret_leaked(self._w)

    def secret_value(self) -> str:
        return ml_target.secret_value(self._w)

    # --- 잔여 ICS 평면 오라클(실제 상태 변화) -------------------------------
    def scan_discovered(self) -> bool:
        return ics_actions.scan_discovered(self._w)

    def c2_established(self) -> bool:
        return ics_actions.c2_established(self._w)

    def actuator_changed(self) -> bool:
        return ics_actions.actuator_changed(self._w)

    def telemetry_spoofed(self) -> bool:
        return ics_actions.telemetry_spoofed(self._w)

    def protection_lost(self) -> bool:
        return ics_actions.protection_lost(self._w)

    def satcom_compromised(self) -> bool:
        return ics_actions.satcom_compromised(self._w)


class TargetTelemetry:
    """표적발 보고값 — untrusted(스푸핑·ACK 위조 가능). 비교용으로만 사용."""

    def __init__(self, world: _World, forge: bool = False):
        self._w = world
        self.forge = forge          # True면 실제와 다른 값을 '성공'으로 보고(적대 시뮬)

    def heartbeat(self) -> dict:
        """결정론 파서가 읽는 원시 HEARTBEAT(§1.4 (1))."""
        return {
            "autopilot": "ArduPilot",
            "type": "MUAV",
            "sysid": self._w.sysid,          # 프로파일 seed (하드코딩 아님)
            "base_mode_armed": self._w.armed,
            "custom_mode": self._w.custom_mode,
            "mavlink_signing": self._w.mavlink_signing,
            "arming_check": self._w.arming_check,
        }

    def global_position(self) -> tuple:
        """드론이 *믿는* 위치. GNSS 스푸핑이 먹히면 실제(ground truth)와 괴리된다.

        Validator는 이 값(믿는 위치)과 SimGroundTruth.position()(실제 위치)의 괴리로
        S1 성공을 판정한다. 과거 구현은 두 분기 모두 실제 위치를 반환해 괴리가 항상
        0이었고, S1 시나리오가 스텁에서 절대 검증되지 않았다.
        """
        if self._w.gps_spoofed and self._w.believed_lat is not None:
            return (self._w.believed_lat, self._w.believed_lon)
        return (self._w.lat, self._w.lon)


class ExecutorTransport:
    """격리 공격박스에서 원자 명령 1건을 물리에 적용. COMMAND_ACK 반환."""

    def __init__(self, world: _World):
        self._w = world

    def apply(self, action: str, params) -> dict:
        """물리 규칙에 따라 world를 변경하고 ACK를 반환.

        주의: ACK=ACCEPTED는 '수신'만 의미하고 위조 가능(§1.0 통찰2).
        Validator는 이 ACK가 아니라 SimGroundTruth로 효과를 검증한다.
        """
        # 온보드-AI 평면 액션은 ml_target으로 위임(동형 3계층 분리).
        if action in ml_target.ML_ACTIONS:
            return ml_target.apply_ml_action(self._w, action, params)
        # 잔여 ICS 평면 액션(정찰/C2/무인가명령/보고위조/보호무력화)은 ics_actions로 위임.
        if action in ics_actions.ICS_ACTIONS:
            return ics_actions.apply_ics_action(self._w, action, params)

        forged = False
        if action == "set_mode":
            self._w.custom_mode = int(params[1]) if len(params) > 1 else self._w.custom_mode
            result = "ACCEPTED"
        elif action == "force_arm":
            # ARMING_CHECK=0 이므로 지상 무장 성공(환경이 공격에 유리).
            if self._w.arming_check == 0 or self._w.mavlink_signing is False:
                self._w.armed = True
                result = "ACCEPTED"
            else:
                # 하드닝 인스턴스: 거부되지만 ACK는 위조되어 ACCEPTED로 올 수 있음.
                result = "ACCEPTED"
                forged = True     # ACK≠상태: 수락 보고했지만 실제 무장 안 됨
        elif action == "takeoff":
            # 물리 비가역. 게이트를 통과해 토큰이 소비된 경우에만 executor가 호출.
            self._w.in_flight = True
            self._w.alt_agl = float(params[0]) if params and params[0] else self._w.takeoff_alt_m
            result = "ACCEPTED"
        elif action == "disarm":
            self._w.armed = False
            self._w.in_flight = False
            result = "ACCEPTED"
        elif action == "gnss_spoof":
            # 성공한 스푸핑: 드론이 '믿는' 위치를 공격자 목표로 이동(실제 위치 불변).
            # params = [drift_lat_deg, drift_lon_deg] (선택). 기본 ≈1.1km >> 임계.
            if self._w.gnss_antispoof:
                # 하드닝(다중센서 융합/인증): 주입 거부 — 믿는 위치 불변. ACK는 위조 가능.
                result = "ACCEPTED"
                forged = True
            else:
                d_lat = float(params[0]) if params and len(params) > 0 and params[0] else 0.01
                d_lon = float(params[1]) if params and len(params) > 1 and params[1] else 0.0
                self._w.gps_spoofed = True
                self._w.believed_lat = self._w.lat + d_lat
                self._w.believed_lon = self._w.lon + d_lon
                result = "ACCEPTED"
        else:
            result = "ACCEPTED"
        return {"command_ack": result, "action": action, "forged": forged}


@dataclass
class Range:
    """레인지 번들 — state["range"]에 실린다. vuln/hardened 페어 지원(§2.9 M3)."""

    world: _World = field(default_factory=_World)
    hardened: bool = False

    def __post_init__(self):
        if self.hardened:
            # PoV 페어레인지 변환(§2.9 M3): 하드닝 인스턴스 = 서명 ON·ARMING_CHECK=1
            # + GNSS 다중센서 융합(스푸핑 거부). 동일 명령이 vuln=성공/hardened=거부.
            self.world.arming_check = 1
            self.world.mavlink_signing = True
            self.world.gnss_antispoof = True
            self.world.ml_robust = True          # 적대적 견고 모델+입력검증+출력필터(AI 평면)
            self.world.network_segmented = True  # 망분리 → 상용 포트 C2 차단(T0885 하드닝)
            self.world.satcom_encrypted = True   # BLOS 링크 암호화/인증 → SATCOM MITM 차단(T0830)

    @classmethod
    def from_profile(cls, profile: dict, hardened: bool = False) -> "Range":
        """환경 정보를 코드가 아니라 프로파일 YAML에서 seed한다.

        target_profile(sysid·signing·arming_check) + sim(home·initial·takeoff_alt)를
        읽어 _World를 구성. 실 레인지 전환 시 이 메서드만 교체하면 된다(seam).
        """
        tp = profile.get("target_profile", {})
        hosts = tp.get("hosts", [{}])
        datalink = tp.get("datalink", {})
        sim = profile.get("sim", {})
        home = sim.get("home", {})
        initial = sim.get("initial", {})
        # 정찰 오라클 진실 — 프로파일 services 포트에서 seed(부재 시 MAVLink 기본).
        ports = [s.get("port") for s in tp.get("services", []) if s.get("port")]

        world = _World(
            sysid=hosts[0].get("sysid", 1) if hosts else 1,
            armed=bool(initial.get("armed", False)),
            in_flight=bool(initial.get("in_flight", False)),
            custom_mode=FLIGHT_MODE.get(initial.get("mode", "STABILIZE"),
                                        FLIGHT_MODE["STABILIZE"]),
            lat=float(home.get("lat", 0.0)),
            lon=float(home.get("lon", 0.0)),
            takeoff_alt_m=float(sim.get("takeoff_alt_m", 10.0)),
            arming_check=int(datalink.get("arming_check", 0)),
            mavlink_signing=bool(datalink.get("mavlink_signing", False)),
            open_ports=ports or [5790],
        )
        return cls(world=world, hardened=hardened)

    @property
    def ground_truth(self) -> SimGroundTruth:
        return SimGroundTruth(self.world)

    @property
    def telemetry(self) -> TargetTelemetry:
        return TargetTelemetry(self.world)

    @property
    def transport(self) -> ExecutorTransport:
        return ExecutorTransport(self.world)


def independent_oracle(state) -> SimGroundTruth:
    """실행 tick에 라이브 물리상태를 재취득하는 독립 오라클(§2.5 ①, 캐시 금지)."""
    return state["range"].ground_truth


def haversine(a: tuple, b: tuple) -> float:
    """두 (lat,lon) 사이 거리(m). S1 GNSS 스푸핑 드리프트 판정용."""
    r = 6371000.0
    dlat = math.radians(b[0] - a[0])
    dlon = math.radians(b[1] - a[1])
    h = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(a[0])) * math.cos(math.radians(b[0])) * math.sin(dlon / 2) ** 2)
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))
