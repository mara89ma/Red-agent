"""GazeboBackend — 물리 상태 root-of-trust (§2.7).

공격 경로 밖(out-of-band) Gazebo 시뮬레이터에서 기체의 **실제 물리 pose**를 읽는다.
표적발 MAVLink 텔레메트리(위조 가능)와 독립적이므로 진위 검증의 신뢰근거가 된다.

Gazebo(gz) CLI(`gz topic -e`)로 model pose를 구독한다. gz 미설치/미기동 시 명확히
실패한다 — 이 백엔드가 붙어야 물리 상태(고도·위치)가 신뢰근거가 된다.
Gazebo는 로컬 ENU(m) 좌표를 주므로 sim.home(lat/lon) 기준으로 위경도 변환.
"""

from __future__ import annotations

import json
import math
import shutil
import subprocess
from dataclasses import dataclass

_EARTH_R = 6378137.0


@dataclass
class GazeboBackend:
    world: str
    model: str
    home_lat: float
    home_lon: float
    timeout_s: float = 3.0

    def _gz(self) -> str:
        gz = shutil.which("gz") or shutil.which("ign")
        if not gz:
            raise RuntimeError("Gazebo(gz/ign) CLI 없음 — 물리 ground truth엔 Gazebo 필요")
        return gz

    def _pose(self) -> dict:
        """model pose 1건을 gz topic으로 읽어 {x,y,z} ENU(m) 반환."""
        gz = self._gz()
        topic = f"/world/{self.world}/dynamic_pose/info"
        try:
            out = subprocess.run([gz, "topic", "-e", "-n", "1", "-t", topic],
                                 capture_output=True, text=True, timeout=self.timeout_s)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Gazebo pose 타임아웃: {topic}") from exc
        return _parse_pose(out.stdout, self.model)

    def model_altitude_agl(self) -> float:
        return float(self._pose().get("z", 0.0))

    def model_position_latlon(self) -> tuple:
        p = self._pose()
        # ENU(m) → lat/lon 근사 (home 기준 평면 근사)
        dlat = (p.get("y", 0.0) / _EARTH_R) * (180.0 / math.pi)
        dlon = (p.get("x", 0.0) / (_EARTH_R * math.cos(math.radians(self.home_lat)))) * (180.0 / math.pi)
        return (self.home_lat + dlat, self.home_lon + dlon)


def _parse_pose(text: str, model: str) -> dict:
    """gz topic 출력(텍스트/JSON)에서 model의 position을 추출. 형식 관용 처리."""
    text = (text or "").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
        for pose in data.get("pose", []) if isinstance(data, dict) else []:
            if pose.get("name") == model:
                pos = pose.get("position", {})
                return {"x": pos.get("x", 0.0), "y": pos.get("y", 0.0), "z": pos.get("z", 0.0)}
    except json.JSONDecodeError:
        pass
    return {}


def from_config(gt_cfg: dict, home: dict) -> "GazeboBackend | None":
    """sim.ground_truth 설정에서 GazeboBackend 구성(backend != gazebo면 None)."""
    if str(gt_cfg.get("backend")) != "gazebo":
        return None
    gz = gt_cfg.get("gazebo", {})
    return GazeboBackend(
        world=gz.get("world", "default"),
        model=gz.get("model", "iris"),
        home_lat=float(home.get("lat", 0.0)),
        home_lon=float(home.get("lon", 0.0)),
    )
