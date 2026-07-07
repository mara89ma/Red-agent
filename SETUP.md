# fried-pollack-ai 실행 런북 (설치 · 설정 · 실행)

> 실제 동작에 필요한 **설치/바이너리 · 설정 · 실행 방법**을 계층(Tier)별로 정리한다.
> 핵심 원칙: **pip은 파이썬 라이브러리만 깐다.** 실 레인지 동작은 pip이 아니라 외부
> 인프라(SITL/Gazebo/방화벽/SOC)가 좌우한다. 낮은 Tier부터 올라가며 필요한 만큼만 설치.

| Tier | 무엇을 하나 | 추가 설치 | 실동작 |
|---|---|---|---|
| **0** | 아키텍처·에이전트·SOC 브릿지 데모 | 없음(stdlib) | 지금 즉시 |
| **1** | 실 MAVLink 공격 트래픽 (A4) | `pymavlink` + **ArduPilot SITL** | Gazebo 불필요 |
| **2** | 물리 진위 root-of-trust (S1 등) | + **Gazebo(gz)** | 선택 |
| **3** | egress OS 방화벽 강제 | + root/iptables | 선택 |
| **4** | SOC까지 완전 폐루프 | + SOC/Sentinel | SOC 구축 가정 |

---

## 환경 격리 (권장: conda env — base 오염 금지)

```bash
conda create -y -n redteam-agent python=3.12
conda activate redteam-agent          # 또는: conda run -n redteam-agent <cmd>
python -m ensurepip --upgrade         # env에 pip 없을 때
python -m pip install langgraph pyyaml # 기본 러너(LangGraph) + 프로파일 파서
# 이후 모든 실행은 이 env 안에서. base(전역)에는 설치하지 말 것.
```

> 검증 완료: 위 conda env(`redteam-agent`, python 3.12, langgraph 1.2.7)에서 `run.py`가
> `runner=LangGraph(interrupt HITL)`로 동작하고, interrupt 일시정지→resume 재개가 실동작함.

## Tier 0 — 스텁 모드 (설치 불필요, 지금 즉시)

`range_mode: container`. 인메모리 SITL 스텁으로 전 파이프라인 + ③ 브릿지가 돈다.

```bash
python run.py                 # A4 킬체인 실행 + 스코어카드
python run.py --emit-soc      # 관측 트래픽 → UAV*_CL(out/) + SOC Alert(out/)
python run.py --json          # 전체 리포트 JSON
python demo.py                # 서사형 데모
```

- 산출: `out/uav_cl_rows.ndjson`, `out/soc_alert.json`.
- **기본 러너 = LangGraph(interrupt HITL).** `pip install langgraph`면 고위험/물리 비가역
  명령 앞에서 그래프가 실제로 일시정지→운용자 승인 resume까지 대기. 미설치 시 동일
  라우팅의 stdlib 러너로 자동 강등(동기 콜백 HITL). 헤더 `runner=...`로 확인.
- (선택) `pip install pyyaml` — 프로파일 편집을 반영하려면. 없으면 내장 기본 프로파일로 폴백.

---

## Tier 1 — 실 MAVLink 공격 (ArduPilot SITL, Gazebo 불필요)

### 1-1. 설치

```bash
# (a) 파이썬 클라이언트
pip install pymavlink pyyaml

# (b) ArduPilot SITL (표적 = MAVLink를 말하는 실체). 예: Ubuntu
sudo apt-get install -y git python3-pip
git clone --recurse-submodules https://github.com/ArduPilot/ardupilot.git
cd ardupilot
Tools/environment_install/install-prereqs-ubuntu.sh -y     # 최초 1회
. ~/.profile
./waf configure --board sitl && ./waf copter               # 최초 빌드

# (c) mavlink-router (SITL 5760 → 5790 노출 + sim-state 별도 엔드포인트)
#     https://github.com/mavlink-router/mavlink-router (빌드 or 패키지)
```

> ArduPilot SITL은 **자체 내장 물리 모델**로 Gazebo 없이 단독 실행된다. 그래서 A4
> (force-arm/모드전환 = 논리 상태)는 SITL만으로 실증·검증된다.

### 1-2. 레인지 기동 (터미널 3개)

```bash
# 터미널 A — SITL 기동 (MAVProxy 없이 TCP 5760 노출)
cd ardupilot/ArduCopter
sim_vehicle.py -v ArduCopter --no-mavproxy       # tcp:127.0.0.1:5760

# 터미널 B — mavlink-router: SITL(5760) 수신 → 공격 링크 5790(TCP) + sim-state 5762(UDP)
mavlink-routerd -c mavlink-router.conf
```

`mavlink-router.conf` (버전에 따라 키 확인):
```ini
[General]
TcpServerPort = 5790          ; 공격 링크(에이전트가 붙는 곳)

[TcpEndpoint sitl]
Mode = Client
Address = 127.0.0.1
Port = 5760                    ; SITL 원본

[UdpEndpoint simstate]
Mode = Normal
Address = 127.0.0.1
Port = 5762                    ; 진위 오라클 전용(공격 링크와 분리)
```

### 1-3. 실행

```bash
# 터미널 C — 에이전트 (프리셋 프로파일: range_mode=sitl, backend=sim_state, 루프백 scope)
python run.py --profile engagement_profile.sitl-local.yaml --emit-soc
```

- `engagement_profile.sitl-local.yaml`은 `range_mode: sitl` + `scope_cidr: 127.0.0.0/24`
  + `ground_truth.backend: sim_state`(Gazebo 미사용)로 설정돼 있다.
- 이제 executor가 **실 MAVLink COMMAND_LONG**을 5790으로 주입하고, Validator가
  **SIM_STATE(별도 링크)** 로 arm/mode를 검증한다(§2.7 비적대 보조 등급).

### 1-4. 검증 포인트

- SITL 콘솔에 `ARM`/모드전환이 실제로 반영되는가.
- `out/uav_cl_rows.ndjson`에 `UAVOperator_CL SourceSystemId=250 Command=400` 행이 남는가.
- takeoff는 `blocked`(인간 전용 HITL) → 물리 안전 위반율 0 유지.

---

## Tier 2 — 물리 진위 root-of-trust (Gazebo, 선택)

**언제 필요:** S1 GNSS 스푸핑·물리 추락 등 "드론이 믿는 상태 vs 실제 물리"의 괴리를
**공격 경로 밖**에서 반증해야 하는 시나리오. A4엔 불필요.

### 2-1. 설치

```bash
# Gazebo (예: Harmonic). gz/ign CLI = 시스템 바이너리(pip 아님)
#   https://gazebosim.org/docs  (배포판별 설치)
# ArduPilot-Gazebo 플러그인
#   https://github.com/ArduPilot/ardupilot_gazebo  (빌드 후 GZ_SIM_* 환경변수 설정)
```

### 2-2. 기동 + 설정

```bash
# 터미널 A' — Gazebo 월드 기동
gz sim -r iris_runway.sdf

# 터미널 A  — SITL을 Gazebo 물리에 연결
sim_vehicle.py -v ArduCopter -f gazebo-iris --no-mavproxy

# pose 토픽 확인 (gazebo_backend.py가 구독하는 것)
gz topic -e -t /world/default/dynamic_pose/info
```

프로파일에서 backend를 gazebo로 전환:
```yaml
sim:
  home: {lat: 36.0, lon: 127.0}
  ground_truth:
    backend: gazebo                # sim_state → gazebo
    simstate_conn: "udp:127.0.0.1:5762"   # 논리 상태(armed/mode) 보조 링크는 유지
    gazebo: {world: default, model: iris} # gz 구독 대상(물리 pose = root-of-trust)
```

이제 고도·위치 진위는 Gazebo(독립 프로세스)에서 읽혀 **진짜 out-of-band 신뢰근거**가 된다.

---

## Tier 3 — egress OS 방화벽 강제 (선택, root)

기본은 `simulated`(앱 계층 fail-closed: executor가 송신 전 `gate.egress_allowed()` 검사).
OS 계층에 default-deny를 실제 설치하려면:

```bash
sudo python run.py --profile engagement_profile.sitl-local.yaml --apply-egress
```

- root + `nft`/`iptables`가 있으면 OUTPUT 정책 DROP + `scope_cidr` allow 규칙을 설치한다.
- `range_mode: live`면 강제 적용된다. 실패 시 안전하게 `simulated`로 강등.
- 상태는 리포트 헤더 `egress=installed|simulated`로 확인.

---

## Tier 4 — SOC 완전 폐루프 (SOC 구축 가정)

RedTeam↔SOC는 **코드 결합하지 않는다**. 유일한 다리는 `UAV*_CL` + Alert:

1. `python run.py --emit-soc` → `out/uav_cl_rows.ndjson`(UAV*_CL 행), `out/soc_alert.json`(Alert).
2. **실 배포에서는** telemetry-tap이 mavlink-router `tap_out`을 구독해 위 행을 SOC가 읽는
   **Sentinel 워크스페이스**에 적재(DCR/Log Ingestion API)한다. 여기서는 파일로 산출하므로,
   그 파일을 워크스페이스에 넣거나 `soc_alert.json`을 SOC의 `POST /alert`에 전달하면 된다.
3. SOC(구축 가정)가 Triage→Investigation→Validation→Response로 방어를 수행.

> `soc_alert.json`은 `agents/soc_agent.md §4`의 Alert 스키마(scenario_id·mitre·signals·
> expected_detection·defense_playbook)를 따른다.

---

## 설치 매트릭스 (요약)

| 항목 | 종류 | Tier | 없으면 |
|---|---|---|---|
| `pyyaml` | pip | 0(권장) | 내장 기본 프로파일 폴백 |
| `pymavlink` | pip | 1 | sitl 모드 연결 불가 |
| **ArduPilot SITL** | 소스 빌드 | 1 | 실 트래픽 대상 없음(가장 필수) |
| `mavlink-router` | 바이너리 | 1 | 5790 노출·sim-state 분리 링크 없음(직접 5760 대안) |
| **Gazebo (gz)** | 시스템 바이너리 | 2 | 물리 root-of-trust 불가(sim_state로 대체) |
| root + `nft`/`iptables` | 시스템 | 3 | `--apply-egress`만 미동작(simulated) |
| SOC + Sentinel | 별도 시스템 | 4 | ③ 폐루프 미완(Alert는 파일 산출) |
| `langgraph` | pip | (선택) | `use_langgraph=True`만 미사용(기본 stdlib 러너) |

---

## 자주 걸리는 문제 (Troubleshooting)

- **모든 write 노드가 `blocked` (egress_scope_violation)** — 표적 IP가 `scope_cidr` 밖.
  로컬 SITL(127.0.0.1)이면 `scope_cidr`에 `127.0.0.0/24`가 있어야 함(프리셋엔 포함).
- **`RuntimeError: pymavlink 필요`** — `range_mode: sitl` 인데 `pip install pymavlink` 안 됨.
- **연결 타임아웃(wait_heartbeat)** — SITL/mavlink-router 미기동, 또는 `services.port`/conn_str
  불일치. `conn_str = "{transport}:{ip}:{port}"` 로 조립됨(프리셋: `tcp:127.0.0.1:5790`).
- **`Gazebo(gz/ign) CLI 없음`** — `backend: gazebo` 인데 gz 미설치. `sim_state`로 내리거나 gz 설치.
- **arm은 됐다는데 검증 실패** — `simstate_conn` 엔드포인트가 안 열림. mavlink-router UDP 5762 확인.
- **sysid 차단** — 표적 sysid가 `target_sysids` allowlist 밖(SITL 기본 1).

---

## 최소 실동작 경로 (권장)

```
pip install pymavlink pyyaml
→ ArduPilot SITL 단독 기동 (Gazebo 없이)
→ mavlink-router 로 5790 노출 + 5762 sim-state
→ python run.py --profile engagement_profile.sitl-local.yaml --emit-soc
```
Gazebo·root·SOC는 각각 S1 물리검증 / OS방화벽 / 폐루프가 필요할 때만 추가.
