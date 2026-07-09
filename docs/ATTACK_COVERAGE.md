# UAV ATT&CK 커버리지 (자동 요약)

> 우리가 만든 **UAV용 ATT&CK 매트릭스(Enterprise + ICS, 15전술·116기법)** 대비 RED 에이전트 커버리지.
> **전 시나리오(S1~S126)·캠페인(C1~C33)이 매트릭스 기법으로 설명 가능**(미설명 0). 결정론·`mapping/uav_coverage.py` 산출.

## 핵심 수치
| 항목 | 값 |
|---|---|
| 총 기법 | 116 |
| 커버(공격 가능) | 113 (97.4%) |
| 범위내 유효 커버리지 | **100.0%** (제외 3=Resource Dev, 공격자 자기 인프라) |
| 히어로셋(방어 탐지불가 중 공격) | **34** |

## 15개 전술별 커버리지
| 전술 | 커버 |
|---|---|
| Reconnaissance | 4/4 |
| Resource Dev | 0/3 |
| Initial Access | 7/7 |
| Execution | 6/6 |
| Persistence | 5/5 |
| Privilege Escalation | 2/2 |
| Stealth/Evasion | 7/7 |
| Discovery | 3/3 |
| Lateral Movement | 11/11 |
| Collection | 10/10 |
| Command and Control | 14/14 |
| Exfiltration | 7/7 |
| Impair Process Control | 6/6 |
| Inhibit Response | 11/11 |
| Impact | 20/20 |

→ **Resource Development(공격자 준비)만 빼면 전 전술 100% 공격 가능.**

## 매트릭스 보강 기법 (전 시나리오 설명용)

**지상 세그먼트(4)**: T1203 GCS 파서 · T1195.002 GCS 업데이트 · T0857 모뎀 펌웨어 · T1565.001 텔레메트리

**군집·운용·공급망(3)**:
| 기법 | 전술 | 시나리오 |
|---|---|---|
| T0856 Spoof Reporting Message | Impair Process Control | S101 리더 스푸핑·S117 BLOS |
| T1553 Subvert Trust Controls | Stealth/Evasion | S73 아티팩트 서명 우회 |
| T1649 Steal/Forge Auth Certificates | Lateral Movement | S70 mTLS 위조 |

> 검토: 시나리오 31개 고유기법 대조 → 미설명 5개 중 T1070 오탐·S77 T0836 정정·신규 3개 추가 → **미설명 0**.
