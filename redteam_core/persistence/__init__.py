"""persistence — 설치/지속 실 메커니즘 (고도화 §L, 킬체인 5단계 본선 보강).

이전엔 지속성이 §J 모델뿐이었다. 이 층은 실제로 잔존하는 발판을 제공한다:
FileImplant(파일 발판·재부팅 생존 검증), ParamImplant(PARAM_SET EEPROM 백도어),
Foothold(발판 설치 + §K 지속 비콘 재수립). ATT&CK Persistence(TA0003).
"""
from .implant import FileImplant, ParamImplant, Foothold

__all__ = ["FileImplant", "ParamImplant", "Foothold"]
