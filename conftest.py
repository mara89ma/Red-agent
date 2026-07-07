"""pytest 루트 앵커 — 저장소 루트를 sys.path에 넣어 `redteam_core`를 import 가능하게.

src-layout이 아니므로 conftest.py의 위치(저장소 루트)가 sys.path[0]에 들어간다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
