"""아카이브 detonation — 추출 경로순회(Zip Slip) 탐지 (§T 확장).

취약한 추출기를 흉내내되 **실제로 밖에 쓰지 않고**, 각 엔트리의 해석 경로가 격리
베이스를 벗어나는지 검사해 탈출 엔트리를 잡는다. red 가 만든 악성 아카이브(§N
S39~S41)를 추출 전에 봉인·판정 = 방어 seam(blue Sentinel 룰 사각지대 보완).
"""
from __future__ import annotations

import io
import os
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import List


@dataclass
class ArchiveReport:
    fmt: str
    entries: List[str] = field(default_factory=list)
    escaping: List[str] = field(default_factory=list)   # 격리 밖으로 탈출하는 엔트리
    contained: bool = True                              # 실제 밖 쓰기 없음
    verdict: str = "benign"                             # benign | malicious


def _escapes(base_real: str, name: str) -> bool:
    dest = os.path.realpath(os.path.join(base_real, name))
    return not (dest == base_real or dest.startswith(base_real + os.sep))


def detonate_archive(data: bytes, fmt: str = "zip") -> ArchiveReport:
    """아카이브를 격리 파싱해 경로순회/심링크 탈출 엔트리를 탐지(실 추출 없음)."""
    r = ArchiveReport(fmt=fmt)
    base = tempfile.mkdtemp(prefix="arc_")
    base_real = os.path.realpath(base)
    try:
        if fmt == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    r.entries.append(name)
                    if name.startswith("/") or _escapes(base_real, name):
                        r.escaping.append(name)
        else:  # tar
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    r.entries.append(m.name)
                    if m.name.startswith("/") or _escapes(base_real, m.name):
                        r.escaping.append(m.name)
                    if (m.issym() or m.islnk()):
                        ln = m.linkname
                        if ln.startswith("/") or _escapes(base_real, ln):
                            r.escaping.append(f"{m.name}->{ln}(symlink 탈출)")
    finally:
        # 실제로 아무것도 추출하지 않았으므로 밖 쓰기 없음(봉인).
        import shutil
        shutil.rmtree(base, ignore_errors=True)
    r.verdict = "malicious" if r.escaping else "benign"
    return r
