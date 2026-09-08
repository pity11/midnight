"""Defense-in-depth contamination scanner for agent-visible task bundles."""

from __future__ import annotations

import hashlib
import re
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_NAME_MARKERS = re.compile(
    r"(?i)(?:^|[._-])(solution|writeup|answer|grader|expected[_-]?flag)(?:[._-]|$)"
)
_CONTENT_MARKERS = re.compile(
    r"(?i)\b(solution|writeup|answer|grader|expected[_-]?flag)\b"
)
_DEFAULT_FLAG = re.compile(rb"(?i)\b[A-Za-z0-9_]{0,32}(?:flag|ctf)[A-Za-z0-9_]*\{[^}\r\n]{2,}\}")
_TEXT_LIMIT = 4 * 1024 * 1024
_ARCHIVE_MEMBER_LIMIT = 16 * 1024 * 1024
_ARCHIVE_TOTAL_LIMIT = 128 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    finding_id: str
    path: str
    rule: str
    detail: str

    @classmethod
    def create(cls, *, path: str, rule: str, detail: str) -> Finding:
        raw = f"{path}\0{rule}\0{detail}".encode("utf-8", errors="replace")
        return cls(hashlib.sha256(raw).hexdigest()[:16], path, rule, detail)


def _unsafe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return path.is_absolute() or any(part == ".." for part in path.parts)


def _scan_bytes(path: str, data: bytes, patterns: list[re.Pattern[bytes]]) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in [_DEFAULT_FLAG, *patterns]:
        match = pattern.search(data)
        if match:
            excerpt_hash = hashlib.sha256(match.group(0)).hexdigest()[:12]
            findings.append(
                Finding.create(
                    path=path,
                    rule="flag-pattern",
                    detail=f"matched sensitive pattern (excerpt sha256:{excerpt_hash})",
                )
            )
    if len(data) <= _TEXT_LIMIT and b"\0" not in data:
        text = data.decode("utf-8", errors="ignore")
        marker = _CONTENT_MARKERS.search(text)
        if marker:
            findings.append(
                Finding.create(
                    path=path,
                    rule="sensitive-keyword",
                    detail=f"contains keyword {marker.group(1).lower()!r}",
                )
            )
    return findings


def _scan_zip(path: Path, patterns: list[re.Pattern[bytes]]) -> list[Finding]:
    findings: list[Finding] = []
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                logical = f"{path.name}!/{member.filename}"
                if _unsafe_archive_name(member.filename):
                    findings.append(
                        Finding.create(path=logical, rule="archive-path", detail="unsafe member path")
                    )
                    continue
                if member.is_dir():
                    continue
                total += member.file_size
                if member.file_size > _ARCHIVE_MEMBER_LIMIT or total > _ARCHIVE_TOTAL_LIMIT:
                    findings.append(
                        Finding.create(path=logical, rule="archive-limit", detail="scan size exceeded")
                    )
                    break
                with archive.open(member) as stream:
                    findings.extend(_scan_bytes(logical, stream.read(), patterns))
    except (OSError, zipfile.BadZipFile):
        return []
    return findings


def _scan_tar(path: Path, patterns: list[re.Pattern[bytes]]) -> list[Finding]:
    findings: list[Finding] = []
    total = 0
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                logical = f"{path.name}!/{member.name}"
                if _unsafe_archive_name(member.name) or member.issym() or member.islnk():
                    findings.append(
                        Finding.create(path=logical, rule="archive-path", detail="unsafe member type/path")
                    )
                    continue
                if not member.isfile():
                    continue
                total += member.size
                if member.size > _ARCHIVE_MEMBER_LIMIT or total > _ARCHIVE_TOTAL_LIMIT:
                    findings.append(
                        Finding.create(path=logical, rule="archive-limit", detail="scan size exceeded")
                    )
                    break
                stream = archive.extractfile(member)
                if stream is not None:
                    findings.extend(_scan_bytes(logical, stream.read(), patterns))
    except (OSError, tarfile.TarError):
        return []
    return findings


def compile_flag_patterns(patterns: list[str]) -> list[re.Pattern[bytes]]:
    compiled: list[re.Pattern[bytes]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern.encode("utf-8"), re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"invalid contamination flag pattern: {pattern!r}") from exc
    return compiled


def scan_bundle(root: str | Path, *, flag_patterns: list[str] | None = None) -> list[Finding]:
    """Return stable findings without exposing matched secret values."""
    base = Path(root).resolve()
    patterns = compile_flag_patterns(flag_patterns or [])
    findings: list[Finding] = []
    for path in sorted(base.rglob("*")):
        relative = path.relative_to(base).as_posix()
        if path.is_symlink():
            findings.append(
                Finding.create(path=relative, rule="file-type", detail="non-regular file")
            )
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            findings.append(
                Finding.create(path=relative, rule="file-type", detail="non-regular file")
            )
            continue
        marker = _NAME_MARKERS.search(path.name)
        if marker:
            findings.append(
                Finding.create(
                    path=relative,
                    rule="sensitive-filename",
                    detail=f"filename contains {marker.group(1).lower()!r}",
                )
            )
        data = path.read_bytes()
        findings.extend(_scan_bytes(relative, data, patterns))
        if zipfile.is_zipfile(path):
            findings.extend(_scan_zip(path, patterns))
        elif tarfile.is_tarfile(path):
            findings.extend(_scan_tar(path, patterns))
    return sorted(findings, key=lambda item: (item.path, item.rule, item.finding_id))
