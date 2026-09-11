"""Defense-in-depth contamination scanner for agent-visible task bundles."""

from __future__ import annotations

import hashlib
import io
import re
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO

_NAME_MARKERS = re.compile(
    r"(?i)(?:^|[._-])(solution|writeup|answer|grader|expected[_-]?flag)(?:[._-]|$)"
)
_CONTENT_MARKERS = re.compile(
    r"(?i)\b(solution|writeup|answer|grader|expected[_-]?flag)\b"
)
_DEFAULT_FLAG = re.compile(rb"(?i)\b[A-Za-z0-9_]{0,32}(?:flag|ctf)[A-Za-z0-9_]*\{[^}\r\n]{2,}\}")
_TEXT_LIMIT = 4 * 1024 * 1024
_ARCHIVE_MEMBER_LIMIT = 32 * 1024 * 1024
_ARCHIVE_TOTAL_LIMIT = 128 * 1024 * 1024
_ARCHIVE_MEMBER_COUNT_LIMIT = 4096
_ARCHIVE_DEPTH_LIMIT = 3


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


@dataclass
class _ArchiveBudget:
    members: int = 0
    decompressed_bytes: int = 0


def _unsafe_archive_name(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return (
        path.is_absolute()
        or any(part == ".." for part in path.parts)
        or bool(path.parts and path.parts[0].endswith(":"))
    )


def _name_finding(path: str, name: str) -> Finding | None:
    marker = _NAME_MARKERS.search(PurePosixPath(name.replace("\\", "/")).name)
    if marker is None:
        return None
    return Finding.create(
        path=path,
        rule="sensitive-filename",
        detail=f"filename contains {marker.group(1).lower()!r}",
    )


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


def _limit_finding(path: str, detail: str) -> Finding:
    return Finding.create(path=path, rule="archive-limit", detail=detail)


def _read_archive_member(
    stream: IO[bytes],
    *,
    path: str,
    declared_size: int,
    budget: _ArchiveBudget,
) -> tuple[bytes | None, list[Finding], bool]:
    if declared_size > _ARCHIVE_MEMBER_LIMIT:
        return None, [_limit_finding(path, "archive member size exceeded")], False
    remaining = _ARCHIVE_TOTAL_LIMIT - budget.decompressed_bytes
    if declared_size > remaining:
        return None, [_limit_finding(path, "archive total size exceeded")], False

    read_limit = min(_ARCHIVE_MEMBER_LIMIT, remaining)
    data = stream.read(read_limit + 1)
    budget.decompressed_bytes += min(len(data), read_limit)
    if len(data) > read_limit:
        return None, [_limit_finding(path, "archive decompressed size exceeded")], True
    return data, [], False


def _archive_kind(data: bytes) -> str | None:
    source = io.BytesIO(data)
    if zipfile.is_zipfile(source):
        return "zip"
    source.seek(0)
    try:
        with tarfile.open(fileobj=source, mode="r:*"):
            return "tar"
    except (OSError, tarfile.TarError):
        return None


def _scan_nested_archive(
    path: str,
    data: bytes,
    patterns: list[re.Pattern[bytes]],
    budget: _ArchiveBudget,
    depth: int,
) -> list[Finding]:
    kind = _archive_kind(data)
    if kind is None:
        return []
    if depth > _ARCHIVE_DEPTH_LIMIT:
        return [_limit_finding(path, "archive nesting depth exceeded")]
    source = io.BytesIO(data)
    if kind == "zip":
        return _scan_zip(source, path, patterns, budget, depth)
    return _scan_tar(source, path, patterns, budget, depth)


def _scan_zip(
    source: Path | IO[bytes],
    logical_root: str,
    patterns: list[re.Pattern[bytes]],
    budget: _ArchiveBudget,
    depth: int,
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(source) as archive:
            for member in archive.infolist():
                logical = f"{logical_root}!/{member.filename}"
                if budget.members >= _ARCHIVE_MEMBER_COUNT_LIMIT:
                    findings.append(_limit_finding(logical, "archive member count exceeded"))
                    break
                budget.members += 1
                if _unsafe_archive_name(member.filename):
                    findings.append(
                        Finding.create(path=logical, rule="archive-path", detail="unsafe member path")
                    )
                    continue
                if member.is_dir():
                    continue
                name_finding = _name_finding(logical, member.filename)
                if name_finding is not None:
                    findings.append(name_finding)
                try:
                    with archive.open(member) as stream:
                        data, limit_findings, exhausted = _read_archive_member(
                            stream,
                            path=logical,
                            declared_size=member.file_size,
                            budget=budget,
                        )
                    findings.extend(limit_findings)
                    if exhausted:
                        break
                    if data is None:
                        continue
                    findings.extend(_scan_bytes(logical, data, patterns))
                    findings.extend(
                        _scan_nested_archive(logical, data, patterns, budget, depth + 1)
                    )
                except RuntimeError as exc:
                    if "encrypted" not in str(exc).lower() and "password" not in str(exc).lower():
                        raise
                    findings.append(
                        Finding.create(
                            path=logical,
                            rule="archive-encrypted",
                            detail="encrypted archive member could not be contamination-scanned",
                        )
                    )
    except (OSError, zipfile.BadZipFile):
        return findings
    return findings


def _scan_tar(
    source: Path | IO[bytes],
    logical_root: str,
    patterns: list[re.Pattern[bytes]],
    budget: _ArchiveBudget,
    depth: int,
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with (
            tarfile.open(source, mode="r:*")
            if isinstance(source, Path)
            else tarfile.open(fileobj=source, mode="r:*")
        ) as archive:
            for member in archive:
                logical = f"{logical_root}!/{member.name}"
                if budget.members >= _ARCHIVE_MEMBER_COUNT_LIMIT:
                    findings.append(_limit_finding(logical, "archive member count exceeded"))
                    break
                budget.members += 1
                if _unsafe_archive_name(member.name) or member.issym() or member.islnk():
                    findings.append(
                        Finding.create(path=logical, rule="archive-path", detail="unsafe member type/path")
                    )
                    continue
                if not member.isfile():
                    continue
                name_finding = _name_finding(logical, member.name)
                if name_finding is not None:
                    findings.append(name_finding)
                stream = archive.extractfile(member)
                if stream is not None:
                    with stream:
                        data, limit_findings, exhausted = _read_archive_member(
                            stream,
                            path=logical,
                            declared_size=member.size,
                            budget=budget,
                        )
                    findings.extend(limit_findings)
                    if exhausted:
                        break
                    if data is None:
                        continue
                    findings.extend(_scan_bytes(logical, data, patterns))
                    findings.extend(
                        _scan_nested_archive(logical, data, patterns, budget, depth + 1)
                    )
    except (OSError, tarfile.TarError):
        return findings
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
        name_finding = _name_finding(relative, path.name)
        if name_finding is not None:
            findings.append(name_finding)
        data = path.read_bytes()
        findings.extend(_scan_bytes(relative, data, patterns))
        budget = _ArchiveBudget()
        if zipfile.is_zipfile(path):
            findings.extend(_scan_zip(path, relative, patterns, budget, 0))
        elif tarfile.is_tarfile(path):
            findings.extend(_scan_tar(path, relative, patterns, budget, 0))
    return sorted(findings, key=lambda item: (item.path, item.rule, item.finding_id))
