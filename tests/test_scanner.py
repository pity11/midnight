from __future__ import annotations

import io
import tarfile
import zipfile

from midnight.evaluation import scanner


def _zip_bytes(name: str, data: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return output.getvalue()


def _tar_bytes(name: str, data: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def test_scans_zip_and_tar_archives_recursively(tmp_path):
    nested_tar = _tar_bytes("evidence.txt", b"CTF{nested-contamination}")
    (tmp_path / "bundle.zip").write_bytes(_zip_bytes("captures/inner.tar.gz", nested_tar))

    findings = scanner.scan_bundle(tmp_path)

    assert any(
        finding.rule == "flag-pattern"
        and finding.path == "bundle.zip!/captures/inner.tar.gz!/evidence.txt"
        for finding in findings
    )


def test_allows_25_mib_archive_evidence_member(tmp_path):
    evidence = b"\0" * (25 * 1024 * 1024)
    (tmp_path / "capture.zip").write_bytes(_zip_bytes("capture.pcap", evidence))

    findings = scanner.scan_bundle(tmp_path)

    assert not any(finding.rule == "archive-limit" for finding in findings)


def test_nested_archive_depth_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_ARCHIVE_DEPTH_LIMIT", 1)
    nested = _zip_bytes("level-3.zip", _zip_bytes("payload.bin", b"player data"))
    (tmp_path / "level-1.zip").write_bytes(_zip_bytes("level-2.zip", nested))

    findings = scanner.scan_bundle(tmp_path)

    assert any(
        finding.rule == "archive-limit"
        and finding.detail == "archive nesting depth exceeded"
        and finding.path.endswith("!/level-3.zip")
        for finding in findings
    )


def test_archive_member_count_and_total_size_are_bounded(tmp_path, monkeypatch):
    count_archive = tmp_path / "count.zip"
    with zipfile.ZipFile(count_archive, "w") as archive:
        archive.writestr("one.bin", b"1")
        archive.writestr("two.bin", b"2")
    monkeypatch.setattr(scanner, "_ARCHIVE_MEMBER_COUNT_LIMIT", 1)

    total_archive = tmp_path / "total.zip"
    with zipfile.ZipFile(total_archive, "w") as archive:
        archive.writestr("evidence.bin", b"123456789012")
    monkeypatch.setattr(scanner, "_ARCHIVE_TOTAL_LIMIT", 10)

    findings = scanner.scan_bundle(tmp_path)

    details = {finding.detail for finding in findings if finding.rule == "archive-limit"}
    assert "archive member count exceeded" in details
    assert "archive total size exceeded" in details


def test_archive_member_size_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_ARCHIVE_MEMBER_LIMIT", 4)
    (tmp_path / "oversized.zip").write_bytes(_zip_bytes("evidence.bin", b"12345"))

    findings = scanner.scan_bundle(tmp_path)

    assert any(
        finding.rule == "archive-limit" and finding.detail == "archive member size exceeded"
        for finding in findings
    )


def test_nested_unsafe_windows_member_path_is_rejected(tmp_path):
    inner = _zip_bytes(r"..\answer.txt", b"player data")
    (tmp_path / "outer.zip").write_bytes(_zip_bytes("inner.zip", inner))

    findings = scanner.scan_bundle(tmp_path)

    assert any(
        finding.rule == "archive-path" and finding.path.endswith(r"!/..\answer.txt")
        for finding in findings
    )
