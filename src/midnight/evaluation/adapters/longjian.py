"""Evaluator-side adapter for selected Longjian Cup 2025 finals tasks."""

from __future__ import annotations

import hashlib
import html
import re
import subprocess
from html.parser import HTMLParser
from pathlib import Path

from midnight.evaluation.provider import EvaluatorManifest, EvaluatorTask
from midnight.evaluation.stager import BenchmarkStager, StagingSpec, VisibleFile

_TASKS = {
    "which-sql": ("which_sql", "2.which_sql.zip"),
    "from-web-to-root": ("从Web到Root", "3.从Web到Root.zip"),
    "shell-decoder": ("ShellDecoder", "5.ShellDecoder.zip"),
}
_FLAG = re.compile(r"(?i)\bflag\{[^}\r\n]+\}")
_PLACEHOLDER_PAYLOAD = re.compile(r"(?i)(?:\bmd5\s*\(|\bpart\d*\b|x{3,}|\bexample\b)")


class _HeadingSections(HTMLParser):
    """Collect body text under real h3 elements, ignoring TOCs and prose mentions."""

    def __init__(self) -> None:
        super().__init__()
        self.ignored = 0
        self.heading_tag: str | None = None
        self.heading_parts: list[str] = []
        self.current_title: str | None = None
        self.current_parts: list[str] = []
        self.sections: dict[str, str] = {}

    def _finish_section(self) -> None:
        if self.current_title is not None:
            self.sections[self.current_title] = html.unescape("".join(self.current_parts))
        self.current_title = None
        self.current_parts = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style"}:
            self.ignored += 1
            return
        if self.ignored:
            return
        if tag in {"h2", "h3"}:
            self._finish_section()
            self.heading_tag = tag
            self.heading_parts = []
        elif self.current_title is not None and tag in {"br", "p", "div", "li", "pre", "code"}:
            self.current_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.ignored:
            self.ignored -= 1
            return
        if self.ignored:
            return
        if self.heading_tag == tag:
            title = " ".join(html.unescape("".join(self.heading_parts)).split())
            self.current_title = title if tag == "h3" else None
            self.current_parts = []
            self.heading_tag = None
            self.heading_parts = []
        elif self.current_title is not None and tag in {"p", "div", "li", "pre", "code"}:
            self.current_parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.ignored:
            return
        if self.heading_tag is not None:
            self.heading_parts.append(data)
        elif self.current_title is not None:
            self.current_parts.append(data)

    def close(self) -> None:
        super().close()
        self._finish_section()


class LongjianCup2025Adapter:
    """Stage public player archives and keep third-party write-ups evaluator-only."""

    def __init__(
        self,
        repository: str | Path,
        writeup: str | Path,
        *,
        upstream_revision: str,
        writeup_revision: str,
        verify_revision: bool = True,
    ):
        self.repository = Path(repository).resolve()
        self.attachments = self.repository / "attachments"
        self.readme = self.repository / "README.md"
        self.writeup = Path(writeup).resolve()
        self.upstream_revision = upstream_revision
        self.writeup_revision = writeup_revision
        if not self.attachments.is_dir() or not self.readme.is_file():
            raise FileNotFoundError("Longjian Cup release is incomplete")
        if not self.writeup.is_file():
            raise FileNotFoundError("Longjian Cup evaluator write-up is unavailable")
        if verify_revision:
            self._verify_checkout(self.repository, upstream_revision, [self.readme, self.attachments])
            self._verify_checkout(self.writeup.parent, writeup_revision, [self.writeup])
        material = hashlib.sha256()
        for path in [self.readme, *(self.attachments / item[1] for item in _TASKS.values()), self.writeup]:
            material.update(path.name.encode("utf-8"))
            material.update(b"\0")
            material.update(path.read_bytes())
        material.update(writeup_revision.encode("utf-8"))
        self.suite_version = f"{upstream_revision[:12]}+mat.{material.hexdigest()[:16]}"

    @staticmethod
    def _verify_checkout(cwd: Path, expected: str, material: list[Path]) -> None:
        root = Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=cwd,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        ).resolve()
        actual = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual != expected:
            raise ValueError(f"upstream revision differs: expected {expected}, got {actual}")
        relatives = [str(path.resolve().relative_to(root)) for path in material]
        clean = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *relatives], cwd=root, check=False
        )
        if clean.returncode:
            raise ValueError("upstream benchmark material differs from the pinned revision")

    @staticmethod
    def task_ids() -> list[str]:
        return list(_TASKS)

    def _entry(self, task_id: str) -> tuple[str, Path]:
        try:
            heading, filename = _TASKS[task_id]
        except KeyError as exc:
            raise KeyError(f"unsupported Longjian Cup task: {task_id}") from exc
        attachment = (self.attachments / filename).resolve()
        if not attachment.is_relative_to(self.attachments) or not attachment.is_file():
            raise FileNotFoundError(f"Longjian Cup attachment is unavailable: {filename}")
        return heading, attachment

    def _description(self, heading: str) -> str:
        text = self.readme.read_text(encoding="utf-8", errors="replace")
        match = re.search(
            rf"(?ms)^###\s+{re.escape(heading)}\s*$\n(.*?)(?=^###\s+|^##\s+|\Z)",
            text,
        )
        if not match:
            raise ValueError(f"Longjian Cup README has no section for {heading}")
        return f"### {heading}\n\n{match.group(1).strip()}"

    def _answer(self, task_id: str) -> str:
        heading, _ = self._entry(task_id)
        parser = _HeadingSections()
        parser.feed(self.writeup.read_text(encoding="utf-8", errors="replace"))
        parser.close()
        section = parser.sections.get(heading)
        if section is None:
            raise ValueError(f"evaluator write-up has no section for {heading}")
        candidates = []
        for value in _FLAG.findall(section):
            payload = value.split("{", 1)[1].lower()
            if _PLACEHOLDER_PAYLOAD.search(payload):
                continue
            if value not in candidates:
                candidates.append(value)
        if len(candidates) != 1:
            raise ValueError(f"evaluator write-up must yield one final flag for {heading}")
        return candidates[0]

    def staging_spec(
        self, task_id: str, *, approved_findings: list[str] | None = None
    ) -> StagingSpec:
        heading, attachment = self._entry(task_id)
        return StagingSpec(
            suite="longjian-cup-2025-finals",
            suite_version=self.suite_version,
            upstream_revision=self.upstream_revision,
            challenge_id=task_id,
            name=heading,
            description=self._description(heading),
            category="forensics",
            flag_format=r"(?i)flag\{[^}\r\n]+\}",
            internet_policy="disabled",
            visible_files=[VisibleFile(source=attachment.name, target=attachment.name)],
            approved_findings=approved_findings or [],
        )

    def stage_task(
        self,
        task_id: str,
        destination: str | Path,
        *,
        approved_findings: list[str] | None = None,
    ):
        spec = self.staging_spec(task_id, approved_findings=approved_findings)
        return BenchmarkStager(self.attachments).stage(spec, destination)

    def evaluator_manifest(self, task_ids: list[str]) -> EvaluatorManifest:
        return EvaluatorManifest(
            suite_version=self.suite_version,
            tasks={
                task_id: EvaluatorTask(expected_flags=[self._answer(task_id)])
                for task_id in task_ids
            },
        )
