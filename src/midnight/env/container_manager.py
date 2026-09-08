"""Container lifecycle manager (Docker CLI via asyncio subprocess).

Process-level manager: ensures images/networks exist, starts per-challenge
containers with resource/capability limits, and tracks created containers for
guaranteed cleanup.
"""

from __future__ import annotations

import asyncio
import platform as _platform
import re
from dataclasses import dataclass, field

from midnight.config import AppConfig, get_config
from midnight.env.images import image_for
from midnight.state import ChallengeType
from midnight.utils.logging import get_logger

log = get_logger(__name__)

# map docker platform string -> python machine() values
_ARCH_ALIASES = {
    "linux/amd64": {"x86_64", "amd64"},
    "linux/arm64": {"aarch64", "arm64"},
}


def _host_needs_platform(target_platform: str) -> bool:
    """True if the image's target platform differs from the host arch.

    On a matching host we omit --platform on `docker run` so docker doesn't try
    to resolve a (non-existent) multi-arch local manifest.
    """
    host = _platform.machine().lower()
    matches = _ARCH_ALIASES.get(target_platform, set())
    return host not in matches


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


async def _run(*args: str, timeout: int | None = None) -> ExecResult:
    """Run a docker CLI command, capturing stdout/stderr."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return ExecResult(124, "", f"timeout after {timeout}s")
    return ExecResult(
        proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
    )


@dataclass
class ContainerManager:
    """Manages images, networks and the set of live containers."""

    config: AppConfig = field(default_factory=get_config)
    run_id: str = "local"
    _containers: set[str] = field(default_factory=set)
    _networks: set[str] = field(default_factory=set)

    def container_name(self, challenge_id: str) -> str:
        safe_run = re.sub(r"[^a-zA-Z0-9_.-]", "-", self.run_id)[:24]
        safe_challenge = re.sub(r"[^a-zA-Z0-9_.-]", "-", challenge_id)[:32]
        return f"midnight-{safe_run}-{safe_challenge}".lower()

    async def is_running(self, container_id_or_name: str | None) -> bool:
        if not container_id_or_name:
            return False
        result = await _run(
            "docker",
            "inspect",
            "--format",
            "{{.State.Running}}",
            container_id_or_name,
            timeout=10,
        )
        return result.ok and result.stdout.strip().lower() == "true"

    async def ensure_network(self, name: str = "ctfnet") -> str:
        if name in self._networks:
            return name
        res = await _run("docker", "network", "inspect", name)
        if not res.ok:
            await _run("docker", "network", "create", name)
        self._networks.add(name)
        return name

    async def ensure_image(self, ctype: ChallengeType) -> str:
        """Ensure the image for ``ctype`` exists locally, building if needed."""
        spec = image_for(ctype, config=self.config)
        # already present?
        res = await _run("docker", "image", "inspect", spec.image)
        if res.ok:
            return spec.image
        # build from the Dockerfile (build context = project root)
        from midnight.config import PROJECT_ROOT

        log.info("building image %s from %s ...", spec.image, spec.dockerfile)
        build_args = [
            "docker",
            "build",
            "-t",
            spec.image,
            "-f",
            str(PROJECT_ROOT / spec.dockerfile),
        ]
        if _host_needs_platform(spec.platform):
            build_args += ["--platform", spec.platform]
        build_args.append(str(PROJECT_ROOT))
        build = await _run(*build_args, timeout=1800)
        if not build.ok:
            raise RuntimeError(f"image build failed for {spec.image}:\n{build.stderr[-2000:]}")
        return spec.image

    async def create(self, ctype: ChallengeType, name: str) -> str:
        """Start a container for ``ctype`` and return its id.

        Issues ``docker run -d`` with platform / network / cap / resource flags
        derived from ImageSpec + settings.
        """
        spec = image_for(ctype, config=self.config)
        await self.ensure_image(ctype)

        s = self.config.settings
        args = [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--memory",
            s.container_memory,
            "--cpus",
            s.container_cpus,
            "--pids-limit",
            str(s.container_pids_limit),
            "--cap-drop",
            "ALL",
            "--label",
            "midnight.managed=true",
            "--label",
            f"midnight.run_id={self.run_id}",
        ]
        # Only pin platform when it differs from the host (e.g. amd64 image on
        # an arm host). On a native-arch host, passing --platform can make
        # docker try to pull a non-existent multi-arch local image.
        if _host_needs_platform(spec.platform):
            args += ["--platform", spec.platform]
        for cap in spec.cap_add:
            args += ["--cap-add", cap]
        if spec.network == "none":
            args += ["--network", "none"]
        elif spec.network:
            await self.ensure_network(spec.network)
            args += ["--network", spec.network]
        # workdir + keep-alive entrypoint comes from the image CMD (sleep infinity)
        args += [spec.image]

        res = await _run(*args)
        if not res.ok:
            raise RuntimeError(f"docker run failed:\n{res.stderr}")
        cid = res.stdout.strip()
        self._containers.add(cid)
        # ensure workdir exists
        await _run("docker", "exec", cid, "mkdir", "-p", s.workdir)
        return cid

    async def stop(self, container_id: str) -> None:
        await _run("docker", "rm", "-f", container_id)
        self._containers.discard(container_id)

    async def cleanup_all(self) -> None:
        for cid in list(self._containers):
            await self.stop(cid)

    async def cleanup_run(self) -> int:
        """Remove orphaned managed containers belonging to this run ID."""
        listed = await _run(
            "docker",
            "ps",
            "-aq",
            "--filter",
            "label=midnight.managed=true",
            "--filter",
            f"label=midnight.run_id={self.run_id}",
            timeout=30,
        )
        if not listed.ok:
            raise RuntimeError(f"failed to list run containers: {listed.stderr.strip()}")
        container_ids = [line for line in listed.stdout.splitlines() if line]
        for container_id in container_ids:
            await self.stop(container_id)
        return len(container_ids)
