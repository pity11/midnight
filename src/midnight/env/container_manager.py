"""Container lifecycle manager (Docker CLI via asyncio subprocess).

Process-level manager: ensures images/networks exist, starts per-challenge
containers with resource/capability limits, and tracks created containers for
guaranteed cleanup.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import platform as _platform
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

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


def _docker_build_proxy(value: str) -> str:
    """Translate a host-loopback proxy into an address visible to Docker."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.port is None:
        raise ValueError("MIDNIGHT_BUILD_PROXY must be an http(s) URL with an explicit port")
    if parsed.username or parsed.password:
        raise ValueError("authenticated build proxy URLs are not accepted on the command line")
    hostname = parsed.hostname
    if hostname in {"127.0.0.1", "localhost", "::1"}:
        hostname = "host.docker.internal"
    return urlunsplit((parsed.scheme, f"{hostname}:{parsed.port}", "", "", ""))


def _apt_mirror(value: str) -> str:
    """Validate an unauthenticated Ubuntu repository base URL."""
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("MIDNIGHT_APT_MIRROR must be a plain http(s) repository URL")
    return value.rstrip("/")


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
    except asyncio.CancelledError:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except TimeoutError:
            proc.kill()
            await proc.wait()
        raise
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
    _owned_networks: set[str] = field(default_factory=set)

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

    async def ensure_target_network(self) -> str:
        safe_run = re.sub(r"[^a-zA-Z0-9_.-]", "-", self.run_id)[:32].lower()
        name = f"midnight-{safe_run}-targets"
        result = await _run("docker", "network", "inspect", name)
        if not result.ok:
            created = await _run("docker", "network", "create", "--internal", name)
            if not created.ok:
                raise RuntimeError(f"could not create target-only network: {created.stderr.strip()}")
        self._networks.add(name)
        self._owned_networks.add(name)
        return name

    async def ensure_relay_image(self) -> str:
        image = self.config.settings.relay_image
        inspected = await _run("docker", "image", "inspect", image, timeout=30)
        if not inspected.ok:
            pulled = await _run("docker", "pull", image, timeout=600)
            if not pulled.ok:
                raise RuntimeError(f"could not pull target relay image {image}: {pulled.stderr.strip()}")
        return image

    async def relay_image_digest(self) -> str:
        image = await self.ensure_relay_image()
        result = await _run("docker", "image", "inspect", "--format", "{{.Id}}", image, timeout=30)
        if not result.ok or not result.stdout.strip().startswith("sha256:"):
            raise RuntimeError(f"could not resolve relay image digest: {result.stderr.strip()}")
        return result.stdout.strip()

    async def prepare_target_relay(self, target: str) -> str:
        """Expose exactly one external TCP target to the internal solver network."""
        try:
            host, raw_port = target.rsplit(":", 1)
            port = int(raw_port)
        except ValueError as exc:
            raise ValueError(f"target must use host:port form: {target!r}") from exc
        if not host or not (1 <= port <= 65535):
            raise ValueError(f"invalid target: {target!r}")
        network = await self.ensure_target_network()
        image = await self.ensure_relay_image()
        suffix = hashlib.sha256(target.encode()).hexdigest()[:10]
        alias = f"target-{suffix}"
        name = self.container_name(f"relay-{suffix}")
        await self.stop(name)
        started = await _run(
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--network",
            "bridge",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--label",
            "midnight.managed=true",
            "--label",
            f"midnight.run_id={self.run_id}",
            image,
            "-dd",
            f"TCP-LISTEN:{port},fork,reuseaddr",
            f"TCP:{host}:{port}",
        )
        if not started.ok:
            raise RuntimeError(f"target relay failed to start: {started.stderr.strip()}")
        relay_id = started.stdout.strip()
        self._containers.add(relay_id)
        connected = await _run(
            "docker", "network", "connect", "--alias", alias, network, relay_id
        )
        if not connected.ok:
            await self.stop(relay_id)
            raise RuntimeError(f"target relay network attach failed: {connected.stderr.strip()}")
        return f"{alias}:{port}"

    async def ensure_image(self, ctype: ChallengeType) -> str:
        """Ensure the image for ``ctype`` exists locally, building if needed."""
        spec = image_for(ctype, config=self.config)
        from midnight.config import PROJECT_ROOT

        dockerfile = PROJECT_ROOT / spec.dockerfile
        source_digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
        res = await _run(
            "docker",
            "image",
            "inspect",
            "--format",
            '{{ index .Config.Labels "midnight.dockerfile_sha256" }}',
            spec.image,
        )
        if res.ok and res.stdout.strip() == source_digest:
            return spec.image
        # Build when absent or when the effective Dockerfile changed.

        log.info("building image %s from %s ...", spec.image, spec.dockerfile)
        build_args = [
            "docker",
            "build",
            "-t",
            spec.image,
            "--label",
            f"midnight.dockerfile_sha256={source_digest}",
        ]
        build_proxy = os.getenv("MIDNIGHT_BUILD_PROXY", "").strip()
        if build_proxy:
            proxy = _docker_build_proxy(build_proxy)
            build_args += ["--build-arg", f"HTTP_PROXY={proxy}"]
            build_args += ["--build-arg", f"HTTPS_PROXY={proxy}"]
        apt_mirror = os.getenv("MIDNIGHT_APT_MIRROR", "").strip()
        if apt_mirror:
            mirror = _apt_mirror(apt_mirror)
            mirror_host = urlsplit(mirror).hostname
            build_args += ["--build-arg", f"APT_MIRROR={mirror}"]
            # Domestic package mirrors are faster and more reliable when they
            # bypass the local proxy. Other build traffic still uses it.
            if build_proxy and mirror_host:
                build_args += ["--build-arg", f"NO_PROXY={mirror_host}"]
                build_args += ["--build-arg", f"no_proxy={mirror_host}"]
        build_args += ["-f", str(dockerfile)]
        if _host_needs_platform(spec.platform):
            build_args += ["--platform", spec.platform]
        build_args.append(str(PROJECT_ROOT))
        build = await _run(*build_args, timeout=1800)
        if not build.ok:
            raise RuntimeError(f"image build failed for {spec.image}:\n{build.stderr[-2000:]}")
        return spec.image

    async def image_digest(self, ctype: ChallengeType) -> str:
        """Return the immutable local Docker image ID used for a category."""
        image = await self.ensure_image(ctype)
        result = await _run("docker", "image", "inspect", "--format", "{{.Id}}", image, timeout=30)
        if not result.ok or not result.stdout.strip().startswith("sha256:"):
            raise RuntimeError(f"could not resolve image digest for {image}: {result.stderr.strip()}")
        return result.stdout.strip()

    async def create(
        self,
        ctype: ChallengeType,
        name: str,
        *,
        network_policy: str | None = None,
    ) -> str:
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
        effective_network = "none" if network_policy == "disabled" else spec.network
        if network_policy == "target_only":
            effective_network = await self.ensure_target_network()
        if effective_network == "none":
            args += ["--network", "none"]
        elif effective_network:
            await self.ensure_network(effective_network)
            args += ["--network", effective_network]
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
        for network in list(self._owned_networks):
            await _run("docker", "network", "rm", network, timeout=30)
            self._owned_networks.discard(network)

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
