"""Evaluator-side lifecycle for local benchmark target services."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from midnight.env.container_manager import (
    _DIRECT_PACKAGE_HOSTS,
    _apt_mirror,
    _docker_build_proxy,
    _host_needs_platform,
    _run,
)


class BenchmarkService(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    context: str
    dockerfile: str = "Dockerfile"
    dockerfile_override: str | None = None
    image: str
    target: str
    platform: str = "linux/amd64"

    @model_validator(mode="after")
    def validate_names(self) -> BenchmarkService:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]*", self.image):
            raise ValueError("invalid service image name")
        host, separator, raw_port = self.target.rpartition(":")
        if not separator or not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", host):
            raise ValueError("service target must use hostname:port form")
        if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
            raise ValueError("service target port is invalid")
        return self


class BenchmarkServiceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = Field(default=1, ge=1, le=1)
    suite_version: str
    repository_root: str
    network: str
    tasks: dict[str, BenchmarkService]

    @model_validator(mode="after")
    def validate_inventory(self) -> BenchmarkServiceManifest:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", self.network):
            raise ValueError("invalid benchmark service network")
        if not self.tasks:
            raise ValueError("service manifest must contain at least one task")
        targets = [service.target for service in self.tasks.values()]
        if len(targets) != len(set(targets)):
            raise ValueError("service targets must be unique")
        return self


class BenchmarkServiceManager:
    """Build and run reviewed target images on an evaluator-only network."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.manifest = BenchmarkServiceManifest.model_validate(payload)
        self.repository_root = (self.path.parent / self.manifest.repository_root).resolve()
        if not self.repository_root.is_dir():
            raise FileNotFoundError(f"service repository root not found: {self.repository_root}")
        self._image_refs: dict[str, str] = {}

    @property
    def network(self) -> str:
        return self.manifest.network

    @property
    def challenge_ids(self) -> set[str]:
        return set(self.manifest.tasks)

    @property
    def targets(self) -> dict[str, str]:
        return {
            challenge_id: service.target
            for challenge_id, service in self.manifest.tasks.items()
        }

    def _paths(self, service: BenchmarkService) -> tuple[Path, Path]:
        context = (self.repository_root / service.context).resolve()
        if not context.is_relative_to(self.repository_root) or not context.is_dir():
            raise ValueError(f"service context escapes repository root: {service.context}")
        if service.dockerfile_override:
            dockerfile = (self.path.parent / service.dockerfile_override).resolve()
            if not dockerfile.is_relative_to(self.path.parent) or not dockerfile.is_file():
                raise ValueError("service Dockerfile override escapes evaluator directory")
        else:
            dockerfile = (context / service.dockerfile).resolve()
            if not dockerfile.is_relative_to(context) or not dockerfile.is_file():
                raise ValueError(f"service Dockerfile escapes context: {service.dockerfile}")
        return context, dockerfile

    @staticmethod
    def _container_name(challenge_id: str) -> str:
        suffix = hashlib.sha256(challenge_id.encode()).hexdigest()[:12]
        return f"midnight-target-{suffix}"

    async def ensure_images(self) -> dict[str, str]:
        digests: dict[str, str] = {}
        for challenge_id, service in sorted(self.manifest.tasks.items()):
            context, dockerfile = self._paths(service)
            inspected = await _run(
                "docker", "image", "inspect", "--format", "{{.Id}}", service.image, timeout=30
            )
            digest = inspected.stdout.strip()
            if inspected.ok and digest.startswith("sha256:"):
                digests[f"_target/{challenge_id}"] = digest
                self._image_refs[challenge_id] = digest
                continue
            args = ["docker", "build", "-t", service.image]
            proxy_value = os.getenv("MIDNIGHT_BUILD_PROXY", "").strip()
            direct_hosts = set(_DIRECT_PACKAGE_HOSTS)
            if proxy_value:
                proxy = _docker_build_proxy(proxy_value)
                args += ["--build-arg", f"HTTP_PROXY={proxy}"]
                args += ["--build-arg", f"HTTPS_PROXY={proxy}"]
            mirror_value = os.getenv("MIDNIGHT_APT_MIRROR", "").strip()
            if mirror_value:
                mirror = _apt_mirror(mirror_value)
                args += ["--build-arg", f"APT_MIRROR={mirror}"]
                mirror_host = urlsplit(mirror).hostname
                if mirror_host:
                    direct_hosts.add(mirror_host)
            if proxy_value:
                no_proxy = ",".join(sorted(direct_hosts))
                args += ["--build-arg", f"NO_PROXY={no_proxy}"]
                args += ["--build-arg", f"no_proxy={no_proxy}"]
            args += ["-f", str(dockerfile)]
            if _host_needs_platform(service.platform):
                args += ["--platform", service.platform]
            args.append(str(context))
            built = await _run(*args, timeout=1800)
            if not built.ok:
                raise RuntimeError(
                    f"target image build failed for {challenge_id}:\n{built.stderr[-2000:]}"
                )
            inspected = await _run(
                "docker", "image", "inspect", "--format", "{{.Id}}", service.image, timeout=30
            )
            digest = inspected.stdout.strip()
            if not inspected.ok or not digest.startswith("sha256:"):
                raise RuntimeError(f"could not resolve target image digest for {challenge_id}")
            digests[f"_target/{challenge_id}"] = digest
            self._image_refs[challenge_id] = digest
        return digests

    async def start_all(self) -> None:
        inspected = await _run("docker", "network", "inspect", self.network, timeout=30)
        if not inspected.ok:
            created = await _run("docker", "network", "create", "--internal", self.network)
            if not created.ok:
                raise RuntimeError(f"could not create target service network: {created.stderr}")
        started: list[str] = []
        try:
            for challenge_id, service in sorted(self.manifest.tasks.items()):
                name = self._container_name(challenge_id)
                await _run("docker", "rm", "-f", name, timeout=30)
                host, _, _ = service.target.rpartition(":")
                args = [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--network",
                    self.network,
                    "--network-alias",
                    host,
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--memory",
                    "1g",
                    "--cpus",
                    "1",
                    "--label",
                    "midnight.target-service=true",
                    "--label",
                    f"midnight.suite_version={self.manifest.suite_version}",
                ]
                if _host_needs_platform(service.platform):
                    args += ["--platform", service.platform]
                image_ref = self._image_refs.get(challenge_id)
                if image_ref is None:
                    raise RuntimeError("target images must be resolved before services are started")
                args.append(image_ref)
                result = await _run(*args, timeout=60)
                if not result.ok:
                    raise RuntimeError(f"target service failed to start: {result.stderr.strip()}")
                started.append(name)
            await self._wait_until_ready()
        except Exception:
            await self.stop_all(names=started)
            raise

    async def _wait_until_ready(self) -> None:
        for challenge_id, service in sorted(self.manifest.tasks.items()):
            ready = False
            for _ in range(30):
                probe = await _run(
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    self.network,
                    "alpine/socat:1.8.0.3",
                    "-T2",
                    "-u",
                    "/dev/null",
                    f"TCP:{service.target}",
                    timeout=10,
                )
                if probe.ok:
                    ready = True
                    break
                await asyncio.sleep(1)
            if not ready:
                raise RuntimeError(f"target service did not become ready: {challenge_id}")

    async def stop_all(self, *, names: list[str] | None = None) -> None:
        selected = names or [self._container_name(item) for item in self.manifest.tasks]
        for name in selected:
            await _run("docker", "rm", "-f", name, timeout=30)
        await _run("docker", "network", "rm", self.network, timeout=30)
