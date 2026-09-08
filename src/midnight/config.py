"""Configuration loading: YAML files under config/ + .env overrides.

Exposes a cached ``get_config()`` returning a typed ``AppConfig``.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# A source checkout keeps assets at the repository root. Built wheels include
# the same directories under ``midnight/_assets`` so installed CLI runs do not
# depend on the caller's current working directory.
_SOURCE_ROOT = Path(__file__).resolve().parents[2]
_PACKAGED_ROOT = Path(__file__).resolve().parent / "_assets"
PROJECT_ROOT = _SOURCE_ROOT if (_SOURCE_ROOT / "config").is_dir() else _PACKAGED_ROOT
CONFIG_DIR = PROJECT_ROOT / "config"


class ModelSpec(BaseModel):
    model: str
    temperature: float = 0.0
    max_tokens: int = 4096


class ImageSpec(BaseModel):
    image: str
    dockerfile: str
    platform: str = "linux/amd64"
    network: str = "none"
    cap_add: list[str] = Field(default_factory=list)


class Settings(BaseModel):
    max_concurrency: int = 3
    pwn_max_concurrency: int = 1
    per_task_timeout: int = 1800
    recursion_limit: int = 100
    specialist_step_limit: int = 40
    helper_recursion_limit: int = 25
    escalation_max_depth: int = 2
    max_attempts: int = 3  # specialist retry/fallback attempts per challenge
    container_memory: str = "2g"
    container_cpus: str = "1.0"
    container_pids_limit: int = 256
    workdir: str = "/ctf"
    max_tool_output_chars: int = 8000
    flag_regex: str = r"[A-Za-z0-9_]+\{[^}]+\}"


class AppConfig(BaseModel):
    models: dict[str, ModelSpec]
    images: dict[str, ImageSpec]
    tools: dict[str, list[str]]
    settings: Settings


def _load_yaml(name: str) -> Any:
    path = CONFIG_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"config file missing: {path}")
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _flatten_tools(raw: dict[str, Any]) -> dict[str, list[str]]:
    """Resolve the YAML anchor expansion into flat per-expert tool lists.

    ``common`` is an anchor; experts include it as a nested list, so we flatten
    any nested lists and drop the standalone ``common`` key.
    """
    out: dict[str, list[str]] = {}
    for expert, items in raw.items():
        if expert == "common":
            continue
        flat: list[str] = []
        for item in items or []:
            if isinstance(item, list):
                flat.extend(item)
            else:
                flat.append(item)
        # de-dup while preserving order
        out[expert] = list(dict.fromkeys(flat))
    return out


def _apply_env_overrides(settings: Settings) -> Settings:
    mapping = {
        "MIDNIGHT_MAX_CONCURRENCY": ("max_concurrency", int),
        "MIDNIGHT_PER_TASK_TIMEOUT": ("per_task_timeout", int),
        "MIDNIGHT_RECURSION_LIMIT": ("recursion_limit", int),
    }
    data = settings.model_dump()
    for env_key, (field, caster) in mapping.items():
        val = os.environ.get(env_key)
        if val:
            data[field] = caster(val)
    return Settings(**data)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Load and cache the full application config."""
    # allow overriding the models file (e.g. stub for smoke tests)
    models_file = os.environ.get("MIDNIGHT_MODELS_FILE", "models.yaml")
    models_raw = _load_yaml(models_file) or {}
    images_raw = _load_yaml("images.yaml") or {}
    tools_raw = _load_yaml("tools.yaml") or {}
    settings_raw = _load_yaml("settings.yaml") or {}

    return AppConfig(
        models={k: ModelSpec(**v) for k, v in models_raw.items()},
        images={k: ImageSpec(**v) for k, v in images_raw.items()},
        tools=_flatten_tools(tools_raw),
        settings=_apply_env_overrides(Settings(**settings_raw)),
    )


def model_spec_for(role: str, *, config: AppConfig | None = None) -> ModelSpec:
    """Return the ModelSpec for a role, falling back to 'default'."""
    cfg = config or get_config()
    return cfg.models.get(role) or cfg.models["default"]
