"""Configuration loading: YAML files under config/ + .env overrides.

Exposes a cached ``get_config()`` returning a typed ``AppConfig``.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator

# A source checkout keeps assets at the repository root. Built wheels include
# the same directories under ``midnight/_assets`` so installed CLI runs do not
# depend on the caller's current working directory.
_SOURCE_ROOT = Path(__file__).resolve().parents[2]
_PACKAGED_ROOT = Path(__file__).resolve().parent / "_assets"
PROJECT_ROOT = _SOURCE_ROOT if (_SOURCE_ROOT / "config").is_dir() else _PACKAGED_ROOT
CONFIG_DIR = PROJECT_ROOT / "config"


class ModelSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str | None = None
    model: str | None = None
    temperature: float = 0.0
    max_tokens: int = 4096


class ProviderSpec(BaseModel):
    """Connection and tool-protocol policy for one model provider."""

    model_config = ConfigDict(extra="forbid")

    adapter: Literal["openai_compatible", "langchain"]
    model: str
    model_env: str | None = None
    api_key_env: str | None = None
    base_url: str | None = None
    base_url_env: str | None = None
    langchain_provider: str | None = None
    connect_timeout: float = 10.0
    timeout: float = 60.0
    max_retries: int = 0
    tool_mode: Literal["native", "json_protocol"] = "native"
    require_https: bool = True
    network_mode: Literal["environment", "direct_ipv4"] = "environment"


class ImageSpec(BaseModel):
    image: str
    dockerfile: str
    platform: str = "linux/amd64"
    network: str = "none"
    cap_add: list[str] = Field(default_factory=list)


class SandboxProfile(BaseModel):
    """Executable and Python-module contract for one specialist sandbox."""

    model_config = ConfigDict(extra="forbid")

    required_commands: list[str] = Field(default_factory=list)
    required_python_modules: list[str] = Field(default_factory=list)
    optional_commands: list[str] = Field(default_factory=list)

    @field_validator("required_commands", "optional_commands")
    @classmethod
    def validate_commands(cls, values: list[str]) -> list[str]:
        import re

        if any(not re.fullmatch(r"[A-Za-z0-9_.+-]+", value) for value in values):
            raise ValueError("sandbox commands must be plain executable names")
        return values

    @field_validator("required_python_modules")
    @classmethod
    def validate_modules(cls, values: list[str]) -> list[str]:
        import re

        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value) for value in values):
            raise ValueError("sandbox modules must be importable Python names")
        return values


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
    relay_image: str = "alpine/socat:1.8.0.3"


class AppConfig(BaseModel):
    active_provider: str
    providers: dict[str, ProviderSpec]
    models: dict[str, ModelSpec]
    images: dict[str, ImageSpec]
    sandbox_profiles: dict[str, SandboxProfile] = Field(default_factory=dict)
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
        "MIDNIGHT_SPECIALIST_STEP_LIMIT": ("specialist_step_limit", int),
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
    env_file = Path(os.environ.get("MIDNIGHT_ENV_FILE", _SOURCE_ROOT / ".env")).resolve()
    if env_file.is_file():
        load_dotenv(env_file, override=False)
    # allow overriding the models file (e.g. stub for smoke tests)
    models_file = os.environ.get("MIDNIGHT_MODELS_FILE", "models.yaml")
    models_raw = _load_yaml(models_file) or {}
    providers_raw = _load_yaml("providers.yaml") or {}
    images_raw = _load_yaml("images.yaml") or {}
    sandbox_profiles_raw = _load_yaml("sandbox_profiles.yaml") or {}
    tools_raw = _load_yaml("tools.yaml") or {}
    settings_raw = _load_yaml("settings.yaml") or {}

    return AppConfig(
        active_provider=os.environ.get("MIDNIGHT_MODEL_PROVIDER")
        or providers_raw.get("active_provider", ""),
        providers={
            key: ProviderSpec(**value)
            for key, value in (providers_raw.get("providers") or {}).items()
        },
        models={k: ModelSpec(**v) for k, v in models_raw.items()},
        images={k: ImageSpec(**v) for k, v in images_raw.items()},
        sandbox_profiles={
            key: SandboxProfile(**value) for key, value in sandbox_profiles_raw.items()
        },
        tools=_flatten_tools(tools_raw),
        settings=_apply_env_overrides(Settings(**settings_raw)),
    )


def model_spec_for(role: str, *, config: AppConfig | None = None) -> ModelSpec:
    """Return the ModelSpec for a role, falling back to 'default'."""
    cfg = config or get_config()
    return cfg.models.get(role) or cfg.models["default"]


def provider_spec_for(
    provider_id: str | None, *, config: AppConfig | None = None
) -> tuple[str, ProviderSpec]:
    """Resolve an explicit provider or the configured default provider."""
    cfg = config or get_config()
    selected = provider_id or cfg.active_provider
    if not selected:
        raise RuntimeError("MODEL_PROVIDER_NOT_CONFIGURED")
    try:
        return selected, cfg.providers[selected]
    except KeyError as exc:
        raise RuntimeError(f"MODEL_PROVIDER_UNKNOWN:{selected}") from exc


def effective_model_id(role: str, *, config: AppConfig | None = None) -> str:
    """Return the non-secret provider/model identifier bound to a role."""
    cfg = config or get_config()
    spec = model_spec_for(role, config=cfg)
    if spec.model and spec.model.startswith("stub:"):
        return spec.model
    provider_id, provider = provider_spec_for(spec.provider, config=cfg)
    universal_model = (
        os.environ.get("MIDNIGHT_LLM_MODEL", "").strip()
        if provider.adapter == "openai_compatible"
        else ""
    )
    env_model = os.environ.get(provider.model_env, "").strip() if provider.model_env else ""
    model = universal_model or env_model or (spec.model or provider.model).strip()
    if not model:
        raise RuntimeError("MODEL_CONFIGURATION_EMPTY")
    return f"{provider_id}:{model}"
