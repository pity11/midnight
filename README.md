# Midnight

Midnight is an autonomous CTF solver for authorized competitions and reproducible
security benchmarks. It combines category routing, specialist workflows, isolated
execution environments, and auditable run events.

The current codebase is an early engineering prototype. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the design and implementation roadmap.

## Features

- Specialist workflows for pwn, reverse engineering, web, cryptography, and miscellaneous tasks.
- One isolated Docker container per challenge.
- Concurrent challenge scheduling with per-task timeouts.
- Stateful wrappers for interactive tools such as GDB and network sessions.
- Bounded retries and rejected-candidate tracking.
- Platform-neutral provider and submission interfaces.
- Append-only JSONL run events with credential-field redaction.
- Local fixtures and stub models for offline development.

## Requirements

- Python 3.11 or 3.12
- Docker
- [`uv`](https://docs.astral.sh/uv/)

Apple Silicon hosts may require Docker's x86/amd64 emulation support for pwn and
reverse-engineering images.

## Quick start

```bash
uv sync --extra dev
cp .env.example .env
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight --check-config
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight --list-only
```

Cloud model credentials are optional when using the bundled stub configuration.
Keep real credentials in `.env`; the file is excluded from version control.

## Project layout

```text
config/          Model, image, tool, and runtime configuration
docker/          Category-specific container images
src/midnight/    Runtime, graphs, tools, models, and platform interfaces
tests/           Offline tests and local challenge fixtures
```

## Status

- [x] Project scaffold and typed configuration
- [x] Single-challenge solve loop
- [x] Category router and specialist graphs
- [x] Isolated execution environments
- [x] Interactive tool sessions
- [x] Concurrent challenge scheduling
- [x] Bounded retry and rejected-candidate handling
- [x] Redacted append-only event journal
- [ ] Persistent graph checkpoints
- [ ] Generic HTTP platform adapter
- [ ] Reproducible benchmark runner and reports

## Configuration

Runtime settings live under `config/` and can be overridden with environment
variables. Common overrides include:

```bash
MIDNIGHT_MODELS_FILE=models.stub.yaml
MIDNIGHT_MAX_CONCURRENCY=3
MIDNIGHT_PER_TASK_TIMEOUT=1800
MIDNIGHT_RECURSION_LIMIT=100
```

## Safety and testing

Local fixtures are the default execution target. Competition-specific access is
implemented through separate adapters and explicit configuration. Offline tests
must not read production credentials or contact live competition services.
