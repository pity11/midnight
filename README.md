# Midnight

Midnight is an autonomous CTF solver for authorized competitions and reproducible
security benchmarks. It combines category routing, specialist workflows, isolated
execution environments, and auditable run events.

The current codebase provides a platform-neutral competition runtime. See
[ARCHITECTURE.md](ARCHITECTURE.md) for its design and implementation roadmap.
The benchmark policy and capability-claim criteria are defined in
[EVALUATION.md](EVALUATION.md).

## Features

- Specialist workflows for pwn, reverse engineering, web, cryptography, and miscellaneous tasks.
- One isolated Docker container per challenge.
- Concurrent challenge scheduling with per-task timeouts.
- Stateful wrappers for interactive tools such as GDB and network sessions.
- Bounded retries and rejected-candidate tracking.
- Platform-neutral provider and submission interfaces.
- A configurable JSON-over-HTTP competition adapter.
- SQLite graph checkpoints and a durable, flag-redacted submission ledger.
- Append-only JSONL run events with credential-field redaction.
- Deterministic benchmark reports that do not persist flag values.
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
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight --id sanity_misc --run-id smoke-1
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
- [x] Persistent graph checkpoints and run recovery
- [x] Generic HTTP platform adapter
- [x] Durable submission idempotency
- [x] Reproducible benchmark runner and reports

## Run recovery

Every challenge checkpoint is namespaced by the run ID, challenge ID, and a
content-derived challenge revision. Reusing `--run-id` resumes interrupted work
without applying stale state to changed attachments:

```bash
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight \
  --run-id benchmark-001 \
  --checkpoint-path logs/checkpoints.sqlite
```

## HTTP platform adapter

Copy `config/platform.example.yaml`, then map its endpoint paths to the
competition API. The adapter keeps credentials in an environment variable,
restricts attachment downloads to the configured origin by default, and runs
with platform submission disabled unless `--submit` is present:

```bash
export MIDNIGHT_PLATFORM_TOKEN="..."
uv run midnight --platform-config config/platform.local.yaml --list-only
uv run midnight --platform-config config/platform.local.yaml --submit
```

The exact response-field mapping can be implemented as a small adapter once the
official platform contract is available. The solver, scheduler, checkpoints,
containers, reports, and submission policy do not depend on that contract.

If a runner process is terminated before its cleanup executes, remove only the
containers labeled for that run:

```bash
uv run midnight --cleanup-run benchmark-001
```

## Configuration

Runtime settings live under `config/` and can be overridden with environment
variables. Common overrides include:

```bash
MIDNIGHT_MODELS_FILE=models.stub.yaml
MIDNIGHT_MAX_CONCURRENCY=3
MIDNIGHT_PER_TASK_TIMEOUT=1800
MIDNIGHT_RECURSION_LIMIT=100
```

If image construction needs a local HTTP proxy, expose it before preflight.
Loopback addresses are translated to Docker's host gateway and are not stored
in the resulting image environment:

```bash
export MIDNIGHT_BUILD_PROXY=http://127.0.0.1:7890
```

If the proxy has unreliable access to Ubuntu's default archive, select a
compatible mirror for package installation:

```bash
export MIDNIGHT_APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/ubuntu
```

Use an HTTP mirror during the bootstrap layer because the minimal Ubuntu base
does not contain the CA certificate bundle until that layer installs it. When
both settings are present, the APT mirror bypasses the proxy while other build
downloads continue through it.

After independent attempts finish, aggregate their reports in attempt order:

```bash
uv run midnight-aggregate \
  runs/attempt-1/report.json \
  runs/attempt-2/report.json \
  runs/attempt-3/report.json \
  --output runs/aggregate.json
```

The aggregate contains `success_at_1`, `success_in_n`, mean solve probability,
and its 95% Wilson interval. It never stores submitted flag values.

Replay tasks with local servers use a separate evaluator-only service manifest:

```bash
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight \
  --bundles-dir /evaluator/bundles/core \
  --evaluator-manifest /evaluator/private/answers.json \
  --evaluation-spec /evaluator/specs/attempt-1.json \
  --service-manifest /evaluator/private/services.json
```

The manifest points to reviewed upstream Docker build contexts. Target images
run without published host ports on an internal network, and solver containers
receive access only through one allowlisted TCP relay per declared endpoint.

## Trusted benchmark bundles

Formal evaluations use allowlist-based clean bundles. The upstream repository
and evaluator answers must remain outside the bundle root:

```bash
# Audit and atomically materialize the pinned Cybench smoke suite.
uv run midnight-benchmark \
  --repository /evaluator/upstream/cybench \
  --selection config/benchmarks/cybench-core-12.json \
  --report /evaluator/reports/cybench-core-12.json \
  audit

uv run midnight-benchmark \
  --repository /evaluator/upstream/cybench \
  --selection config/benchmarks/cybench-core-12.json \
  --report /evaluator/reports/cybench-core-12.json \
  stage \
  --bundles /evaluator/bundles/cybench-core-12 \
  --evaluator-manifest /evaluator/private/cybench-core-12.json

# Stage one custom task.
uv run midnight-stage \
  --source-root /evaluator/upstream/challenge \
  --spec config/staging.example.json \
  --output /evaluator/bundles/reverse-001

MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight \
  --bundles-dir /evaluator/bundles \
  --evaluator-manifest /evaluator/private/answers.json \
  --evaluation-spec config/evaluation.example.json \
  --preflight-only
```

The runner verifies every bundle hash and file inventory before use. It derives
the run ID from the effective task bundles, Midnight revision, model mapping,
prompt and configuration hashes, Docker image IDs, budgets, network policy,
attempt, and seed. Reusing the same identity resumes that attempt; changing the
attempt creates an independent run.

Mixed offline and target-only suites use `bundle_enforced`: every task retains
its own immutable network policy, and the run manifest records the complete
task-to-policy mapping. Open-world access is rejected in this mode.

Target-only tasks place the solver on an internal Docker network and expose each
allowlisted TCP endpoint through a dedicated fixed-destination relay. The relay
image ID is included in the Run Manifest. Hard token-budget enforcement still
fails closed and must be implemented before that policy can be claimed.

Tsecbench uses its official SDK and keeps platform credentials in the controller
process. Challenge containers receive only fixed-destination relay addresses:

```bash
export BENCHMARK_BASE_URL="..."
export BENCHMARK_TOKEN="..."
uv sync --extra tsecbench
uv run midnight --tsecbench --list-only
uv run midnight --tsecbench --submit
```

## Safety and testing

Local fixtures are the default execution target. Competition-specific access is
implemented through separate adapters and explicit configuration. Offline tests
must not read production credentials or contact live competition services.

Engineering fixtures and local CTFd runs validate the runtime; they are not
reported as solving capability. Public legacy suites provide reproducible
calibration, recent competition replays test the hard tail, and fresh private
challenges provide the final blind holdout. Benchmark repositories are staged
outside the solver container so solutions, flags, graders, and write-ups cannot
enter the model context.
