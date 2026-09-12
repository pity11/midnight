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
- Fail-closed capability contracts for every category image.
- Concurrent challenge scheduling with per-task timeouts.
- Stateful wrappers for interactive tools such as GDB and network sessions.
- Bounded retries and rejected-candidate tracking.
- Range-aware file reads, duplicate-write guards, and whole-task forensic I/O budgets.
- Deterministic forensic evidence compaction; retries receive facts and open questions instead of raw tool dumps.
- Hash-addressed Pwn execution history; unchanged local/target exploits are bounded across retries.
- Platform-neutral provider and submission interfaces.
- A configurable JSON-over-HTTP competition adapter.
- A dedicated organizer adapter for query, reset, attachment, and answer APIs.
- SQLite graph checkpoints and a durable, flag-redacted submission ledger.
- Durable per-run challenge workspaces for container restart recovery.
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
uv run midnight --check-model
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight --check-sandboxes
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight --list-only
MIDNIGHT_MODELS_FILE=models.stub.yaml uv run midnight --id sanity_misc --run-id smoke-1
```

Cloud model credentials are optional when using the bundled stub configuration.
The default live provider accepts venue-supplied OpenAI-compatible settings from
`MIDNIGHT_LLM_API_KEY`, `MIDNIGHT_LLM_BASE_URL`, and `MIDNIGHT_LLM_MODEL`, using
a strict JSON tool-action protocol. The previously tested `CUC_*` variables and
reviewed defaults remain backward-compatible fallbacks. Set `MIDNIGHT_ENV_FILE`
to reuse an existing protected environment file without copying credentials.
Keep real credentials in `.env`; the file is excluded from version control.

The short operational procedure used before a live competition is documented in
[docs/competition-mvp.md](docs/competition-mvp.md).
For a clean-clone installation and the exact offline competition-day sequence,
see the [Chinese startup guide](docs/competition-startup-cn.md).
The mapping from organizer challenge labels to specialist tools and sandboxes is
documented in [competition-routing.md](docs/competition-routing.md).
The latest frozen-build evidence is recorded in
[docs/readiness-2026-09-10.md](docs/readiness-2026-09-10.md).
Windows teammates should use the dedicated
[PowerShell deployment and competition guide](docs/competition-startup-windows-cn.md),
which provides setup, preflight, rehearsal, monitoring, and round commands without
requiring Bash or WSL command-line use.

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
- [x] Offline sandbox capability preflight
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

Each challenge also receives a revision-scoped directory below
`logs/workspaces/`, mounted at `/ctf`. Solver artifacts and `evidence.jsonl`
survive container recreation while remaining isolated from changed task content
and independent evaluation attempts.

## Competition platform adapter

Copy `config/platform.ichunqiu.example.yaml` to the ignored local configuration,
then fill in the base URL and three endpoint paths from the organizer document.
Keep the team token in `.env`; the dedicated adapter sends it only from the
controller and suppresses HTTP client URL logs because the API uses a query
parameter credential:

```bash
cp config/platform.ichunqiu.example.yaml config/platform.local.yaml
# Edit config/platform.local.yaml, then set MIDNIGHT_PLATFORM_TOKEN in .env.
scripts/competition platform-preflight
scripts/competition dry-run ORGANIZER_TEST_CHALLENGE_ID
```

Discovery never resets a target or submits an answer. Starting an interactive
challenge calls the reset API and waits for its connection information; static
challenges skip reset. Platform submission remains disabled unless `--submit`
is present. The public example deliberately contains no event endpoint or team
credential.

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

The bundled CUC model provider uses `network_mode: direct_ipv4`. This keeps
model requests on IPv4-only campus VPN routes and ignores inherited shell proxy
variables for that provider; other providers retain normal environment-based
network selection.

If the proxy has unreliable access to Ubuntu's default archive, select a
compatible mirror for package installation:

```bash
export MIDNIGHT_APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/ubuntu
```

Use an HTTP mirror during the bootstrap layer because the minimal Ubuntu base
does not contain the CA certificate bundle until that layer installs it. When
both settings are present, the configured mirror and other external build
downloads use the proxy; official fallback package hosts remain in `NO_PROXY`.

Before a competition or formal benchmark, validate every category image without
running a challenge:

```bash
uv run midnight --check-sandboxes
```

This command builds stale images, starts each image with networking disabled,
and verifies the required executables and Python modules declared in
`config/sandbox_profiles.yaml`. A missing tool fails the preflight.

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

The competition CUC provider uses one bounded transport retry so a single
gateway timeout does not discard an otherwise healthy challenge run. If the
request still fails, the report recovers redacted attempt, token, and tool
counters from the durable checkpoint instead of reporting zero activity.

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
