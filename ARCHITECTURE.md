# Midnight Architecture

## Scope

Midnight solves authorized CTF challenges and reproducible security benchmarks.
It receives challenge text and attachments, analyzes them inside isolated
containers, produces candidate flags, obtains an oracle verdict through a
platform adapter, and exports reproducible run records. Platform credentials and
API details stay outside solver graphs.

## Runtime flow

```text
PlatformAdapter
  -> challenge refresh and attachment download
  -> content revision and SHA-256 inventory
  -> concurrent Scheduler
  -> category Classifier
  -> isolated SpecialistGraph
  -> local candidate validation
  -> durable SubmissionGate
  -> platform oracle
  -> checkpoint, event journal, benchmark report
```

Each challenge has a separate container, graph state, timeout, artifact
directory, and checkpoint thread. Pwn and reverse engineering share a lower
concurrency pool because native binary tooling and x86 emulation consume more
resources.

## State and recovery

The graph checkpoint key contains the run ID, challenge ID, and content-derived
revision. A changed statement or attachment therefore cannot inherit stale
solver state. Completed checkpoints return their previous result without
launching a container or calling the submitter again. In-progress checkpoints
resume at the next LangGraph node; a missing container is recreated and the
attachments are copied back into it.

The submission ledger reserves a candidate before a platform call. It stores a
SHA-256 digest instead of the flag value. A crash after sending a candidate but
before receiving the verdict therefore produces an intentionally uncertain
reservation and suppresses automatic duplicate submission.

## Module boundaries

| Module | Responsibility |
|---|---|
| `interfaces/` | Challenge providers, platform adapters, oracle results, submission policy |
| `orchestrator/` | Concurrency, timeouts, category resource pools, recovery |
| `graph/` | Classification, specialist routing, bounded retries, state transitions |
| `env/` | Container lifecycle, file transfer, command and interactive sessions |
| `models/` | Role-based LangChain model construction and deterministic test model |
| `tools/` | Shell, file, debugger, socket, web, binary, and expert-help tools |
| `events.py` | Append-only, credential-redacted run event journal |
| `reporting.py` | Flag-free benchmark summaries and model metadata |
| `persistence.py` | SQLite-backed LangGraph checkpoints |

## Platform contract

`ChallengeProvider` supplies listing, refreshed metadata, and attachment
downloads. `FlagSubmitter` returns a typed verdict. The generic HTTP adapter maps
common JSON APIs and can be subclassed when a competition uses different fields,
authentication, pagination, or dynamic instances.

HTTP submission is dry-run by default and requires the explicit `--submit`
switch. Tokens are read from the environment variable named in the local
platform configuration. Attachment downloads stay on the configured origin
unless explicitly allowed, enforce a byte limit, reject unsafe filenames, and
use atomic temporary files.

## Specialist topology

The classifier routes each task to a bounded specialist for pwn, reverse, web,
crypto, forensics, or misc work. Specialists use a shared tool registry but
receive category-specific prompts and tool lists. `ask_expert` permits bounded
cross-category help inside the same challenge container and rejects cyclic or
over-depth delegation. Candidate rejection feeds back into the next attempt,
with a fixed maximum attempt count.

## Engineering references

- **D-CIPHER** informs explicit planning and specialist execution boundaries.
- **EnIGMA/SWE-agent** informs stateful debugger and network-session tools.
- **BoxPwnr** informs provider adapters, benchmark reports, and trace analysis.
- **Veria ctf-agent** informs challenge-level concurrency and future optional
  model racing.
- **OpenSage** informs future structured memory and dynamic specialist research.
- **LangGraph** provides bounded state transitions and durable checkpoints.

Midnight uses these projects as design references. Their platform assumptions,
prompts, benchmark claims, and licensing are not copied into this repository.

## Current acceptance criteria

- Offline fixtures run end to end with a deterministic model and local oracle.
- Attachments are hashed and challenge revisions isolate stale checkpoints.
- Interrupted and completed runs resume without duplicate work or submission.
- Containers have CPU, memory, PID, capability, and network policies.
- Per-task timeouts and bounded retries always produce a terminal status.
- Events, reports, and the submission ledger do not persist raw flag values.
- Unit tests never load production credentials or contact a competition service.

## Planned experiments

The stable runtime is the control group for model routing, parallel candidate
racing, structured cross-agent memory, and context compression. Each experiment
must report success rate, time, model usage, incorrect submissions, and recovery
behavior on a fixed benchmark before it becomes a default feature.

Capability evaluation follows [EVALUATION.md](EVALUATION.md). In particular,
local CTFd is an infrastructure test, Cybench and NYU CTF Bench are public
calibration sets, recent competition replays are the primary public capability
evidence, and fresh private tasks are the blind holdout. Tsecbench is retained as
a standardized external evaluation provider and will receive a dedicated
adapter for challenge lifecycle, multi-target instances, and multi-flag status.
