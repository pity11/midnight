# Midnight Evaluation Protocol

Midnight separates software correctness from CTF solving capability. A local
platform test can prove that challenge discovery, attachment handling,
submission, recovery, and cleanup work; it cannot establish that the solver is
competitive.

## Evaluation ladder

| Level | Suite | Purpose |
|---|---|---|
| E0 | Local fixtures and local CTFd | Infrastructure and recovery correctness |
| B1 | CTFTiny and a 12-task Cybench smoke subset | Fast regression and ablation screening |
| B2 | Cybench 40 and NYU CTF Bench 200 | Comparable public calibration |
| B3 | TribeCTF 2025 and BSidesSF 2026 replay | Recent real-competition capability |
| B4 | Selected DEF CON CTF 2026 replay tasks | Long-horizon and hard-tail stress testing |
| B5 | 20-30 fresh private challenges | Blind generalization evidence |

Tsecbench remains an external evaluation entry point. Its hosted Cybench is a
standardized B2 run, Tsecbench v1 is a closed-book robustness test, and its XBOW
suite is a Web-specialist test. Tsecbench scores are reported separately because
its offensive-security task distribution does not match a six-category CTF.

Public suites are calibration evidence. B3, B4, and especially B5 carry the
main capability claim. No aggregate "Midnight score" may combine engineering
fixtures with challenge solves.

The first evaluation release uses single-category challenges across Pwn,
Reverse, Web, Crypto, Forensics, and Misc. Mixed-category challenges are
deferred until category routing and per-specialist baselines are stable. They
will later form a separate cross-specialist evaluation and will not be inserted
retroactively into an existing suite version.

## Tracks

### Standard

- 30 minutes per challenge.
- One fresh container and one fresh model context per attempt.
- Five independent attempts for reported core results when budget permits;
  three attempts are acceptable during development.
- Internet disabled. Only evaluator-declared challenge targets are reachable.
- Report `success@1`, `success-in-3`, empirical solve probability, and a 95%
  confidence interval.

### Long horizon

- Two to four hours per selected hard challenge.
- The same network and isolation rules as Standard.
- Checkpointing and context compression remain enabled within an attempt.
- No state, trajectory, or rejected candidate crosses attempt boundaries.

### Open world

This optional track permits public Internet access only for fresh or private
challenges. Results are never compared directly with the closed-book tracks.

## Contamination controls

The benchmark repository is evaluator-side material. Before a run, a staging
step creates a clean challenge bundle containing only:

- the challenge statement;
- player-visible attachments or source;
- the declared target address; and
- the public flag format, when provided by the event.

Solutions, flags, graders, metadata containing answers, write-ups, organizer
notes, and repository history remain outside the agent sandbox. The solver
container never receives the benchmark repository, platform credentials, or the
platform control-plane base URL.

Every staged bundle receives a content hash. Reports record this hash and the
upstream repository revision so a result can be reproduced without disclosing
answers. Private holdout material must be stored outside this repository.

### Staging pipeline

```text
upstream benchmark
  -> pinned source snapshot
  -> allowlist-based extraction
  -> contamination scan
  -> clean immutable bundle
  -> isolated agent execution
  -> evaluator-side grading
  -> metrics and trace export
```

Extraction is allowlist based. A task adapter must explicitly identify every
player-visible file; the stager does not copy an upstream challenge directory
and then try to delete known secret files. Symlinks, path traversal, files
outside the declared challenge root, device files, and archives that expand
outside their destination are rejected.

After extraction, the stager scans filenames and text content for generic and
suite-specific leakage indicators, including flag patterns, `solution`,
`writeup`, `answer`, `grader`, and `expected_flag`. It also inspects Dockerfiles,
compose files, test scripts, environment templates, and recursively unpacked
archives within configured size limits. A match blocks the task until an
evaluator reviews or explicitly suppresses that exact finding.

The scan is defense in depth. Passing it does not make a bundle trusted; trust
comes from the player-visible allowlist and the separation between the staging,
solver, and evaluator environments.

### Immutable manifests

Each clean task bundle contains a public manifest similar to:

```yaml
schema_version: 1
suite: cybench
suite_version: 2026-09-08.1
upstream_revision: <commit>
challenge_id: <stable-id>
category: pwn
bundle_sha256: <canonical-bundle-hash>
created_at: <utc-timestamp>
internet_policy: disabled
allowed_targets: []
agent_visible:
  - statement.md
  - files/chall
excluded_classes:
  - flag
  - solution
  - writeup
  - grader
```

The evaluator stores a separate private manifest for answers, graders, scoring,
and secrets. The run manifest references the task manifest without copying
private values:

```yaml
schema_version: 1
suite: cybench
suite_version: 2026-09-08.1
task_bundles:
  task-1: <hash>
midnight_revision: <commit>
agent_mode: midnight
models:
  default: <provider/model/version>
prompt_revision: <hash>
config_revision: <hash>
tool_image_digests:
  pwn: <oci-digest>
track: standard
attempt: 1
random_seed: 1
time_budget_seconds: 1800
token_budget: <integer-or-null>
internet_policy: disabled
task_internet_policies:
  task-1: disabled
```

For a suite containing both offline and remote tasks, the evaluation spec uses
`bundle_enforced`. The runner derives enforcement from each signed bundle and
records the per-task policy map in the run manifest. This mode rejects
open-world bundles.

Manifests are canonicalized and hashed. Published results are immutable: any
change to a task bundle, prompt, model, tool image, budget, or network policy
creates a new run identity instead of overwriting an earlier result.

## Controlled comparisons

Every release candidate is compared with a bare single-agent tool loop using:

- the same model and model parameters;
- the same container image and tool inventory;
- the same challenge bundle and target;
- the same wall-clock and model-usage budget; and
- the same number of independent attempts.

Midnight is then evaluated with individual features disabled: specialist
routing, cross-specialist help, persistent memory/checkpoints, context
compression, and retry policy. This distinguishes model and tool-environment
gains from orchestration gains.

For forensic regressions, also compare whole-task `read_file`/`write_file`
counts and input tokens. The runtime suppresses unchanged covered read ranges,
unchanged writes, and evidence-free forensic rewrites; evaluation review remains
limited to tool names/counts, errors, usage, and submission status. Workspace
read/write ledgers and normalized evidence are private run artifacts and are not
published with reports.

For Pwn regressions, compare locally and target-verified script versions by hash,
execution status, repeated unchanged executions, and time to new evidence. The
private `pwn-executions.jsonl` record redacts flag-shaped output and is injected
into retry memory as a bounded failure history; it is never copied into the
published evaluation report.

The CUC JSON-protocol roles use bounded per-response generation limits: 512
tokens for classification, 1024 for the default/preflight role, and 1536 for
specialists. These limits are part of the immutable configuration revision and
must remain identical across controlled comparisons.
When a specialist exhausts its bounded transport retry, the graph records a
normalized transient model error and advances through the ordinary bounded
specialist retry path instead of failing the entire task immediately.

## Required measurements

Each run records:

- suite, upstream revision, challenge bundle hash, track, and attempt number;
- model identifier and role mapping;
- solved flags, available flags, points, and category;
- wall-clock time and time to first accepted flag;
- model tokens and cost when the provider exposes them;
- tool calls, repeated invalid commands, and rejected submissions;
- timeout, environment failure, and recovery status; and
- the effective container image and tool manifest.

Flag values, benchmark answers, API tokens, and private challenge content are
never written to reports.

## Execution order

1. Run E0 on every runtime or platform-adapter change.
2. Run B1 while tuning prompts, routing, memory, tools, and retry behavior.
3. Run full Cybench 40 and the bare-agent control.
4. Replay TribeCTF 2025, including its separately hosted remote tasks.
5. Replay BSidesSF 2026 as the primary recent public competition set.
6. Use NYU development tasks for controlled experiments, freeze the system,
   and then run the public 200-task test set.
7. Run selected hard recent tasks under both Standard and Long-horizon tracks.
8. Run the private holdout once for a release decision. Do not tune on it.

## Release gates

The evaluation pipeline is introduced through four gates:

1. **Trust gate:** staging is allowlist based, leakage scans pass, bundle hashes
   are reproducible, and the solver cannot read evaluator-only files.
2. **Reproducibility gate:** an interrupted run resumes within the same attempt,
   while a new attempt receives no previous state. Re-running a manifest
   reconstructs the same task bundle and runtime configuration.
3. **Measurement gate:** the report contains the required identifiers, outcomes,
   timing, model usage, tool activity, and failure classifications without raw
   flags or credentials.
4. **Capability gate:** Midnight and the bare control complete B2 under matched
   budgets before B3/B4 results are used for claims. A release capability claim
   requires B3 evidence and an untouched B5 evaluation.

Tsecbench results may satisfy part of B2 or provide an additional closed-book
result, but they remain a separate scorecard because task definitions, platform
availability, and scoring are controlled externally.

## Private holdout construction

The initial B5 set contains 20-30 new tasks and covers all six categories. Its
target distribution is approximately 15% easy, 35% medium, 35% hard, and 15%
very hard, adjusted when pilot human solves show that organizer labels are
miscalibrated. Difficulty is based on blinded human solve evidence, not only the
author's estimate.

Holdout authors and evaluators do not expose task content to Agent developers.
The set is versioned and retired after use for prompt or system tuning. Reused
tasks become public calibration tasks in later evaluations. Mixed-category
tasks are optional in the first private set and are reported separately if
included.

## Dataset notes

- Cybench contains Crypto, Web, Reverse, Forensics, Misc, and Pwn tasks.
- TribeCTF 2025 provides 18 tasks in an NYU-agent-compatible layout; three
  remote challenges require their services to be launched separately.
- The BSidesSF release contains the challenges and containers used in the
  March 2026 competition, along with solutions where available. Its repository
  therefore must be staged with the contamination controls above.
- Public test splits are held out from Midnight development by convention, but
  are not described as unseen or blind because their tasks and write-ups may be
  present in model training data.
