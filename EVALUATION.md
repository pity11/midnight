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

