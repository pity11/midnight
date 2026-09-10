# Competition MVP Runbook

This runbook covers the minimum reliable workflow for a live CTF. It assumes the
competition authorizes automated solving and submissions. Keep platform tokens in
environment variables or a mode-600 `.env` file; never add them to YAML or Git.

The commands below are also wrapped by `scripts/competition`. Run
`scripts/competition --help` for the short offline checklist.

## Scope

The competition build must reliably:

1. discover and fetch challenges;
2. download attachments without flattening their directory layout;
3. classify each challenge and start its category sandbox;
4. preserve scripts, evidence, and checkpoints across retries;
5. accept only flags observed in challenge artifacts or target output;
6. submit each candidate at most once and write a redacted report;
7. isolate a failed challenge so other challenges keep running.

Advanced model racing, broad benchmark claims, and large architecture changes are
outside the competition freeze.

## Before platform details arrive

Run the local checks from the repository root:

```bash
uv run midnight --check-config
uv run midnight --check-model
uv run midnight --check-sandboxes
uv run pytest -q
```

After the local environment has been installed, the equivalent competition-day
check avoids package resolution and uses the existing virtual environment:

```bash
scripts/competition local-preflight
```

`--check-model` makes one structured request and prints only the configured model
identifier. It does not print credentials or execute a solver tool.

## Platform integration

Copy the dedicated organizer template to an ignored local path. Fill in the base
URL and the query, reset, and submit paths from the interface document. Put the
team token in `.env`; never place it in YAML or a shell history entry.

```bash
cp config/platform.ichunqiu.example.yaml config/platform.local.yaml
chmod 600 .env
# Edit MIDNIGHT_PLATFORM_TOKEN in .env.
```

The adapter maps the platform contract as follows:

- the query endpoint supplies both the challenge inventory and current target
  connection data;
- solved challenges are skipped by default;
- static challenges are downloaded without an environment reset;
- interactive challenges are reset once and polled until a Pwn or Web target is
  available;
- an empty attachment URL is valid, and a supplied URL is streamed with a size
  limit;
- answers use the platform submit endpoint and are sent only with `--submit`;
- a candidate from a newly reset instance is retried once after 30 seconds when
  the answer oracle initially reports a rejection, covering observed instance
  synchronization delay;
- cleanup is local because the contract does not expose a stop endpoint.

First perform a read-only discovery pass. Omit `--submit`:

```bash
scripts/competition platform-preflight
```

Then solve one known test challenge while submissions remain disabled:

```bash
scripts/competition dry-run TEST_CHALLENGE_ID
```

Inspect `logs/events.jsonl` and `logs/report.json`. Events and reports redact flag
values and credential-shaped fields.

The platform carries the credential in a URL query parameter. Midnight suppresses
HTTPX request URL logging, and all shipped configuration keeps the real endpoint
paths and token in ignored local files.

## Submission rehearsal

Enable submission only for an organizer-provided test challenge:

```bash
scripts/competition submit-test TEST_CHALLENGE_ID
```

Use a fresh run ID when intentionally repeating the full solve and platform
submission path. Reusing an ID correctly resumes its checkpoint and suppresses
duplicate local submissions:

```bash
MIDNIGHT_RUN_ID=rehearsal-1 scripts/competition submit-test TEST_CHALLENGE_ID
scripts/competition monitor rehearsal-1
```

Confirm that the platform accepts the flag and that rerunning the same command
does not duplicate the submission.

## Competition command

Start conservatively on Apple Silicon because pwn and reverse images use amd64
emulation:

```bash
scripts/competition round2
```

For the third stage use `scripts/competition round3`. The expanded command run by
the wrapper is:

```bash
uv run midnight \
  --platform-config config/platform.local.yaml \
  --run-id competition-1 \
  --submit \
  --max-concurrency 2 \
  --task-timeout 1800 \
  --run-timeout 1620 \
  --events-path logs/competition-1/events.jsonl \
  --checkpoint-path logs/competition-1/checkpoints.sqlite \
  --submission-ledger-path logs/competition-1/submissions.sqlite \
  --artifacts-root logs/competition-1/artifacts \
  --workspace-root logs/competition-1/workspaces \
  --report-path logs/competition-1/report.json
```

`--run-timeout 1620` reserves the final three minutes of a 30-minute challenge
window for in-flight platform submissions and operational inspection. Every
challenge receives the same deadline, including tasks waiting for a worker slot.
Organizer-labelled easy tasks are scheduled first.

The wrapper also passes `--wait-for-challenges 300`, so a short organizer-side
publication delay does not make an unattended round exit. Challenge discovery is
retried every five seconds for at most five minutes, including transient query or
DNS failures; this wait happens before the 27-minute solving budget starts. On
macOS the wrapper launches the process under `caffeinate` to keep the laptop and
disks awake for the duration of the round.

Reuse the same run ID and paths after an interruption. Midnight resumes compatible
challenge revisions from checkpoints. If the platform changes a challenge, its
content-derived revision creates a separate workspace and checkpoint identity.

Increase concurrency only after observing stable CPU, memory, Docker, model rate
limits, and platform rate limits. Keep pwn/reverse concurrency at one unless the
host has been tested under amd64 emulation.

## Freeze rule

After the platform submission rehearsal succeeds, accept only fixes for crashes,
incorrect platform mappings, broken attachments, invalid model actions, or leaked
containers. Record each fix in Git and rerun the smallest affected check. Avoid
changing prompts, tool schemas, or orchestration during the final rehearsal day.
