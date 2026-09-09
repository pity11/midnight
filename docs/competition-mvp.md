# Competition MVP Runbook

This runbook covers the minimum reliable workflow for a live CTF. It assumes the
competition authorizes automated solving and submissions. Keep platform tokens in
environment variables or a mode-600 `.env` file; never add them to YAML or Git.

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

`--check-model` makes one structured request and prints only the configured model
identifier. It does not print credentials or execute a solver tool.

## Platform integration

Copy `config/platform.example.yaml` to an ignored local path and adapt only the
base URL, endpoint paths, and authentication header. Put the token in the
environment variable named by `token_env`.

First perform a read-only discovery pass. Omit `--submit`:

```bash
uv run midnight \
  --platform-config config/platform.local.yaml \
  --list-only
```

Then solve one known test challenge while submissions remain disabled:

```bash
uv run midnight \
  --platform-config config/platform.local.yaml \
  --id TEST_CHALLENGE_ID \
  --run-id platform-dry-run-1 \
  --max-concurrency 1 \
  --task-timeout 900
```

Inspect `logs/events.jsonl` and `logs/report.json`. Events and reports redact flag
values and credential-shaped fields.

## Submission rehearsal

Enable submission only for an organizer-provided test challenge:

```bash
uv run midnight \
  --platform-config config/platform.local.yaml \
  --id TEST_CHALLENGE_ID \
  --run-id platform-submit-test-1 \
  --submit \
  --max-concurrency 1 \
  --task-timeout 900
```

Confirm that the platform accepts the flag and that rerunning the same command
does not duplicate the submission.

## Competition command

Start conservatively on Apple Silicon because pwn and reverse images use amd64
emulation:

```bash
uv run midnight \
  --platform-config config/platform.local.yaml \
  --run-id competition-1 \
  --submit \
  --max-concurrency 2 \
  --task-timeout 1800 \
  --events-path logs/competition-1/events.jsonl \
  --checkpoint-path logs/competition-1/checkpoints.sqlite \
  --submission-ledger-path logs/competition-1/submissions.sqlite \
  --artifacts-root logs/competition-1/artifacts \
  --workspace-root logs/competition-1/workspaces \
  --report-path logs/competition-1/report.json
```

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
