# Readiness Report — 2026-09-10

## Decision

Midnight is ready for an organizer API integration rehearsal and an initial
autonomous CTF evaluation. It has a complete platform-to-sandbox-to-submission
workflow and demonstrated multi-category solving with the configured low-cost
model. The remaining work after the organizer documentation arrives should be
limited to mapping the platform contract and running the supplied test task.

This result does not establish parity with frontier multi-model systems. The
current evidence is a public, compact development benchmark rather than a fresh
blind evaluation.

## Frozen solver revision

The full benchmark below used solver revision `9023ac0`. The run was independent:
fresh workspaces and containers, no previous trajectories, no general Internet
access, and only challenge-target networking. Benchmark flags, solutions,
write-ups, and graders remained outside the agent-visible bundles.

## Offline arsenal

| Area | Built-in workflow and tools |
| --- | --- |
| Web | HTTP sessions, source-first analysis, TInjA, `jwt_tool`, SQLi/SSTI/JWT/SSRF/XXE/deserialization/upload playbooks, and a target-bound Velocity adapter |
| Pwn | `pwntools`, GDB/Pwndbg sessions, ROPgadget, one_gadget, checksec, cyclic/core analysis, Keystone, and target-bound exploit execution |
| Reverse | Ghidra headless, radare2, binutils, UPX, Angr, Z3, LIEF, Keystone, Kaitai Struct, PE/Python bytecode tooling, and custom-protocol/VM playbooks |
| Crypto | SageMath, PyCryptodome, SymPy, Z3, RsaCtfTool, and RSA/lattice/symmetric-oracle playbooks |
| Forensics | Volatility 3, Sleuth Kit, binwalk, foremost, exiftool, tshark, Scapy, YARA, Hayabusa, archive recovery, QR decoding, and IR/log timelines |
| Misc | Python jail analysis, restricted-pickle inspection, archive recovery, QR/barcode decoding, and reusable target-bound Python scripts |

Every specialist can persist a solver script and run it against the declared
challenge target through the same provenance gate. Flags from remote tasks are
accepted only when observed through a target-bound action.

## Tool verification

The seven specialist profiles and their six category images passed offline
capability contracts. Representative real executions also passed:

- RsaCtfTool recovered a private key from a close-prime sample.
- TInjA and `jwt_tool` executed from the Web image.
- Kaitai compiled a schema and its generated parser decoded a sample structure.
- `fcrackzip` recovered a test archive password.
- Hayabusa processed a public EVTX sample with 4,648 rules and produced 287
  timeline events.

Docker images are local runtime artifacts in Docker Desktop's Linux VM. The
repository stores only pinned, reproducible Dockerfiles and checksums.

## Full Core-12 evaluation

The final complete run solved **10/12 (83.33%)** in **781.481 seconds** with a
maximum concurrency of three and a 30-minute per-task budget.

| Category | Result |
| --- | ---: |
| Crypto | 2/2 |
| Forensics | 2/2 |
| Reverse | 2/2 |
| Web | 2/2 |
| Pwn | 1/2 |
| Misc | 1/2 |

The run used 2,848,655 input tokens and 119,475 output tokens across 246 tool
calls. It recorded 40 tool errors, 44 repeated calls, and 24 structured-protocol
recoveries. These counters identify efficiency work for later iterations; none
caused a run-level failure.

Unsolved tasks:

- `Were Pickle Phreaks Revenge`: the model did not complete the restricted
  pickle gadget chain after three attempts.
- `network-tools`: the model found the source-level stack-overflow direction but
  did not finish a working exploit after three attempts.

For comparison, the previous complete revision solved 8/12. The final revision
also reproduced the two targeted fixes in the same clean aggregate run:
target-verified script execution solved `Unbreakable`, and the structured
Velocity workflow solved `Labyrinth Linguist`. This is a revision comparison,
not a statistical pass@N claim.

## Competition-day integration gate

When the organizer contract arrives:

1. Copy `config/platform.example.yaml` to the ignored
   `config/platform.local.yaml` and map the base URL, paths, fields, and auth
   header. Keep the token in the `.env` variable selected by `token_env`.
2. Run `scripts/competition local-preflight` without reinstalling packages.
3. Run `scripts/competition platform-preflight` for read-only discovery.
4. Run `scripts/competition dry-run TEST_CHALLENGE_ID` with submissions disabled.
5. Use the organizer's test task with
   `scripts/competition submit-test TEST_CHALLENGE_ID`.
6. Freeze prompts, tool schemas, and orchestration after that rehearsal. Apply
   only platform compatibility or reliability fixes.
7. Start the authorized round with `scripts/competition round2` or `round3` and
   retain the same run ID to enable checkpoint recovery.

The detailed procedure and safety checks are in
[`competition-mvp.md`](competition-mvp.md).

## Post-report hard-tail diagnostics

Later generic tooling added deterministic restricted-Pickle policy auditing and
payload compilation, source-aware crash probing, and static PIE/ROP inventory.
A fresh targeted run solved `Were Pickle Phreaks Revenge` 1/1 and received an
accepted evaluator verdict. `network-tools` remained unsolved in its targeted
run; the tool recovered the correct symbol and frame geometry, but the low-cost
model misused the saved-return distance and a side-effect gadget. Those two
mistakes are now explicit phase invariants with tests. See
[`capability-iteration-2.md`](capability-iteration-2.md). The frozen full score
above remains unchanged until another complete aggregate evaluation is run.
