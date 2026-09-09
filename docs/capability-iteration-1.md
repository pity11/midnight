# Capability Iteration 1: Procedural Solving and Weak-Model Control

## Objective

Improve CTF solving behavior while keeping the existing low-cost DeepSeek model
fixed. The iteration targets harness contribution: repeatable gains should come
from orchestration, procedural knowledge, tools, and recovery rather than a model
upgrade.

## Reference designs

- [Veria ctf-agent](https://github.com/verialabs/ctf-agent): challenge scheduling,
  solver isolation, and artifact-oriented competition operation.
- [D-CIPHER](https://github.com/NYU-LLM-CTF/nyuctf_agents): explicit planning and
  specialist execution boundaries.
- [EnIGMA/SWE-agent](https://github.com/SWE-agent/SWE-agent): stateful interactive
  debugger and service sessions.
- [OpenSage ADK](https://github.com/opensage-agent/opensage-adk): on-demand skills
  and bounded context rather than loading a large knowledge base into every turn.
- [BoxPwnr](https://github.com/0ca/BoxPwnr): reproducible benchmark adapters,
  traces, metrics, and controlled comparisons.
- The local `ctf-agents` reference: evidence gates, continuation from artifacts,
  dead-end avoidance, and time discipline.

Midnight adopts these engineering patterns without copying challenge answers or
write-ups into the agent-visible knowledge base.

## Implemented changes

1. Added a curated procedural playbook catalog selected from observable evidence.
   It covers format-string writes, PIE leak plus ROP, UPX, verifier inversion,
   decimal partial RSA factors, restricted pickle, MIME layers, and source-first
   web analysis.
2. Added `binary_triage`, `upx_unpack`, `pickle_disassemble`, and
   `lookup_playbook` tools.
3. Installed checksum-pinned UPX 4.2.4 in the reverse image and Pickora 1.0.0 in
   the misc image. Both were verified in containers with networking disabled.
4. Added repeated-command stagnation feedback and one-shot recovery for failed
   GDB and network terminal sessions.
5. Added artifact and target phase gates. After three useful reconnaissance
   actions, a specialist must produce an executable solver or payload artifact;
   after six actions on a network task, it must exercise the target.
6. Added bounded continuation of prematurely completed solver lanes and retained
   a tail of prior evidence across outer retries.
7. Required target provenance for network-task flag candidates and disabled
   transcript-wide flag promotion for those tasks.
8. Reduced text-only model overhead with compact tool definitions while retaining
   local validation against the complete JSON Schema. Canonical actions with
   harmless metadata or string-encoded argument objects are normalized.
9. Limited each specialist lane to 24 model turns so it returns artifacts and
   evidence before the LangGraph recursion limit, allowing the next lane to
   continue instead of losing the attempt.

## Verification

- Static checks: passed.
- Test suite: 106 passed, 1 environment-dependent test skipped.
- Reverse image: a generated amd64 ELF was packed and unpacked successfully with
  UPX in a `--network none` container.
- Misc image: Pickora compiled a payload and imported its compiler offline.
- No benchmark answer, flag, solution, or write-up was added to the repository.

## Targeted benchmark observations

These are diagnostics from different code revisions and random seeds. They are
not a formal comparable score and must not be combined with the existing Core-12
aggregate.

| Challenge class | Before | Diagnostic outcome | Evidence |
| --- | --- | --- | --- |
| UPX reverse | failed | solved | 29.8 s, 7 tool calls, 0 tool errors |
| Decimal partial RSA | failed in Midnight runs | solved | 84.5 s, 10 tool calls |
| Format-string pwn | failed | still failed | an executable `solve.py` is now produced; graph-limit loss was fixed afterward |
| Restricted pickle | failed | still failed | protocol errors were removed, but the low-cost model did not finish the gadget chain |

The strongest demonstrated gain is on deterministic tool and algorithm gaps:
UPX reverse and decimal partial RSA changed from failure to success under the
same base-model family. Pwn and restricted pickle now produce better engineering
signals but do not yet establish a solve-rate gain.

## Next controlled evaluation

1. Run the final revision on the focused failure set with fresh seeds.
2. Run one complete Cybench Core-12 attempt for Midnight and the matched bare
   baseline with identical model, images, time limit, and network policy.
3. Compare success, tool-call efficiency, protocol-repair rate, artifact creation,
   and category results. Keep the existing public aggregate unchanged.
4. Use remaining Pwn failures to add an exploit-artifact critic and structured
   local-to-target executor. Use restricted-pickle failures to add opcode-policy
   validation rather than challenge-specific gadget answers.
