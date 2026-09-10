# Capability Iteration 2: Deterministic Pickle and PIE/ROP Planning

## Objective

Reduce weak-model failures in two hard-tail patterns observed after the frozen
Core-12 run: restricted Pickle programs and source-confirmed PIE stack
overflows. The benchmark repository, solutions, flags, and write-ups remain
outside agent-visible bundles. Only generic procedures and deterministic tools
are stored in Midnight.

## Restricted Pickle lane

- `pickle_policy_audit` extracts allow/block policy facts, explains protocol-4
  dotted-name resolution, disassembles exact payload bytes, and invokes the
  challenge's local validator inside the isolated container.
- `pickle_build` compiles a declarative stack program. It owns opcode bytes,
  tracks stack and memo depth, provides an atomic `call(count)` operation, and
  rejects malformed programs before target contact.
- The phase gate now enforces policy audit, compiler construction, local
  validation, and only then target execution.
- The portable mapping-gadget plan uses
  `function.__globals__.__class__.get` plus a separately resolved globals
  mapping. This avoids Python-version assumptions about a direct
  `function.__builtins__` attribute.

An isolated loopback smoke test confirmed that the compiled generic chain could
produce target output containing the expected flag pattern without exposing the
flag. A fresh end-to-end Midnight diagnostic then solved **1/1** for
`Were Pickle Phreaks Revenge`; the evaluator accepted the submitted flag on the
third attempt. This targeted diagnostic is not merged into the frozen Core-12
aggregate.

## PIE/ROP lane

- `source_audit` now highlights unsafe Rust bounds, post-copy checks, static
  mutable state, and runtime pointer leaks.
- `pwn_crash_probe` creates a bounded cyclic input, runs batch GDB, and falls
  back to static symbol/disassembly evidence when Apple Silicon's emulated
  amd64 environment cannot expose ptrace registers.
- `pwn_rop_inventory` extracts the leaked symbol's static offset, focused stack
  frame geometry, candidate saved-return distances, writable sections,
  relocations, and prioritized full gadget semantics.
- The phase gate routes a source-confirmed overwrite plus runtime symbol leak
  into the ROP inventory and explicitly prevents double-subtracting a buffer
  offset or treating a side-effect gadget as a plain register pop.

The real offline smoke test against the `network-tools` binary recovered the
PIE symbol offset, stack-frame size, saved-return distance, writable sections,
and syscall-oriented gadgets. The end-to-end diagnostic still failed 0/1: the
configured low-cost model initially double-subtracted the buffer offset and
ignored a gadget side effect. The resulting invariant checks were added after
that run. A later diagnostic used the correct padding and accounted for the
side-effect gadget, producing a plausible two-stage `read`/`execve` chain, but
then stopped in `io.interactive()` and lost the stronger artifact on the next
retry. Midnight now rejects interactive final solvers and reads an existing
`solve.py` before restarting Pwn reconnaissance. No Pwn solve is claimed.

## Evidence boundary

The formal full Core-12 score remains **10/12 (83.33%)** at revision `9023ac0`.
The restricted-Pickle success is valid targeted evidence under a later revision.
The ROP inventory smoke test demonstrates tool correctness, while the unsolved
Pwn diagnostic remains an open capability gap. A new full aggregate run is
required before changing the published Core-12 score.
