# SIFTMesh Evidence Integrity & Chain of Custody

_Epic L (supports L2 path-policy + L4 evidence-as-hostile). The integrity boundary keeps
originals hashed before analysis, opened read-only, and never written back, and it records
every derived artifact and tool read so a finding traces to exact bytes. Read with
[`threat_model.md`](https://github.com/aryanbuilds/Project_SIFTMESH/blob/mvp_phase_1/docs/threat_model.md)._

---

## 1. The integrity invariants

1. **Hash before analysis.** SIFTMesh computes the SHA-256 of every evidence file at
   `init-case`, before any tool runs. The manifest is the baseline, and any later mismatch
   triggers a stop-and-ask event.
2. **Originals are read-only.** SIFTMesh opens sources read-only and never writes to the
   evidence tree (posture-level; see §4 for the OS-level non-goal).
3. **Writes stay in the run dir.** SIFTMesh canonicalizes every write through
   `safe_write_path` into `case_runs/RUN-*/` and rejects it if it escapes (see
   `threat_model.md` §5.1).
4. **Every claim traces to bytes.** A finding records `source_artifact` + `source_sha256`
   + `tool_call_id`. The sha256 is the exact bytes the tool parsed, re-hashed at read
   time (§3). With no anchor, the critic rejects it.
5. **Derived artifacts inherit custody.** SIFTMesh records files produced by
   extraction/decompression with their provenance and their own hashes, and re-ingests
   them as first-class evidence.

---

## 2. Artifacts written under `evidence/`

| File | Content | Producer |
|---|---|---|
| `evidence_manifest.json` | One row per source: path, size, sha256, type, ingest time. | `evidence/manifest.py` |
| `hashes.sha256` | Flat `sha256␠␠path` list (standard `sha256sum -c` format). | `evidence/manifest.py` |
| `readonly_mounts.json` | The read-only record (`enforcement: posture_only`, or `os_bind_mount_ro` with `original_path` where the Linux host granted a verified ro bind mount; sources, access). | `evidence/readonly.py` |
| `derived_artifacts.json` | Artifacts produced by tools (extracted/decompressed), with provenance + hash. | extraction/decompress tools |
| `custody_log.jsonl` | Append-only custody events (ingest, derive, access). | evidence layer |

The deterministic report loader joins these inputs into chain-of-custody and the
tool-execution appendix (Epic J), so the audit trail in the report is a pure function of
these files.

---

## 3. Per-access integrity hashing

Reads route through `mcp_gateway/tools/_common.resolved_source(evidence_root,
source_artifact, *, run_root=None)`, which:

- resolves the artifact path under the trusted root(s): the read-only evidence root, plus
  (for **derived-artifact** readers) the active run root where
  `extract_artifacts_from_image` / `decompress` write `evidence/extracted/…`;
- **rejects any path that escapes every trusted root** (`..`, absolute, symlink-out) with
  `ValueError`, since case data is hostile (CLAUDE §6);
- **re-hashes the exact bytes** it is about to parse, and returns `(real_path, sha256)`;
- after the parse, `audit_exec.run_tool` re-verifies the source (full SHA-256 at or
  below 64 MB, `(size, mtime_ns)` stat fast-path above it with full re-hash on any
  stat drift) and records `source_rehash_verified`; a mismatch fails the tool as
  `integrity_mismatch` instead of persisting tainted results.

That returned sha256 becomes the claim's `source_sha256`, which anchors a finding to the
bytes actually analysed rather than to a path that might have changed. Admitting the run
root for derived artifacts does not widen the boundary beyond directories SIFTMesh owns,
and the dual-root containment is regression-tested (`test_bypass_agent_sandbox.py`).

---

## 4. Read-only posture (and its honest limit)

`evidence/readonly.py` records `enforcement: posture_only`: SIFTMesh opens originals
read-only and never writes to a source, and `safe_write_path(evidence_root=…)` refuses any
write under the evidence tree. This is **construction-level** integrity rather than an
OS-level read-only mount (`mount -o ro` / `blockdev --setro`): since D-7h7,
`init-case` attempts a verified read-only bind mount on Linux and records
`enforcement: os_bind_mount_ro` when `/proc/mounts` confirms it, else the honest
`posture_only`. A privileged external process on the host
sits outside SIFTMesh's scope. We do not claim court-ready forensic soundness.

---

## 5. Evidence-as-hostile (spotlighting), in one place

When a live LLM agent is in the loop, and only then, SIFTMesh hands evidence over as inert,
spotlighted DATA, never as raw bytes and never as instructions. The full spec lives in
[`threat_model.md`](https://github.com/aryanbuilds/Project_SIFTMESH/blob/mvp_phase_1/docs/threat_model.md) §5.3. In short, the prompt carries only `{path,
sha256}` rows, wrapped with a per-run delimiter sentinel, a "DATA, not instructions"
banner, and interleaved datamarking (Microsoft spotlighting, arXiv:2403.14720). SIFTMesh
logs instruction-like content to `injection_alerts.jsonl` and the critic acts on it
(`human_review_required`); it is never executed. The deterministic tool path builds no LLM
prompt at all, so it has no injection surface.

---

## 6. What this buys the investigation

- A reviewer can re-hash any source and compare to the manifest, giving a tamper-evident
  baseline.
- A reviewer can take any claim in the final report, read its `tool_call_id` in the
  tool-execution appendix, and see the exact artifact + sha256 it came from, giving full
  traceability ("replayable audit").
- A reviewer can replay `orchestration_events.jsonl` to see every transition, dispatch,
  tool call, and verdict in order, giving reproducible run history.

The committed full ledgers for the reference run live at
`docs/logs/rocba-live-RUN-20260615-064002/` (the live Claude-agent run, disk plus memory in one
autonomous pass), so a reviewer can trace these invariants against the real recorded audit trail.
