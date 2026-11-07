# Checkpointed workflow recovery

In **Local workspace → Runs**, select a stopped workflow and choose **Recover
workflow branches**. Select retry roots, prepare a review, inspect the steps and
cached captures, and approve that snapshot once. Recovery creates a new run;
the source run, its evidence and operator reviews stay intact.

## Branch selection

The default selection contains nodes without healthy completed checkpoints,
including completed nodes whose outputs recorded operation errors. The operator
can also select a completed node for a deliberate refresh.

1. Execute each selected root and its downstream descendants again.
2. Include all upstream dependencies needed by those execution steps.
3. If an upstream dependency has no usable completed checkpoint, execute it and
   its descendants as well. Repeat until the graph has all required inputs.
4. Reuse the remaining healthy upstream outputs. Leave unrelated branches in
   the source run; their omission does not claim they succeeded or were fixed.

The review displays this expanded plan before dispatch, including original
scope, ports, parallelism, native/CLI limits, deadline, executable pins and
registered-input hashes. Limits apply to the new run. Native operations and CLI
launches have separate counters; external binaries' internal requests remain
outside the native counter. Missing binaries are checked only for steps that
will execute, so a completed CLI checkpoint does not need its binary reinstalled.

## Fresh review and dispatch

Reviews expire after 15 minutes and pending reviews invalidate at runtime
restart. Changing the original scope, graph, source node state, checkpoint
contents, adapter contracts, selected credentials, model endpoint/name/key,
registered input contents or executable pins requires a new review. Credential
identity uses a memory-only keyed digest; keys are never placed in a review.

Preparing or inspecting a review performs local validation without model or
target requests. Explicit approval consumes the exact snapshot. Run creation,
artifact copies, checkpoint records and the approval receipt commit in one
SQLite transaction. Concurrent dispatch and retries return the same run.
Disconnecting the requesting client does not cancel an already approved
consume/start operation. Normal pause, resume and cancel controls apply to the
new run, with fresh native and CLI counters.

Selected CLI credentials and resolved model settings are snapshotted again for
the approved recovery, then held privately on its run control. Changes made to
settings while that run executes cannot mix identities mid-run.

## Evidence and checkpoint integrity

Reused node outputs and their referenced artifacts are copied into the new run
under `reused/<source-run>/<original-name>`. Copies retain their original capture
timestamps and record source run/artifact IDs plus original and copied hashes.
Structured artifact references are remapped; response bodies and report text
are preserved. The original artifacts are never rewritten.

Each reused node has status `reused` and emits `node.reused` with its provenance.
The runner verifies the copied bundle before admitting traffic; file inputs are
checked again when consumed. Copied file artifacts belong to the recovery run,
so the existing CLI rule rejecting another run's file artifacts remains intact.
Registered file/folder contents are also checked against approved hashes after
the runner copies them for an invocation.

Reused captures are **historical inputs**, not new observations or detections.
Their namespace keeps them out of capture/asset parsers and run comparison does
not treat them as freshly observed findings. An evidence analyst can review
cached captures and persist a new analysis artifact; candidates relying only on
those cached captures are not indexed as new detections. Rerun the capture step
too when fresh workbench observations are needed. Original findings and their
operator review state are preserved.

## API

| Operation | Endpoint |
| --- | --- |
| Inspect nodes and review history | `GET /api/runs/{source_run_id}/recovery` |
| Prepare a recovery review | `POST /api/runs/{source_run_id}/recoveries` |
| Load a review or receipt | `GET /api/recoveries/{id}` |
| Revoke a pending review | `POST /api/recoveries/{id}/revoke` |
| Approve and dispatch once | `POST /api/recoveries/{id}/dispatch` |

Preparation accepts only `node_ids`, `allow_cli`, `max_requests`,
`max_cli_invocations`, `max_hosts` and `max_seconds`. It accepts no replacement
graph, scope, commands, paths or credential values. Revocation requires
`expected_hash`; dispatch requires `expected_hash` and `approve: true`.
Both review records and recovered run configuration contain durable provenance.

## Current limits

- Workflow executions only; plans, live assessment/team engines and active runs
  are not recoverable through this API.
- Controlled verification pairs require a new proposal execution review. Recovery
  cannot reuse one side of a pair or inherit its original approval.
- Reusable artifact bundles are bounded to 25 MB and 1,000 artifacts. Include an
  oversized or unavailable upstream checkpoint in the retry to recapture it.
- No automatic retry loop, worker resurrection, actual token accounting or
  evidence-age expiration policy is introduced. Capture ages are visible for
  the operator's decision; a fresh review authorizes the selected reuse.
