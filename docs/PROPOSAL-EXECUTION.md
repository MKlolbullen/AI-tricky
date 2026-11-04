# Proposal execution — 0.7

In **Agent desk → Evidence follow-ups**, open **Review execution** on a proposed test. Choose budgets and any required reviewed templates folder, then prepare a saved execution review. Preparation performs local validation and preflight; it sends no target requests and starts no binary. The snapshot is not an execution grant until the local operator explicitly approves and dispatches it.

## Bound configuration

The server rebuilds the workflow from the saved, current proposal. Clients may supply only native-operation, CLI-launch, host and deadline limits, explicit CLI enablement, and the reviewed templates folder needed by the Nuclei profile. Clients cannot change the target, original scope, adapter, flags, commands, graph, credentials, evidence references or goal through this endpoint. Original scope entries must still be registered entered targets. These 13 profiles declare no provider credential variables, so proposal executions pass no provider credentials to CLI tools.

The snapshot binds plan/proposal IDs, source run, evidence context hash, action, exact source input, registered target IDs, scope, typed graph, limits, binary paths and SHA-256 hashes, registered input metadata and content fingerprints. Folder fingerprints include relative paths and file contents, with the existing 20 MB / 10,000-file bound and a 20,000-entry cap. File inputs are bounded to 10 MB. A separate runtime identifier prevents a saved review from becoming valid in a new API process.

Before dispatch the server rechecks evidence, parser/profile/catalog bindings, registered scope, executable pins, input contents and preflight. Copied CLI inputs are fingerprinted again before process launch, covering changes after dispatch validation. The existing runner also verifies the executable before launch. These checks do not isolate a third-party executable from the operating system or constrain its internal network traffic.

## Approval and lifecycle

Reviews expire 15 minutes after preparation. Settings are locked while reviewing a pending snapshot. **Change settings** revokes that review before preparing another. The explicit approval checkbox is never restored as checked. The UI sends only the review ID, expected snapshot hash and affirmative approval to dispatch.

| State | Meaning |
| --- | --- |
| `pending` | Prepared and awaiting explicit local operator approval |
| `dispatched` | Consumed exactly once; linked run may be queued, active or terminal |
| `revoked` | Operator revoked it before dispatch |
| `expired` | Approval window elapsed before dispatch |
| `invalidated` | Evidence, scope, inputs, binaries or runtime bindings changed |

Approval audit entries and run creation commit in one SQLite transaction. Concurrent/repeated dispatch requests return the same run ID; they never launch another run from that review. A failed or interrupted run does not reset its consumed review. Repeating a test requires preparing and approving a new review. A capacity rejection leaves the review pending so it can be retried within its validity window.

The local API uses one process and its existing loopback, host and origin boundary. “Local operator” describes that boundary; it is not an authenticated multi-user identity or a signed approval credential. Pending reviews are invalidated at API startup. Prior receipts and audit history remain readable; interrupted runs are not automatically resumed.

## Accounting and provenance

Execution uses the existing runner, including pause/resume/cancel, deadlines, native scope checks, separate native and CLI admission counts, per-node artifacts and events. The exact proposal input is used even if the original scope contains additional assets. Host limits are also checked against entered CIDRs during review preparation, as in normal run setup.

The run configuration records execution-review, plan, proposal, source-run and context IDs plus the approval snapshot hash. A `proposal.approved` run event and a durable execution audit record link the approval to requests and artifacts through their run ID. The Runs view displays that provenance. New output does not automatically verify a finding, resolve absence or cause another proposal to dispatch.

Canvas loading and ordinary manual runs remain available independently. Node `proposalId` fields are informational labels; a manual run cannot forge server-recorded proposal approval provenance. Editing the canvas never edits an existing execution snapshot.

## API

| Method | Route | Behavior |
| --- | --- | --- |
| POST | `/api/agent/proposals/{plan}/{proposal}/executions` | Strict execution options; prepare and persist an immutable review after preflight |
| GET | `/api/agent/proposals/{plan}/executions` | Latest 50 execution-review summaries for the plan |
| GET | `/api/agent/executions/{id}` | Saved snapshot, current state, linked run and audit; pending bindings are rechecked |
| POST | `/api/agent/executions/{id}/dispatch` | Requires `expected_hash` and boolean `approve: true`; atomically consume once and start/return its run |
| POST | `/api/agent/executions/{id}/revoke` | Requires `expected_hash`; revoke a pending review |

Snapshot hashes bind server-owned configuration and provenance. They are not substitutes for the local API boundary, authenticated identities or cryptographic approval signatures. Semantic proposal quality and broad real-binary compatibility still require controlled-lab evaluation.
