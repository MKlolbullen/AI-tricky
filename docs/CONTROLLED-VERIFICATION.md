# Controlled verification — 0.8

For a saved **native HTTP** proposal, open **Review execution → HTTP check profile**. Choose a profile, optionally link a finding supported by the proposal's cited observations, prepare the review and inspect the exact requests before approving. Preparation sends no target traffic. Dispatch uses the existing single-use approval and native runner controls.

## Initial profiles

| Profile | Baseline | Variant | Observed signal |
| --- | --- | --- | --- |
| Repeat GET stability | GET the bound URL | Repeat the same GET | Complete successful captures match in status, selected headers and captured byte fingerprint |
| CORS response policy | GET without an Origin header | GET the same URL with `Origin: https://ai-tricky.invalid` | A response allow-origin rule matches the fixed test origin or permits anonymous wildcard access |

Both profiles admit at most two native operations and require a selected budget of at least two. The requests are sequential, use the same bound URL, omit cookies and authorization, and do not follow redirects. The fixed test origin is a header marker; the platform does not connect to it. These profiles do not send OPTIONS, invoke a browser, bind identities or accept user/model-provided headers, methods, bodies or alternate URLs. CLI proposals retain their existing execution flow.

The execution snapshot includes the profile/version/contract hash, request roles, exact URL, method, additional headers, omitted-credential policy, response byte cap, optional finding link and native cost. A changed profile contract invalidates a pending review. Changing the selected profile, finding link or budget requires another review; restoring a review never restores affirmative approval.

## Capture and comparison

The repeat GET and CORS profiles retain HTTP artifacts with baseline/variant labels, selected response headers, connected IP, decoded text, captured byte count, byte SHA-256 and truncation flag. The HTTP journal also preserves bounded captured entity bytes. The authenticated profile uses the metadata capture described below.

The comparison artifact records capture IDs and content hashes, selected field differences, narrow profile facts, source approval provenance, evaluator version and coverage limits. The Runs view shows both captures and exports the comparison. Read-only comparison does not send requests or call a model.

| Outcome | Meaning |
| --- | --- |
| `signal_observed` | This profile's specified response signal was captured |
| `signal_not_observed` | A complete pair did not show that narrow signal |
| `inconclusive` | Missing/failed captures, denial/redirect, truncation, ambiguous headers, different connected IPs, interruption or changed capture evidence prevents the conclusion |

A failed baseline stops the pair before the variant. Cancellation/deadline interruption preserves any baseline already captured and persists an inconclusive comparison when the node started. A run stopped before the node starts exposes an inconclusive receipt with no captures. Repeated dispatch returns the existing run and never repeats the pair.

Comparison reads preserve saved historical verdicts. If an underlying capture changes or disappears, the read view flags `evidence_current: false`, retains `recorded_outcome` and presents an inconclusive effective outcome. The original comparison artifact is retained. Historical results are not silently re-evaluated under a newer profile version.

## CORS interpretation

The CORS profile records anonymous allow-origin rules and whether an exact origin plus lowercase `true` credential-permission header pair was present. A wildcard does not authorize credentialed sharing, and the credential header value is case-sensitive. These response-header facts do not prove authenticated data exposure, browser exploitability or a vulnerability. Public resources can deliberately allow cross-origin reads. See the primary [Fetch Standard's CORS and credentials rules](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials).

## Authenticated object access

Select **Authenticated object access** for a native HTTP proposal targeting an
object that belongs to your first test account. Under **Manage test identities**,
register a bearer token for each account. Then select the owner, the second
identity and a different object that belongs to the second identity. Both
objects must be within the approved scope and on the same scheme, host and port.
Choose a JSON Pointer such as `/id` or `/data/id` and enter the expected ID of
each object. The profile compares the string representation of a JSON string
or integer at that pointer.

The approved run can spend up to three native operations:

1. The owner requests the owner object.
2. The second identity requests its own control object.
3. The second identity requests the owner object after both controls return
   HTTP 200 with their expected IDs and the same connected peer.

The comparison records a signal when the third request returns HTTP 200,
matches the owner ID and has the same complete body fingerprint as the owner
response. With both controls satisfied, a distinct 403 or 404 response without
the owner marker records a denial signal. HTTP 401, redirects, changing payloads,
failed controls, truncation and peer changes lead to an inconclusive result.
Review the actual access policy before drawing a finding conclusion. Equal
objects may be intentionally shared, and different representations may still
contain protected data.

Identity tokens live in application memory for the current session. Registration
binds each identity to its exact origin. Removing an identity invalidates pending
reviews that reference it. A dispatched run holds its approved snapshot in
memory until completion or cancellation. Use the run controls to stop it.
HTTPS uses the existing direct verified transport and approved CA settings.
Plain HTTP is available on direct loopback for labs. This profile uses bearer
tokens and direct routing.

The HTTP journal and artifacts record a redacted Authorization header, status,
connected peer, bounded byte counts, resource marker results and HMAC-SHA256
fingerprints. Response headers and bodies are discarded after comparison.
Fingerprints use an ephemeral run key and compare within a single run. HAR
exports identify the metadata capture mode. The review receipt contains
identity labels, IDs and exact approved requests. It contains no bearer values.

## Findings and review

Only a finding supported by a cited proposal observation can be linked. Approved verification runs appear in that finding's workbench, alongside baseline/variant capture inspection and export. Intact linked HTTP captures become available to the existing explicit, revision-checked review form. A comparison artifact itself is not a substitute for an HTTP capture.

Verification never changes severity, confidence, status, first/last-seen timestamps or review history automatically. A negative signal never resolves a finding. An operator can inspect evidence and record a separate decision with an explanatory note; the comparison does not make that decision for them.

## API additions

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/api/verification/profiles` | Server-owned profile descriptions and native cost |
| GET, POST | `/api/verification/identities` | List session identity metadata or register an origin-bound bearer token |
| POST | `/api/verification/identities/{id}/remove` | Remove an identity and invalidate its pending reviews on next read or dispatch |
| GET | `/api/agent/proposals/{plan}/{proposal}/verification-findings` | Findings supported by cited observations |
| POST | `/api/agent/proposals/{plan}/{proposal}/executions` | Prepare a profile with optional finding link and `object_access` controls for the authenticated profile |
| GET | `/api/runs/{run}/verification` | Persisted comparison or current partial/inconclusive receipt |
| GET | `/api/findings/{finding}/verification` | Latest 50 linked approved checks |

Approval expiry, revocation, restart invalidation, snapshot binding, pause/resume/cancel and native admission accounting apply. Verification requests are built by the server from the approved proposal and profile.
