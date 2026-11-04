# Controlled verification — 0.8

For a saved **native HTTP** proposal, open **Review execution → HTTP check profile**. Choose a profile, optionally link a finding supported by the proposal's cited observations, prepare the review and inspect both exact requests before approving. Preparation sends no target traffic. Dispatch uses the existing single-use approval and native runner controls.

## Initial profiles

| Profile | Baseline | Variant | Observed signal |
| --- | --- | --- | --- |
| Repeat GET stability | GET the bound URL | Repeat the same GET | Complete successful captures match in status, selected headers and captured byte fingerprint |
| CORS response policy | GET without an Origin header | GET the same URL with `Origin: https://ai-tricky.invalid` | A response allow-origin rule matches the fixed test origin or permits anonymous wildcard access |

Both profiles admit at most two native operations and require a selected budget of at least two. The requests are sequential, use the same bound URL, omit cookies and authorization, and do not follow redirects. The fixed test origin is a header marker; the platform does not connect to it. These profiles do not send OPTIONS, invoke a browser, bind identities or accept user/model-provided headers, methods, bodies or alternate URLs. CLI proposals retain their existing execution flow.

The execution snapshot includes the profile/version/contract hash, request roles, exact URL, method, additional headers, omitted-credential policy, response byte cap, optional finding link and native cost. A changed profile contract invalidates a pending review. Changing the selected profile, finding link or budget requires another review; restoring a review never restores affirmative approval.

## Capture and comparison

Every successful response is retained as an HTTP artifact with a baseline/variant request label, selected response headers, connected IP, decoded text, captured byte count, byte SHA-256 and truncation flag. The byte fingerprint is computed before UTF-8 decoding. Displayed text can be lossy for binary/non-UTF-8 bodies; complete original binary bytes are not exported by this transport.

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

## Findings and review

Only a finding supported by a cited proposal observation can be linked. Approved verification runs appear in that finding's workbench, alongside baseline/variant capture inspection and export. Intact linked HTTP captures become available to the existing explicit, revision-checked review form. A comparison artifact itself is not a substitute for an HTTP capture.

Verification never changes severity, confidence, status, first/last-seen timestamps or review history automatically. A negative signal never resolves a finding. An operator can inspect evidence and record a separate decision with an explanatory note; the comparison does not make that decision for them.

## API additions

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/api/verification/profiles` | Server-owned profile descriptions and native cost |
| GET | `/api/agent/proposals/{plan}/{proposal}/verification-findings` | Findings supported by cited observations |
| POST | `/api/agent/proposals/{plan}/{proposal}/executions` | Existing review endpoint adds optional `verification_profile` and `finding_id` |
| GET | `/api/runs/{run}/verification` | Persisted comparison or current partial/inconclusive receipt |
| GET | `/api/findings/{finding}/verification` | Latest 50 linked approved checks |

Existing approval expiry, revocation, restart invalidation, snapshot binding, pause/resume/cancel and native admission accounting apply. Ordinary manual run input cannot supply server-recorded verification configuration. This increment does not add arbitrary replay, identity switching or automatic exploitation.
