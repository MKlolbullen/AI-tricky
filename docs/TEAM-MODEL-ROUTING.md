# Specialist teams and model routing

In **Local workspace → Run setup**, choose the Team engine and the specialist profile. **Use mixed-provider routing** sets up Gemini for recon, OpenAI for analysis, Venice for vulnerability/PoC work and Anthropic for lead synthesis. Enter exact model IDs from your accounts. You can change every provider, including using local models throughout. No model IDs or automatic provider rankings are hardcoded.

The preset edits settings only. Store provider keys in Credentials and enable remote inference with `CAI_ALLOW_REMOTE_MODEL=1` before using remote models. Selected evidence and upstream reports are sent to the selected providers. Hosting and artifacts remain local. All configured primary, fallback and complex-task routes are validated before a run is created; their credential values are snapshotted in memory and never stored in run JSON, events, handoffs or the usage ledger.

## Roles and stages

| Profile / role | Inputs and responsibility | Target tools |
| --- | --- | --- |
| Classic | Existing surface, transport, auth/session, injection-surface and business-logic roles run in parallel | Existing scoped tools and permissions |
| Specialist: surface | Reconnaissance and captured response gathering | Scoped HTTP and bounded TCP in live Team runs |
| Specialist: analyst | Correlates captures and the recon report | Captured evidence only |
| Specialist: vulnerability | Assesses hypotheses, prerequisites and counterevidence | Captured evidence only |
| Specialist: PoC | Produces reproducible validation plans with expected and negative signals | Captured evidence only |
| Optional lead | Synthesizes completed role reports using its own model route | No target tools |

The server owns stage order and tool permissions. Model output cannot add roles, select providers, expand scope or create tools. Explicit selected roles override profile defaults. The classic profile remains the default for old runs. Specialist profiles take precedence over adaptive classic-role selection. Skipped or failed roles remain explicit coverage gaps.

The same profiles work on `native_team` workflow nodes. Node profile/role settings override run settings. All roles in these nodes review connected captures only, including their surface/recon pass. Run setup supplies model routing; node controls supply per-node turns, workers and optional profile overrides. Existing classic evidence-team behavior remains supported.

## Primary, complex-task and fallback choices

Each role, plus `lead`, can override the run's default provider/model. An optional **complex-task override** selects a different primary model when **Task complexity** is Complex. This is an operator-selected tier, not a guessed difficulty or an automatic claim that one model is strongest. Without that override, the primary model stays selected.

An optional **availability fallback** is a separate, preauthorized provider/model. It runs only after recognized provider connection errors, provider timeouts, HTTP 429 or HTTP 5xx. Authentication/configuration errors, malformed reports, target-tool errors, refusals, cancellations and run deadlines do not switch providers. A successful refusal/insufficient-evidence report does not trigger fallback. Fallback does not add tools or relax scope.

Fallback capacity is reserved inside the existing role ceiling: primary gets `ceil(role_turns / 2)` and fallback gets `floor(role_turns / 2)`. Without fallback, primary gets the entire ceiling. A one-turn role has no fallback capacity. Unused primary turns are not refunded or shared with other roles. Provider retries are disabled in the client; both attempts receive separate durable usage IDs and retain unknown/missing token counts honestly. A fallback restarts that role's pass and may repeat a scoped read; those reads still consume the same run's native request budget.

The compatibility client uses provider-default sampling. OpenAI-selected calls use `max_completion_tokens`; other compatible endpoints use `max_tokens`. The model must support the selected API and, for live recon, tool calling. Route configuration is not proof that a particular model ID supports every feature.

## Handoffs and validation evidence

`team-handoff-<role>.json` records a versioned packet with original scope, at most 12 capture references, bounded response fields and completed prior-stage reports. Report excerpts are capped at 4,000 characters and explicitly mark truncation; body excerpts are capped at 1,200 characters. Prior reports are untrusted hypotheses. `team-member-<role>.json` records each result, route attempts and the handoff artifact ID. The run result links both. Inspect handoffs under **Runs → Team routes and handoffs** or download their artifacts.

Analyst and vulnerability reports use the existing evidence-analysis contract; candidates must cite supplied captures. PoC reports use a distinct validation-plan contract: summary, proposed validations, evidence IDs, bounded steps, expected signals, negative signals and coverage limits. The server sets `execution=not_executed`, `review_required=true` and `confirmed=false`. A report cannot supply its own execution/confirmation flags or cite unavailable captures.

PoC plans are proposals, not automatically executed scripts or verified findings. To execute a test, use the existing reviewed proposal/verification workflow with a supported server-owned action. Generic exploit execution and authenticated multi-identity comparisons are separate future contracts. Nothing here changes operator finding reviews.

Recovery preserves profile, task tier, role selection and model routes. Reviews bind every selected model endpoint, ID and credential fingerprint. Changed keys invalidate pending reviews. Reused handoff/report references are copied and remapped with the rest of their checkpoint bundle; reused analysis does not add model usage.

## API example

Use existing entered target IDs. Omitted role routes inherit `provider`/`model` or the configured local endpoint.

```json
{
  "engine": "team",
  "target_ids": ["EXISTING_TARGET_ID"],
  "allow_http": true,
  "team_profile": "specialist",
  "team_task_level": "standard",
  "synthesize": true,
  "team_max_turns": 48,
  "member_max_turns": 8,
  "team_routes": {
    "surface": {
      "primary": {"provider": "gemini", "model": "YOUR_RECON_MODEL"},
      "complex_task": {"provider": "openai", "model": "YOUR_COMPLEX_MODEL"}
    },
    "analyst": {
      "primary": {"provider": "openai", "model": "YOUR_ANALYSIS_MODEL"},
      "fallback": {"provider": "anthropic", "model": "YOUR_BACKUP_MODEL"}
    },
    "vulnerability": {"primary": {"provider": "venice", "model": "YOUR_SECURITY_MODEL"}},
    "poc": {"primary": {"provider": "venice", "model": "YOUR_CODING_MODEL"}},
    "lead": {"primary": {"provider": "anthropic", "model": "YOUR_LEAD_MODEL"}}
  }
}
```

Provider compatibility references:

- [Anthropic OpenAI SDK compatibility](https://platform.claude.com/docs/en/cli-sdks-libraries/libraries/openai-sdk)
- [Gemini OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai)
- [Venice Chat Completions](https://docs.venice.ai/api-reference/endpoint/chat/completions)

Tests use injected analysts and loopback model servers. They do not establish live-provider availability, paid-model quality or model superiority.
