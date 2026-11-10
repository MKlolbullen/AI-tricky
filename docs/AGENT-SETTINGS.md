# Saved agent settings and model menus

Open **Local workspace → Agent settings**. Choose the team profile, roles,
default model, per-role primary/fallback/complex-task routes, turn ceilings,
worker limit, adaptive selection and synthesis. The separate planning model is
shared by workflow planning, canvas assistance and evidence follow-ups.

Enter a preset name and click **Save preset**. **Save changes** updates the loaded
preset; give it a different name and use **Save as new preset** to keep both.
**Load preset** applies a saved configuration. Check **Restore this preset by
default** when saving to restore it whenever a new workspace opens, including
after restarting the backend. Only one preset is the default. Saving a different
default replaces that designation; deleting the default clears it.

Run setup and Agent settings edit the same team preferences. The **Save or load
agent settings** button in Run setup opens the preset editor with current choices.
These are team/run defaults: workflow analyst nodes keep their own turn budgets,
adaptive selection, worker limits and synthesis options in the saved graph.

## Model selection

Each provider has a small offline menu with exact model IDs, a documentation
link and a review date. This is a curated starting list, not live discovery of
your account or a promise of CAI SDK compatibility. No model is automatically
ranked or selected as the strongest. Choose **Custom model ID…** for another
model, pinned snapshot or local endpoint model. A blank local choice uses
`CAI_MODEL`; a blank remote choice is an unfinished configuration.

Saved custom IDs are collected from all presets into provider-specific dropdown
entries, including primary, fallback, complex-task, default and planning choices.
Loading a custom choice always retains its exact ID, even if it is absent from
the current reviewed menu. Removing the last preset referencing an ID removes
that saved menu entry; it does not alter any current unsaved selection.

Menu sources, reviewed 2026-11-10:

| Provider | Official source |
| --- | --- |
| OpenAI | https://developers.openai.com/api/docs/models (GPT-5.4 and GPT-5.4 Mini pages confirm Chat Completions support) |
| Anthropic | https://platform.claude.com/docs/en/models/overview |
| Gemini | https://ai.google.dev/gemini-api/docs/models |
| Venice | https://docs.venice.ai/models/text |
| xAI | https://docs.x.ai/developers/models |

## Persistence contract

Presets are stored in the existing local SQLite database with schema version 1,
unique case-insensitive names (1–80 characters), timestamps and revisions.
There can be up to 50 presets. Updates and deletes require the loaded revision;
a concurrent edit/default change returns HTTP 409 rather than overwriting it.
Reload the preset before trying again. Default transfers are transactional.
Existing installations gain the table without replacing runs or evidence.

`GET /api/agent-settings` returns preset summaries, the full default and saved
model IDs. `GET /api/agent-settings/{id}` loads a preset. POST to the collection
creates one; POST to `/{id}` updates it with `revision`; POST to `/{id}/delete`
deletes it with `revision`. These use the existing loopback/origin/JSON boundary.
Bodies contain `name`, `settings`, `is_default`, and an update-only `revision`.

Settings use a strict allowlist. They contain no API keys, endpoint URLs,
targets, HTTP/CLI permissions, credential bindings or execution approvals.
Credentials remain in the existing server-side vault. Saving/loading does not
resolve credentials, enable remote inference, run a model, contact targets or
start an assessment. Incomplete model choices can be saved as drafts; existing
run preflight independently validates complete routes and provider access.
Model reasoning toggles remain off when planning views open.
