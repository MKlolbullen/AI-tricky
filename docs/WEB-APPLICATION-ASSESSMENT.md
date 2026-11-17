# Web Application Assessment Template

A curated workflow template that maps the Web Application Penetration Testing methodology from [0xlolbullen.com](https://0xlolbullen.com/pentest-methodology) into AI-tricky.

## Methodology alignment

| Site methodology focus | Template coverage |
|------------------------|-------------------|
| Automated reconnaissance pipelines | Subfinder → HTTPX → Katana + JS collection |
| OWASP Top 10 / exposure & injection | Nuclei + bounded FFUF + HTTP evidence journal |
| Modern web technologies (JS, APIs, SPA) | GetJS / source-map collection → native API Surface |
| Authentication & session management | Native identity / multi-identity access matrix |
| Business logic & access control | Authenticated object access + controlled verification |
| Systematic review & evidence | Specialist agent team (`native_team`) → Findings workbench |

## Usage

1. Open the Template Library.
2. Filter to category **Web Assessment** or search for “Web Application Assessment”.
3. Load the workflow onto the canvas.
4. Register authorized scope, any required wordlists, and credentials in Local Workspace.
5. Run preflight and execute under your budgets and scope controls.
6. Review candidate findings and agent proposals in the evidence workbench. Nothing is auto-confirmed.

## Notes

- Uses existing catalog tools (subfinder, httpx, katana, nuclei, ffuf, getjs) plus native nodes for API surface, identity review, and the multi-role agent team.
- External binaries must be installed separately; preflight reports readiness.
- Provenance: derived from the public methodology description on 0xlolbullen.com. Not a full export of any private category breakdowns.
- Agent outputs remain candidates until supported by evidence and human review.

See the workflow definition in `src/templates.json` (id: `tpl-web-app-assessment`).
