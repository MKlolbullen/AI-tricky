# Web Application Assessment Template

A curated workflow starter that maps the Web Application Penetration Testing methodology from [0xlolbullen.com](https://0xlolbullen.com/pentest-methodology) onto AI-tricky.

The graph is **built and type-validated by the server** (`backend/web_recon.web_app_assessment_workflow`, served at `GET /api/workflow-starters/web-app-assessment`). The curated catalog entry (`src/templates.json`, id `tpl-web-app-assessment`) carries only the description and the starter name, so the workflow cannot drift from the tool and native socket contracts.

## Methodology alignment

| Methodology focus | Workflow coverage |
|-------------------|-------------------|
| Automated reconnaissance | subfinder + assetfinder → unique hosts → httprobe → Katana |
| Evidence journal | Native HTTP evidence capture of the probed and crawled URLs |
| Modern web technologies (JS, APIs, SPA) | Web source collector (JavaScript and source maps) → native API Surface |
| OWASP Top 10 / exposure | Nuclei with the bundled reviewed HTTP templates |
| Content discovery | Bounded ffuf path fuzzing with a registered wordlist |
| Systematic review | Evidence-only CAI specialist team → evidence summary |

Authentication, session and access-control testing are **not canvas nodes**. They start from the HTTP observations this workflow saves: use the multi-identity access matrix and authenticated object verification, which have their own reviewed, single-use approvals (see [Controlled verification](CONTROLLED-VERIFICATION.md)).

## Usage

1. Open the Template Library and choose the **AI-tricky starters** source (or **All sources**).
2. Select **Web Application Assessment** and load it onto the canvas.
3. Select authorized domain targets for the run. `example.com` is an exact host; `*.example.com` covers its subdomains.
4. Install the bundled support data first (Local workspace → Inputs) so the starter binds the Nuclei HTTP starter templates and a small path wordlist automatically; otherwise bind a templates folder and a wordlist yourself.
5. Run preflight, then execute under your scope, request and CLI budgets.
6. Review detections and agent proposals in the evidence workbench. Nothing is auto-confirmed.

## Notes

- The specialist team node needs the optional CAI runtime and a configured model. Delete that node to run the rest of the workflow without CAI.
- External binaries (subfinder, assetfinder, httprobe, Katana, Nuclei, ffuf) are installed separately; preflight reports their readiness.
- CLI tools are counted as process launches. Their internal requests are not limited by the native request cap unless an enforced CLI scope profile is used.
- `docs/templates/web-app-assessment-workflow.json` is an importable export of the same graph. Regenerate it with `python scripts/export-starter-templates.py`; the test suite fails when it is stale.
- Provenance: derived from the public methodology description on 0xlolbullen.com.
