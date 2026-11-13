# API Surface

In **Local workspace → API Surface**, select a run with a completed Web source
collector. The workbench reads saved captures and HTTP history for that run.
Search by method, route or parameter name and select a row to see source
locations and matching exchanges. Download individual captures or export the
endpoint list as JSON. Opening or exporting this view sends no target requests.

To save the analysis as part of a workflow, connect **Web source collector →
API Surface**. The node accepts the collector report and emits `endpoints`.
The Web reconnaissance starter can add this node automatically. Its result
is a run artifact and a snapshot of the HTTP history available when the node
runs. The workbench recomputes matches from saved evidence, including later
imports. The collector may make network requests under the run's existing
scope and budget. The API Surface node itself reads local evidence only.

## Endpoint evidence

| Evidence | Meaning |
| --- | --- |
| Inferred | Literal request call parsed from source |
| Observed | Same normalized origin, exact path and method in completed native HTTP history |
| Imported match | Same method and route in an imported HTTP exchange |

Endpoint IDs are stable hashes of method, normalized origin and exact path.
The output lists parameter names from URL queries and literal Axios `params`
objects. It excludes query and parameter values. Source locations link to the
original capture and include a 1-based line and UTF-8 byte column. Embedded
source-map entries also carry their original source name. A traffic match
records a request/response pair. It makes no claim about which code sent the
request or whether access was authorized.

The parser handles literal `fetch`, `window.fetch`, `globalThis.fetch`, and
Axios calls, including literal Axios `baseURL` and `method` options. It parses
saved JS, TypeScript, JSX/TSX, chunks and embedded source map contents. Relative
routes use a captured page ancestor when available. Root-relative routes fall
back to the source origin. Absolute routes are checked against the run's
original scope. Dynamic URLs, configured client aliases, GraphQL operation
extraction, and indexed source-map sections are outside this first version.

Each analysis examines at most 200 captures, 200 source documents and 2 MB of
source text, and retains up to 500 endpoints. It checks up to 5,000 completed
or imported exchanges. The result exposes truncation, parse warnings, omitted
routes and limits. Source files are parsed as data and never executed.

## Tool inspector

Select a catalog tool and open **Configure → Arguments**. Search by flag or
label, check boolean options, enter typed values, and use **Configured only**
to review saved overrides. Clearing a field restores the tool default. The
command preview shows the base argv and selected flags. Preflight resolves file
bindings and adds adapter-owned options. Restricted arguments show their
reason and remain disabled.

**Input bindings** lists the registered files and folders supported by that
adapter. A selected registered input overrides a connected input on the same
socket. Argument edits and bindings are saved with the workflow.
