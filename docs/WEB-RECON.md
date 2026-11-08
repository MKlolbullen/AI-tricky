# Host scope and web source collection

| Entered scope | Active host authorization |
| --- | --- |
| `example.com` | Apex host only |
| `*.example.com` | All nested subdomains, excluding `example.com` |
| Both entries | Apex and all nested subdomains |
| `https://app.example.com/api` | Exact scheme, host and port, at `/api` and its descendant paths |
| IP or CIDR | Entered address or bounded address range; unchanged |

Wildcard scope is a selector, never a probe address. `*.example.com` matches `api.example.com` and `a.api.example.com`, never `example.com.evil.test`, a resolved IP, or an external CNAME/CDN hostname. Wildcard URLs, IP wildcards and partial/multiple stars are rejected. Domain names are normalized through IDNA. URL paths and pinned native transports retain their existing checks.

The domain source converts an explicitly selected wildcard to its apex **as a passive enumeration seed**. Passive enumeration may retain discovered descendants of an exact domain as data; this does not authorize probing them. Every active consumer checks the immutable original scope. Use both scope entries when you want to test both the apex and descendants. Native inventory records a discovery requirement instead of resolving a literal wildcard.

## Starter workflow

In **Local workspace → Targets**, add/select the domain and/or wildcard scopes and choose **Load web recon workflow**:

1. Selected enumeration domains feed `subfinder` and `assetfinder` independently.
2. A typed merge deduplicates discovered hosts and the apex seed; `httprobe` receives only active-authorized concrete hosts through stdin. An exact apex can run even when enumeration returns only subdomains. A wildcard-only apex seed is filtered out.
3. Probed URLs feed `katana` with JavaScript parsing. The adapter disables redirects, uses FQDN field scope and supplies a server-generated URL scope-regex file.
4. Probed and crawled URLs are deduplicated and passed to the **Web source collector** native node.
5. A summary links the per-node results and captures through the existing artifact dock.

Loading does not run tools. Enable network/CLI execution, inspect budgets and preflight, then start the workflow. Install the four CLI binaries locally; no Docker or model key is needed. A URL-only workflow can instead connect a URL source directly to the collector, or connect **HTTP evidence → Web source collector** to reuse a captured page.

**Load web recon with path fuzzing** adds a separate `ffuf` branch after probing. Bind a registered wordlist in its inspector or connect a registered wordlist source. Preflight blocks missing wordlists. Concrete URLs without a `FUZZ` marker get `/FUZZ` appended under the authorized path; custom path/query markers remain explicit. Fuzz results are captured observations; they do not automatically verify findings.

## Captures and limits

The collector follows HTML script/link/page references, static quoted source/chunk references and `sourceMappingURL` directives. It recognizes JS/MJS/CJS/JSX, TS/TSX, `.chunk`, `.webchunk`, `.map`, CSS, JSON, manifests, GraphQL, text, XML and YAML. It does not guess paths or execute JavaScript. It honors HTML base URLs and independently checks every resolved URL against scope.

Defaults are 10 pages, 40 source files and depth 2 per collector node. Inspector ceilings are 50 pages, 200 files and depth 5; zero disables that category/depth expansion. There is a 1000-URL/reference ceiling and a 128 KiB capture limit per HTTP response. All native GETs share the existing run operation budget, pause/cancel controls and deadline. Reused upstream HTTP captures incur no new request. Source parsing uses the full bounded saved capture, rather than the model's 16 KB preview.

Inspect `node-<id>.json` for a manifest with URL, kind, discovery parent, depth, response status, capture artifact ID, body hash/size and truncation state. Original bounded response bodies live in the linked `http-N.json` artifacts. Map source names and presence of embedded `sourcesContent` are recorded; local/webpack source paths are not requested. Counts expose skipped scope/depth/page/asset/reference limits, errors and unattempted work after budget exhaustion. Redirects are recorded and never followed by the native collector.

This is bounded, discovery-led collection. Dynamic imports assembled at runtime, authenticated content and unlinked files can remain absent. “Not observed” is not evidence of absence. The current collector saves decoded textual HTTP captures, not a byte-exact binary archive.

Native transport enforcement is per request. CLI input checks and Katana's own scope flags are application/tool controls, **not an OS network sandbox**. Tool-internal requests, DNS behavior and upstream bugs are outside the native request counter; only process launches use the CLI budget. Katana field scope can also narrow crawling to each seed FQDN even when a wider wildcard is authorized. Consult the installed CLI version's behavior before relying on it for an engagement.

Official Katana flag reference: https://github.com/projectdiscovery/katana#usage
