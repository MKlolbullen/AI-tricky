# HTTP routing and retained exchanges

Local workspace → Run setup offers **Direct** and **Burp / HTTP proxy**. Native target HTTP always records requests and responses locally in either mode. The same transport serves inventory, workflow HTTP nodes, source collection, controlled verification and live agent HTTP tools. Recording requires neither Burp nor a model.

Choose **HTTP history**, or **Inspect run HTTP traffic** in a run, to filter by run/URL, inspect headers/body, download binary bodies or exchange JSON, and export the displayed page as HAR. The UI exports 25 items per page; the API permits up to 100 and includes `total`, `offset`, `limit` and `has_more`. Exporting sends no target requests. Older response artifacts stay available in their original runs; missing historical requests are not reconstructed.

## Proxy setup

1. Run a local HTTP proxy listener, such as Burp or mitmproxy. The default is `http://127.0.0.1:8080`. Endpoints must be literal loopback addresses or `localhost`, without credentials, path, query or fragment. Remote proxies and SOCKS are outside this increment.
2. Select **Burp / HTTP proxy** and enter the listener URL. If interception is enabled, forward held requests within the native transport's 10-second socket timeout.
3. For HTTPS interception, export the proxy's CA as PEM or DER, register the file in **Inputs**, then select **Additional trusted CA**. System trust remains enabled alongside that CA; certificate/hostname verification is never disabled. A CA may also be selected for direct traffic to a private-CA test service.
4. Start the run through its normal controls. Proxy failure is recorded and does not trigger a direct fallback.

Routing settings and CA content hashes are saved in run configuration and bound into proposal/recovery reviews. Changed CA contents require a new review. Recovery inherits the source route unless explicitly changed in its new settings. Model inference and passive-provider API calls keep their separate transports.

For native HTTPS, CONNECT names the locally checked target IP; TLS uses the original hostname for SNI and certificate validation. Native HTTP uses an absolute request URI with that IP and the original Host header. A proxy can alter its upstream routing or messages. The journal records what the application sent and received; it cannot assert what the proxy sent upstream. `resolved_target_ip` is distinct from an observed origin peer. Proxy captures have `origin_peer_observed: false` and legacy `connected_ip: null`, so controlled checks requiring equal observed peers remain inconclusive.

## Capture boundaries

An admitted native request is persisted before dispatch, including failed attempts. Responses retain duplicate headers, status, reason, HTTP version and base64 entity bytes. Bodies are capped at 128 KiB; headers at 64 KiB / 100 fields. Truncation is explicit. Text previews are capped at 16,000 characters; JSON/body downloads retain all captured bytes. Native headers are normalized; TLS and transfer framing are not recorded.

Cancellation marks in-flight exchanges. A worker already receiving a response can finish saving it after the run stops; the run stays cancelled. Process interruption leaves a durable request marked interrupted on restart. Denied requests and exhausted budgets remain events without claiming dispatched traffic. Headers/bodies may contain target cookies, tokens or sensitive data; exports contain that same evidence. Full journal fields are excluded from model tool returns; existing selected headers and bounded text evidence remain model-visible under the chosen provider configuration.

## CLI coverage

External binaries own their clients and keep separate process-launch accounting. Preflight reports capture coverage per tool:

| Tool | Proxy mode | Local capture |
| --- | --- | --- |
| httpx | Owned `-http-proxy` flag | Tool output; full exchanges in external proxy history |
| katana | Owned `-proxy` flag | Tool output; full exchanges in external proxy history |
| nuclei / nuclei-takeover | Owned `-proxy` flag | Tool output; full exchanges in external proxy history |
| ffuf | Owned `-x` flag | Tool output; full exchanges in external proxy history |
| dnsx, puredns, shuffledns, massdns, naabu, nmap, rustscan, tlsx | Direct DNS/TCP/TLS | Tool output; no native HTTP capture |
| Other active HTTP adapters, including httprobe | Proxy preflight rejects | Select a supported adapter or direct mode |
| Offline/passive adapters | Existing separate transport | Existing tool artifacts |

Direct CLI mode stores tool output, not automatic complete exchanges. Supported tools receive a merged CA bundle through child-only trust variables when a CA is selected; TLS behavior still depends on the tool/version. Flags/trust variables are not proof that every binary request follows the proxy. Native IP pinning does not constrain traffic inside binaries. Ambient proxy environment is not inherited by CLI jobs.

To retain CLI captures locally, export selected Burp history entries as **saved-items XML**, choose the matching run and **Import Burp saved-items XML**. Imports accept 1–100 items / 10 MB, including base64 binary messages. Every exported URL must fit that run's original scope; the entire batch is checked before persistence. Identical XML imported into the same run is idempotent. Reordered/edited exports have a different identity and may create additional records.

Imports are labelled `burp_xml` / externally supplied evidence. They preserve exported headers and bounded bodies without replay, model calls, changing run counts or verifying findings. The exported URL is scope-checked; Host headers, upstream peer and other export metadata are not independently authenticated. Use the [local Burp bridge](BURP-BRIDGE.md) for selected exchanges directly from Burp and manual Repeater handoffs. XML imports remain available for file-based exchange transfer.

## API

Run, proposal execution and recovery settings accept:

```json
{"http_routing":{"mode":"proxy","proxy_url":"http://127.0.0.1:8080","ca_input_id":null}}
```

- `GET /api/http-history?run_id=…&q=…&limit=25&offset=0`
- `GET /api/http-history/{exchange_id}`
- `GET /api/http-history/har?run_id=…&limit=100&offset=0`
- `POST /api/runs/{run_id}/http-history/import` with `{"xml":"<items>…</items>"}`

References: [Burp listener settings](https://portswigger.net/burp/documentation/desktop/settings/tools/proxy), [httpx](https://github.com/projectdiscovery/httpx), [katana](https://github.com/projectdiscovery/katana), [Nuclei](https://github.com/projectdiscovery/nuclei), [ffuf](https://github.com/ffuf/ffuf).
