# Enforced CLI scope on Linux

The **Enforced** profile runs pinned ffuf v2.1.0, httprobe, Katana v1.8.0 and Nuclei v3.11.1 in a Bubblewrap network namespace with a private loopback interface. Each scanner can reach only its private local relay. AI-tricky checks every destination, resolves the selected HTTP(S) target, applies the normal native request budget, and saves the exchange in HTTP history. The same budget covers any other native operations in the workflow.

ffuf and httprobe get their exact routes bound before launch. Katana and Nuclei choose their own request URLs, so each of their requests is authorized against the entered scope when it reaches the gateway.

## Set up and run

1. Install Bubblewrap from your Linux distribution. The local user running AI-tricky must be able to start Bubblewrap with user and network namespaces. On Ubuntu 24.04, check the distribution's AppArmor user namespace policy if preflight fails.
2. Run `./scripts/install-tools.sh --enforced-cli`. The app finds the default profile directory and resolves executables on `PATH` first. The profile installs statically built scanners and the relay. The standalone app uses the same external tools.
3. In **Local workspace → Targets**, add and select the authorized HTTP(S) base URL, for example `https://app.example.test/app`. Select **Load scoped ffuf**.
4. Install and bind **Small directory paths** in **Run setup**, or register and bind a custom list in the ffuf inspector. Use literal relative entries such as `health` and `api/v1`. Each list can have up to 2,048 distinct ASCII paths and occupy up to 128 KiB.
5. In **Run setup**, enable workflow traffic and catalog CLI execution. Select **Direct** HTTP routing, set the native request and CLI launch budgets, and check readiness before starting.

## ffuf requests and evidence

- The profile sends GET requests for the bound paths. A base URL expands to `/FUZZ` under that base path. An explicit placeholder must be the final path segment. Queries, custom request headers, redirects, recursion, CONNECT and raw or general-purpose proxy traffic are disabled.
- Each bound path is dispatched at most once per ffuf invocation. A repeated request is denied without destination traffic, so each ffuf match maps to exactly one saved exchange.
- The selected tool inspector supports **Match Codes**, **Filter Codes** and **Filter Size** on the scoped ffuf starter. The application owns the scanner URL, relay and other arguments.
- AI-tricky connects to each destination with its existing DNS/IP binding and TLS verification. ffuf receives the status, headers and bounded response body from the saved exchange. Body-size filters therefore measure the content available in the capture. Responses beyond the capture limit are marked in HTTP history.
- Each ffuf match links to an HTTP exchange ID. The CLI artifact records gateway attempts, denials and exchange IDs. A network failure may produce a journal entry with an error. A rejected path or exhausted budget produces no destination request.
- Preflight checks Bubblewrap and starts the pinned scanner inside the namespace. The scoped starter preserves its enforcement requirement when saved. The enforced profile supports ffuf, httprobe, Katana and Nuclei. Preflight blocks incompatible nodes and Burp proxy routing. Standard mode uses adapter input checks and its separate CLI launch budget.
- The Bubblewrap and relay hashes are checked again at the CLI admission point, after any pause, together with the ffuf hash. A changed helper fails the launch before the CLI budget is counted.
- Evidence-guided proposal reviews and workflow recovery inherit the source run's enforcement mode and bind the helper hashes. A CLI proposal unsupported by the enforced profile fails its review instead of running in standard mode.

## Katana and Nuclei requests and evidence

Select **Load scoped web recon** to chain scoped httprobe, Katana and Nuclei from the selected hosts and URLs. Bind a reviewed templates folder to the Nuclei node; the bundled HTTP starter templates are bound automatically once installed.

- The scanner has no network route and no DNS. It sends each request to the private relay as a proxy request. HTTPS is terminated inside the namespace by the relay with a throwaway in-memory certificate, so the gateway sees the full URL. The real connection, with certificate and hostname verification, is made outside the namespace by AI-tricky's scoped transport.
- The gateway accepts only `GET`, authorizes the URL against the entered scope, and forwards nothing the scanner supplied: no headers, cookies or bodies. An exact host, a wildcard and a URL prefix keep their usual meaning. Anything else is refused without destination traffic and recorded as a `cli.scope_denied` event.
- Each distinct URL is fetched at most once per invocation. A repeated request is answered from the saved exchange. Every fetch counts against the native request budget; when the budget is spent the scanner receives a local error and no request is sent.
- Katana output keeps only URLs inside the entered scope. A Nuclei detection is kept only when its matched URL has a saved target response in the same invocation, so a refused or failed request can never appear as a finding.
- Nuclei runs HTTP templates only (`-pt http`) with interaction servers, redirects and update checks disabled. Templates that need another method, custom headers, a request body or a non-HTTP protocol do not work in this profile; their requests are refused and counted as denials.
- The profile owns the scanner arguments. The inspector allows Katana **Depth** (1–5) and **JS Crawl**, and Nuclei **Severity**, **Tags** and **Exclude Tags**.
- An invocation accepts up to 64 authorized seed URLs. A concrete host expands to its HTTPS and HTTP root.
- Passive discovery tools such as subfinder and assetfinder query third-party services and cannot run inside the namespace. Enforced runs reject them; the scoped chain starts from the entered targets.

Limits to keep in mind: this profile constrains where requests can go and records each one, but it does not make a crawl or template set safe by itself. Review the templates you bind, and set the request budget for the size of the target.

See the [scanner beta guide](SCANNER-PROFILES.md) for scoped httprobe and installation diagnostics.
