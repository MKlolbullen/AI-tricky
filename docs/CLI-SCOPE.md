# Enforced CLI scope on Linux

The **Enforced** profile runs pinned ffuf v2.1.0 in a Bubblewrap network namespace with a private loopback interface. The ffuf process can reach a local relay. AI-tricky checks the path against the bound wordlist, resolves the selected HTTP(S) target, applies the normal native request budget, and saves the exchange in HTTP history. The same budget covers any other native operations in the workflow.

## Set up and run

1. Install Bubblewrap from your Linux distribution. The local user running AI-tricky must be able to start Bubblewrap with user and network namespaces. On Ubuntu 24.04, check the distribution's AppArmor user namespace policy if preflight fails.
2. Run `./scripts/install-tools.sh --enforced-cli`. Put `$HOME/.local/share/ai-tricky/enforced-cli/bin` on the AI-tricky server's `PATH` before launching the app. The profile installs statically built ffuf and the relay. The standalone app uses the same external tools.
3. In **Local workspace → Targets**, add and select the authorized HTTP(S) base URL, for example `https://app.example.test/app`. Select **Load scoped ffuf**.
4. Install and bind **Small directory paths** in **Run setup**, or register and bind a custom list in the ffuf inspector. Use literal relative entries such as `health` and `api/v1`. Each list can have up to 2,048 distinct ASCII paths and occupy up to 128 KiB.
5. In **Run setup**, enable workflow traffic and catalog CLI execution. Select **Direct** HTTP routing, set the native request and CLI launch budgets, and check readiness before starting.

## Requests and evidence

- The profile sends GET requests for the bound paths. A base URL expands to `/FUZZ` under that base path. An explicit placeholder must be the final path segment. Queries, custom request headers, redirects, recursion, CONNECT and raw or general-purpose proxy traffic are disabled.
- The selected tool inspector supports **Match Codes**, **Filter Codes** and **Filter Size** on the scoped ffuf starter. The application owns the scanner URL, relay and other arguments.
- AI-tricky connects to each destination with its existing DNS/IP binding and TLS verification. ffuf receives the status, headers and bounded response body from the saved exchange. Body-size filters therefore measure the content available in the capture. Responses beyond the capture limit are marked in HTTP history.
- Each ffuf match links to an HTTP exchange ID. The CLI artifact records gateway attempts, denials and exchange IDs. A network failure may produce a journal entry with an error. A rejected path or exhausted budget produces no destination request.
- Preflight checks Bubblewrap and starts the pinned scanner inside the namespace. The scoped starter preserves its enforcement requirement when saved. The enforced profile supports ffuf as its only external CLI, and preflight blocks incompatible nodes or Burp proxy routing. Standard mode uses adapter input checks and its separate CLI launch budget.
