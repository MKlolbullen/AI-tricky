# Trickest open-source tools and workflow adaptations

Open **Templates → Catalog source → Trickest open source**. The pack contains
two local tool adapters and three workflows. Install the generators with the
pinned tool profile:

```bash
./scripts/install-tools.sh --trickest-oss
export PATH="$HOME/.local/share/ai-tricky/trickest-oss/bin:$PATH"
.venv/bin/python scripts/check-recon-tools.py --profile trickest-oss
```

Launch AI-tricky with that PATH. Preflight reports installed versions, missing
binaries and input requirements. The installer keeps per-tool diagnostics.
For the recon workflow, install the separate `--web-recon` profile and include
its bin directory on PATH as well.

| Workflow | Required inputs | Output |
| --- | --- | --- |
| Subdomain candidates | Selected domain or wildcard scope and a small DNS wordlist | mksub generates candidate subdomains for review |
| URL path candidates | Selected HTTP(S) URL and a small relative path wordlist | mkpath generates candidate URLs beneath the base path |
| Recon and vulnerability scanner | Domain or wildcard scope, web recon binaries and reviewed Nuclei templates | Local probing, crawling, HTTP source captures and scanner findings candidates |

Register **Inputs → Templates, resolvers and wordlists → Install bundled support
files** before loading a workflow to bind its bundled input automatically. For
a loaded canvas, use the support data binding action or select the input on
the node. Generator wordlists accept 1–32 distinct ASCII entries in at most
4 KiB. Each tool generates two levels of combinations. Use DNS labels for
mksub and relative paths for mkpath. The mkpath base must be a query-free URL
of at most 512 characters.

The generator templates run offline and save typed candidate streams. Active
downstream tools independently check the selected scope. An entered exact
domain supports generating subdomain candidates. Select an explicit wildcard
scope before authorizing probes against its descendants. Use **Run setup →
Check workflow readiness** to review bindings and budgets before running.

The recon entry adapts the upstream public GitHub example to the existing
local web recon workflow. The upstream example dispatches a named hosted run
through Trickest's GitHub Action. The CLI can retrieve hosted run details and
outputs. Importing additional hosted workflows requires a supported portable
workflow representation and mappings for their tools, scripts and bindings.
[Public recon example](https://github.com/trickest/recon-and-vulnerability-scanner-template/tree/45b274fedd3d1297157775740da8f4ba44e72233)
· [Trickest CLI](https://github.com/trickest/trickest-cli/tree/367ef60d39c60957db5f66fb432a8cb777ef363b)

The pack pins [mksub v1.1.1](https://github.com/trickest/mksub/tree/c344238667a0fac7a76c9fbb654f50f74681a199)
and [mkpath v1.1.0](https://github.com/trickest/mkpath/tree/df878ebf4eb06bd816ec8343ed9329d4a3a284b0).
CI installs both versions and runs the two generator DAGs with fixture inputs.
