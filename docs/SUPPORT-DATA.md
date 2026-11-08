# Templates, resolvers and other support files

Use **Local workspace → Inputs → Templates, resolvers and wordlists** to install the bundled files or download pinned upstream packs. The same bundled installer is available in workflow Run setup. **Use installed support files** fills missing compatible bindings on the canvas; it preserves existing references and connected wordlists. It does not start an assessment.

The CLI uses the same data directory and input registry as the API:

```bash
python3 scripts/setup-support-data.py
python3 scripts/setup-support-data.py --install nuclei-templates --install jaeles-signatures
python3 scripts/setup-support-data.py --status
```

Set `AI_TRICKY_DATA_DIR` or pass `--data-dir` when the server uses another data directory. Existing `OFFSECS_U_AI_DATA_DIR` and `RECONFORGE_DATA_DIR` configurations remain supported. No Docker is required. `scripts/install-tools.sh` installs binaries separately and now points to this setup step.

## Included data

| Pack | Contents | Default binding |
| --- | --- | --- |
| Nuclei HTTP starter | Seven unmodified upstream exposure templates: Git, SVN, Composer, Docker Compose, NPM, webpack config and webpack source maps; MIT license and `.nuclei-ignore` | `nuclei` templates |
| Trickest trusted resolvers | Pinned upstream `resolvers-trusted.txt` and MIT license | `massdns`, `shuffledns` and PureDNS resolvers/trusted resolvers |
| Trickest public resolvers | Pinned upstream `resolvers.txt` and MIT license | Explicit selection in inspector |
| Small directory paths | Independently authored starter paths | Directory fuzzers, including ffuf |
| Rooted HTTP paths | Leading-slash paths for tools such as `meg` | `paths_file` inputs |
| Small DNS labels | Independently authored starter labels | DNS wordlist adapters |
| Interesting files / extensions | Source/configuration paths and JS/TS/map/chunk extensions | Explicit selection in inspector |
| GF patterns | Already bundled; copied into each GF job's private home | Existing GF adapter |
| Payload lists | Already bundled with the MIT-licensed mini-tricky source | Existing typed payload node |

The starter wordlists are deliberately small. Register a larger reviewed list when needed. The resolver lists are upstream snapshots, **not a claim that each resolver was tested from your network**. Resolver selection permits DNS-provider traffic; it does not authorize active assessment of those resolver addresses.

The Nuclei starter covers a small exposure subset, not the complete template catalog. These are active GET checks only when a workflow is launched; installation and binding make no target requests. Larger templates and signatures can be chosen explicitly after installation.

## Optional upstream packs

The committed `support-data/manifest.json` records source commit IDs, download URLs, archive SHA-256 values, bundled file SHA-256 values and license locations. Installation uses those exact versions. It does not fetch `latest` or update an existing version in place.

**Nuclei templates:** the complete pinned upstream tree is retained in `support-data/nuclei-templates-<version>/upstream` beneath the configured local data directory. HTTP categories are copied into independently registered views that retain `http/<category>` paths, `helpers/`, `.nuclei-ignore` and `LICENSE.md`. The current pin produces 18 HTTP category views, including CVEs, exposures, misconfigurations, technologies and takeovers. Non-HTTP formats remain available in the upstream tree for inspection and separate compatible input selection; they are not automatically bound to HTTP workflows.

The full tree exceeds the existing 20 MB / 10,000-file folder-input ceiling. Each registered category view is checked against that ceiling; the general limit remains unchanged. Future larger categories fail installation rather than silently dropping templates or raising limits. A run copies the selected view into its private `HOME/nuclei-templates`, keeping helper paths available without using the operator's home directory. `-t`, redirect disabling, OAST disabling and update-check disabling remain server-owned.

**Jaeles signatures:** the pinned signature tree is a separate registered folder for Jaeles. Its upstream README declares MIT licensing and is retained. Nuclei templates are never automatically substituted as Jaeles signatures. The pack installs data, not the Jaeles executable.

The optional full Nuclei pack provides the takeover-specific default only for `nuclei-takeover`. General `nuclei` bindings continue to use the clearly named small starter until the operator selects another category in the inspector.

## Integrity and recovery

Installed inputs live in versioned directories below the configured data directory. Every installed file and folder is registered with a content fingerprint. Preflight, binding and execution reject a changed pinned folder; the private job copy is checked again. Ordinary user-registered project folders retain their existing editable behavior.

Downloads are bounded to 50 MB compressed, 100 MB expanded and 30,000 archive files. The installer verifies the archive hash before extraction and rejects traversal, links, special files and duplicate paths. It writes into a temporary directory and publishes a complete version once. Existing versions and user changes are not overwritten. Repeating setup reuses registrations; an interruption after publication can resume missing database registrations from the package receipt.

Updating support data is an explicit source-lock change: review the upstream commit, refresh archive/file hashes and licenses, and install as a new version. Binding-role changes also install a new version so prior receipts cannot mask a newly required binding. Old input IDs and run snapshots remain intact. Missing binaries, API credentials, SBOMs, source folders, custom resolver files and tool-specific wordlists still appear in normal preflight; generic defaults are not fabricated for them.

CLI input checks and template pins do not turn third-party tools into an OS network sandbox. Tool-internal traffic remains separately accounted from native HTTP/TCP requests.

## Workflow catalog coverage

AI-tricky already contains the pinned MIT-licensed mini-tricky catalog: 151 tools and 57 migrated workflows, plus the original curated presets. That is not the complete Trickest platform catalog. Common recon, crawling, fuzzing and Nuclei tool contracts already exist, so adding another descriptor for the same tool is usually unnecessary.

AI-tricky workflow JSON and supported mini-tricky graphs can be imported today. Trickest platform exports require a format-specific mapping; they are not advertised as directly executable. Preserve node/tool versions, typed ports, required data, input/output paths and source/license provenance when adapting a workflow. Unknown tools or script nodes need a reviewed adapter contract rather than imported shell strings. A missing binary differs from a missing adapter or required data pack.

Public references:

- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/trickest/resolvers
- https://github.com/jaeles-project/jaeles-signatures
- https://github.com/trickest/trickest-cli
- https://github.com/trickest/recon-and-vulnerability-scanner-template
