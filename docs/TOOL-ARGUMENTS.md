# Tool argument overlay

The migrated catalog (`src/mini-tricky-catalog.json`) is pinned to its upstream commit and is never edited. Extra arguments for a tool live in `src/tool-argument-overlay.json` and are merged into the executable tool contracts when the backend loads. The argument inspector marks them `verified <version>`.

## What it contains

| Tool | Pinned version | Catalog args | With overlay |
|------|----------------|--------------|--------------|
| subfinder | v2.17.0 | 6 | 14 |
| httprobe | v0.1.3 (pinned commit) | 1 | 5 |
| ffuf | v2.1.0 | 12 | 34 |
| katana | v1.8.0 | 9 | 28 |
| nuclei | v3.11.1 | 11 | 34 |
| httpx | v1.12.0 | 15 | 56 |
| dnsx | v1.3.1 | 9 | 22 |
| urlfinder | v0.0.3 | 0 | 7 |
| gau | v2.2.4 | 4 | 13 |

It also corrects catalog entries that were wrong for the pinned versions:

- Katana `-kf` and `-ef` were typed as switches but take a value, so selecting them produced a broken command line.
- dnsx `-rc` (response-code filter) was typed as a switch but takes a value.
- httpx `-location` shows the redirect target a response names. Its catalog label read as a redirect-policy setting, which hid it; it is relabelled and does not make httpx follow redirects.

subfinder, httprobe, Katana and Nuclei are pinned in `toolchains/web-recon.tsv`, ffuf in `toolchains/enforced-cli.tsv`, and httpx, dnsx, urlfinder and gau in `toolchains/recon-extras.tsv` (install with `scripts/install-tools.sh --recon-extras`). Once a tool is pinned, **Run setup → Check workflow readiness** and **Scanner profiles** also report whether the binary AI-tricky found is that version.

Only tools whose exact version is pinned in `toolchains/*.tsv` are covered, because that is what lets every flag be checked against the real binary. The other catalog tools keep their upstream arguments.

## Rules

An overlay entry is rejected at load (the backend refuses to start) when it:

- names a tool that is not in the migrated catalog, or omits the pinned package and version;
- repeats a flag the catalog already defines, a token of the tool's fixed command, or a flag the adapter appends itself (update checks, redirect policy, crawl scope, template folder, proxy routing);
- would be restricted anyway: output paths, configuration files, proxies, headers, cookies, callbacks, scripts, credentials or redirect policy;
- carries any field other than `flag`, `label`, `description`, `type` and `default`.

Deliberately left out even though the binaries support them: target and list inputs, file-reading options, HTTP method and body, TLS verification switches, remote template URLs, code and fuzzing templates, cloud uploads, third-party search engines, port scans, headless browser options, screenshots, custom resolvers, stored responses and anything that changes the output format the adapter parses.

Some flags pass the rules above and still do not belong, which only a real run shows. Each was dropped after a loopback smoke run:

- httpx `-fpt` (page-type filter) downloads a classifier model from a third-party host the first time it is used.
- Katana `-fpt` suppressed all output in the pinned version.
- Nuclei `-hpd` and `-hpt` add a non-JSON line to the output the adapter parses.

Values still pass the existing server validation: switches are booleans, numbers are bounded, strings cannot start with `-` or contain control characters. Arguments are passed as separate argv entries; no shell is involved.

Enforced CLI scope keeps its own narrower allowlist: scoped ffuf accepts only `-mc`, `-fc` and `-fs`; scoped Katana only `-d` (1–5) and `-jc`; scoped Nuclei only `-severity`, `-tags` and `-etags`; scoped httprobe accepts no overrides.

## Verification

`backend/tests/test_tool_argument_overlay.py` runs each pinned binary with `-h` and checks that:

- every catalog, overlay, command and adapter flag exists in that version;
- no two of them are aliases of the same option;
- switches and valued flags match what the help output declares.

CI runs this in the jobs that install the pinned binaries (`web-recon-cli` for subfinder, httprobe, Katana, Nuclei, httpx, dnsx, urlfinder and gau; `enforced-cli` for ffuf) and fails if a required binary is missing. Locally, point `AI_TRICKY_ARG_HELP_BIN` at a directory holding the pinned binaries; without it the help checks are skipped.

Help output proves a flag exists and what kind of value it takes. It does not prove the flag behaves well in every workflow. The httpx additions were also run against a loopback fixture; the dnsx, urlfinder and gau additions were only checked to parse, because DNS and the passive sources they query are not reachable from the test environment.

## Adding a tool

1. Pin its package and version in a `toolchains/*.tsv` file so the installer and CI build that exact version.
2. Add the tool to `src/tool-argument-overlay.json` with the same package and version.
3. Add it to `AI_TRICKY_ARG_HELP_REQUIRED` in the CI job that installs it.
4. Run each new flag once against a loopback fixture and watch for unexpected downloads, extra output lines or empty output.
