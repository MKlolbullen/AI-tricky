# Catalog migration — 0.4
All 151 source tool definitions and 57 built-in workflows are migrated. The original 22 curated workflows/presets and legacy schema imports remain available. The source is pinned to mini-tricky commit `96971000b0058423da52884d9028250ab76b0633` with its MIT license and source-file hashes.
**141 tools have CLI execution adapters. Ten entries are migrated with explicit context restrictions.** A CLI adapter does not imply that a compatible binary is installed, configured or validated against every upstream release. Preflight checks binary presence, hashes the executable, validates sources and reports missing context. No external security binary is included in the ZIP.
Required support files can now be installed and bound through **Local workspace → Inputs**; see [Support data](SUPPORT-DATA.md) for pinned Nuclei templates, Jaeles signatures, resolvers, wordlists and catalog compatibility.
## Execution contracts
- Commands come from the application-owned catalog. Graphs can select typed inputs and allowlisted arguments, but cannot supply commands, executable paths, environment dictionaries or shell strings.
- Multiple output sockets retain their names and edge bindings. Scalar targets fan out into separate invocations; file-list and stdin adapters receive the full input. Merge and collector nodes preserve typed streams.
- Files and folders require explicit registration under **Local workspace → Inputs**. Imported path strings grant no access. Files are checked against their registered hash and copied into a private job directory. Folders are copied when used; folder registration is not a frozen snapshot of a live project. Symlink-containing trees and oversized inputs are rejected.
- Outputs retain invocation IDs, argv, exit code, bounded stdout/stderr and node/run IDs. Generated files are saved as base64 evidence artifacts. Same-run file references can feed later file/folder inputs; cross-run file IDs are rejected.
- Native HTTP/TCP admissions use `max_requests`. CLI processes use `max_cli_invocations`. **The native request cap does not measure or constrain requests inside a binary.** A tool can resolve destinations, follow links, contact providers or update data internally. CLI input checks are not an OS network sandbox.
- Passive discovery records do not authorize active requests. Active downstream adapters screen their input against the selected run scope. Native HTTP transport retains its pinned-address and redirect controls; external binaries do not use that transport.
- POSIX pause/resume signals the process group. Cancel and timeout terminate that group and preserve partial logs. Windows uses admission gating for pause and system `taskkill /T` for cancellation; this session did not validate Windows behavior. Daemons that deliberately escape their process group require OS-level containment for stronger lifecycle guarantees.
- The environment excludes model keys and ambient user configuration. Only explicitly selected, catalog-declared provider variables are forwarded, and their literal values are redacted from invocation records. Parameter flags that change code execution, callbacks, credential handling, output paths or redirect policy require dedicated bindings and are disabled.
- Nuclei and Jaeles require a registered, reviewed templates/signatures folder. Template locations cannot be substituted through free-form flags. DNS adapters that require resolver files use registered resolver inputs. GF runs with seven bundled, independently authored patterns (`xss`, `sqli`, `ssrf`, `lfi`, `ssti`, `rce`, `redirect`), never arbitrary pattern engines from a user configuration.
## Operator path
1. Open Templates and select the mini-tricky source. Load a workflow or add a tool. All socket types are visible in the inspector and available as named connection handles.
2. Register needed files/folders, bind sources and set tool parameters. Source nodes use selected run targets unless an explicit in-scope subset is entered.
3. In Run setup, enable execution and catalog CLI execution, choose separate native/CLI budgets and a run deadline, then check workflow readiness. Resolve every reported issue before launching.
4. Inspect run/node states and CLI artifacts. Successful exit and captured output remain observations; they do not automatically confirm vulnerabilities.
5. Agent desk can plan over the full catalog using bounded typed capability search. That planner is explicitly deterministic; configured CAI model planning and HTTP-evidence review remain separate options.
## Explicit context restrictions
| Tool | Required contract |
|---|---|
| `interlace` | Requires an arbitrary command string. Use typed graph fan-out instead. |
| `rush` | Requires an arbitrary command string. Use typed graph fan-out instead. |
| `notify` | Requires an explicit notification destination contract. |
| `interactsh` | Requires an explicit callback/OAST account contract. |
| `kube-bench` | Requires a Kubernetes cluster/account scope contract. |
| `kubeaudit` | Requires a Kubernetes cluster/account scope contract. |
| `popeye` | Requires a Kubernetes cluster/account scope contract. |
| `prowler` | Requires a cloud account scope contract. |
| `scoutsuite` | Requires a cloud account scope contract. |
| `cloudsploit` | Requires a cloud account scope contract. |

These are recorded restrictions, not missing-binary errors. Imported custom scripts, conditions, loops and modules are rejected until they have dedicated migration contracts. None of those node kinds is required by the 57 migrated built-in workflows.
## Rebuild and verify
`scripts/migrate-catalog.py` converts the committed YAML without network access. Install `requirements-dev.txt`, then use `--check` to detect generated-catalog drift. Runtime catalog reads use generated JSON and do not require PyYAML.
## Tool matrix
| ID | Inputs | Outputs | Adapter |
|---|---|---|---|
| `subfinder` | domain | targets | passive CLI |
| `httpx` | targets, url | targets, url | target CLI |
| `amass` | domain | targets | passive CLI |
| `assetfinder` | domain | targets | passive CLI |
| `findomain` | domain | targets | passive CLI |
| `dnsx` | targets | targets | target CLI |
| `shuffledns` | domain, wordlist | targets | target CLI |
| `chaos` | domain | targets | passive CLI |
| `gobuster` | targets, wordlist | findings | target CLI |
| `dirsearch` | targets, wordlist | findings | target CLI |
| `feroxbuster` | targets, wordlist | findings | target CLI |
| `wfuzz` | targets, wordlist | findings | target CLI |
| `nuclei` | targets, url | findings | target CLI |
| `nikto` | targets | findings | target CLI |
| `wpscan` | targets | findings | target CLI |
| `sqlmap` | targets | findings | target CLI |
| `xsstrike` | targets | findings | target CLI |
| `dalfox` | targets | findings | target CLI |
| `ffuf` | targets, wordlist | findings | target CLI |
| `katana` | targets, url | targets, url | target CLI |
| `gospider` | targets | targets | target CLI |
| `hakrawler` | targets | targets | target CLI |
| `waybackurls` | domain | targets | passive CLI |
| `nmap` | targets | findings | target CLI |
| `masscan` | targets | findings | target CLI |
| `naabu` | targets | targets | target CLI |
| `rustscan` | targets | findings | target CLI |
| `theharvester` | domain | targets | passive CLI |
| `shodan-cli` | domain | findings | passive CLI |
| `censys` | domain | findings | passive CLI |
| `spiderfoot` | domain | findings | passive CLI |
| `gau` | domain | targets, url | passive CLI |
| `waymore` | domain | targets | passive CLI |
| `anew` | targets | targets | offline CLI |
| `qsreplace` | targets, url | targets, url | offline CLI |
| `uro` | targets | targets | offline CLI |
| `unfurl` | targets | targets | offline CLI |
| `jq-filter` | targets | findings | offline CLI |
| `gf` | targets, url | targets, url | offline CLI |
| `interlace` | targets | findings | Context restricted |
| `rush` | targets | findings | Context restricted |
| `notify` | targets | targets | Context restricted |
| `meg` | targets | findings | target CLI |
| `arjun` | targets | findings | target CLI |
| `paramspider` | domain | targets | passive CLI |
| `x8` | targets | findings | target CLI |
| `paraminer` | targets | findings | target CLI |
| `kiterunner` | targets | findings | target CLI |
| `apifuzzer` | targets | findings | target CLI |
| `openapi-diff` | targets | findings | target CLI |
| `restler` | targets | findings | target CLI |
| `ssrfmap` | targets | findings | target CLI |
| `gopherus` | targets | findings | offline CLI |
| `interactsh` | Context | findings | Context restricted |
| `ssrf-sheriff` | targets | findings | target CLI |
| `sstimap` | targets | findings | target CLI |
| `tplmap` | targets | findings | target CLI |
| `xsrfprobe` | targets | findings | target CLI |
| `corscanner` | targets | findings | target CLI |
| `crlfuzz` | targets | findings | target CLI |
| `subjack` | targets | findings | target CLI |
| `subzy` | targets | findings | target CLI |
| `nuclei-takeover` | targets | findings | target CLI |
| `shcheck` | targets | findings | target CLI |
| `hakcheckurl` | targets | findings | target CLI |
| `linkfinder` | targets, url, file | targets, url | target CLI |
| `secretfinder` | targets | findings | target CLI |
| `getjs` | targets, url | targets, url, file | target CLI |
| `subjs` | targets | targets | target CLI |
| `cewl` | targets | findings | target CLI |
| `wordlister` | targets | findings | target CLI |
| `s3scanner` | targets | findings | target CLI |
| `cloudenum` | domain | findings | passive CLI |
| `trufflehog` | targets, folder | findings | target CLI |
| `gitleaks` | targets, folder | findings | offline CLI |
| `whatweb` | targets | findings | target CLI |
| `wafw00f` | targets | findings | target CLI |
| `testssl` | targets | findings | target CLI |
| `sslscan` | targets | findings | target CLI |
| `ghauri` | targets | findings | target CLI |
| `commix` | targets | findings | target CLI |
| `jaeles` | targets | findings | target CLI |
| `cmseek` | targets | findings | target CLI |
| `joomscan` | targets | findings | target CLI |
| `droopescan` | targets | findings | target CLI |
| `nomore403` | targets | findings | target CLI |
| `oralyzer` | targets | findings | target CLI |
| `dirb` | targets, wordlist | findings | target CLI |
| `kube-hunter` | targets | findings | target CLI |
| `kube-bench` | Context | findings | Context restricted |
| `kubeaudit` | Context | findings | Context restricted |
| `trivy` | targets, folder | findings | target CLI |
| `kubeletctl` | targets | findings | target CLI |
| `popeye` | Context | findings | Context restricted |
| `prowler` | Context | findings | Context restricted |
| `scoutsuite` | Context | findings | Context restricted |
| `cloudsploit` | Context | findings | Context restricted |
| `gcpbucketbrute` | targets | findings | target CLI |
| `puredns` | domain, wordlist | targets | target CLI |
| `alterx` | targets | targets | offline CLI |
| `dnsgen` | targets | targets | offline CLI |
| `gotator` | targets, wordlist | targets | offline CLI |
| `tlsx` | targets | targets | target CLI |
| `asnmap` | domain | targets | passive CLI |
| `cero` | targets | targets | target CLI |
| `mapcidr` | targets | targets | offline CLI |
| `cdncheck` | targets | findings | target CLI |
| `smap` | targets | findings | passive CLI |
| `gowitness` | targets, url | folder, findings | target CLI |
| `aquatone` | targets, url | folder | target CLI |
| `jsluice` | targets, url, file | findings | offline CLI |
| `mantra` | targets, url, file | findings | target CLI |
| `xnlinkfinder` | targets, url, file | url | target CLI |
| `graphw00f` | targets, url | findings | target CLI |
| `graphql-cop` | url, targets | findings | target CLI |
| `clairvoyance` | url, targets | findings | target CLI |
| `gxss` | url, targets | findings | target CLI |
| `kxss` | url, targets | findings | target CLI |
| `smuggler` | targets, url | findings | target CLI |
| `retire` | targets, url, file | findings | offline CLI |
| `semgrep` | folder, file | findings | offline CLI |
| `wappalyzer` | url, targets | findings | target CLI |
| `httprobe` | targets | targets, url | target CLI |
| `urlfinder` | domain | targets, url | passive CLI |
| `hakip2host` | targets | targets | target CLI |
| `cariddi` | targets, url | url, findings | target CLI |
| `dsieve` | targets | targets | offline CLI |
| `dnsvalidator` | targets | targets | target CLI |
| `github-subdomains` | domain | targets | passive CLI |
| `gitdorker` | domain | findings | passive CLI |
| `ppfuzz` | url, targets | findings | target CLI |
| `shortscan` | targets, url | findings | target CLI |
| `bbot` | domain | targets, findings | passive CLI |
| `crtsh` | domain | targets | passive CLI |
| `massdns` | targets | targets | target CLI |
| `csprecon` | targets, url | targets | target CLI |
| `github-endpoints` | domain | url | passive CLI |
| `gitlab-subdomains` | domain | targets | passive CLI |
| `nrich` | targets | findings | passive CLI |
| `dnsreaper` | targets | findings | target CLI |
| `sn1per` | targets | findings | target CLI |
| `jwt_tool` | targets, url | findings | target CLI |
| `wapiti` | targets, url | findings | target CLI |
| `zaproxy` | targets, url | findings | target CLI |
| `dirhunt` | targets, url | findings | target CLI |
| `byp4xx` | targets, url | findings | target CLI |
| `crawlergo` | targets, url | url | target CLI |
| `webanalyze` | targets, url | findings | target CLI |
| `uncover` | query | targets | passive CLI |
| `syft` | folder | sbom | offline CLI |
| `grype` | sbom | findings | offline CLI |
