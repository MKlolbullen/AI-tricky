# Linux scanner beta

The Linux beta archive contains the standalone AI-tricky application, the
pinned scanner installer and its version tables. CI builds and smoke-tests it
on Ubuntu 24.04 x86-64. Download both the archive and the SHA-256 file from
the `linux-scanner-beta` CI artifact.

```bash
sha256sum -c ai-tricky-linux-amd64-beta.tar.gz.sha256
tar -xzf ai-tricky-linux-amd64-beta.tar.gz
cd ai-tricky-linux-amd64-beta
./scripts/install-tools.sh --enforced-cli
./ai-tricky
```

The app opens at `http://127.0.0.1:8787`. The scanner installer requires Bash,
Python 3, curl, tar and network access to fetch the verified Go toolchain and
pinned modules. Install Bubblewrap through your Linux package manager for
the enforced profile. Its user and network namespaces must be available to
the account that runs AI-tricky. If preflight reports a namespace failure,
check your distribution's Bubblewrap/AppArmor configuration.

## Readiness

Open **Local workspace → Scanner profiles**. Review the effective binary,
installed and tested versions, capture coverage, isolated launch result and
bundled input status. This check sends no target traffic. Executables on
`PATH` take precedence. AI-tricky also looks in the default profile bin
directories under `~/.local/share/ai-tricky/`. Put a custom install directory
first on `PATH` before starting the app. This also resolves a conflicting
executable from another installation.

| Profile | Install flag | Bundled workflow inputs |
|---|---|---|
| Enforced Linux scanners | `--enforced-cli` | Small directory paths for ffuf. HTTP starter templates for Nuclei. |
| Web reconnaissance | `--web-recon` | HTTP starter templates for Nuclei. Trusted resolvers are available for DNS workflows. |
| Trickest generators | `--trickest-oss` | Small DNS labels and directory paths |

Install the bundled files under **Inputs** and bind the corresponding node
inputs. Run setup preflight checks the bindings on the actual canvas.
Installer errors identify a local diagnostics directory. Re-run with
`--tools=<id>` to retry that tool. Use the pinned compiler version shown by
the installer when passing `--skip-toolchains`.

## Enforced scanners

- **Load scoped ffuf** binds a path wordlist to an authorized HTTP(S) seed.
- **Load scoped httprobe** accepts explicit HTTP(S) URLs or concrete
  authorized hosts. Each explicit URL gets one GET. Concrete hosts expand
  to HTTPS and HTTP on the standard ports. Enter custom ports as exact URLs.
  The number of expanded URLs is capped by the run's host limit. Each URL
  also consumes one CLI invocation and at most one native GET.
- **Load scoped web recon** chains scoped httprobe, Katana and Nuclei from
  the selected hosts and URLs. Katana crawls and Nuclei runs the bound HTTP
  templates; every request they choose is checked against the entered scope
  before it is sent. See [Enforced CLI scope](CLI-SCOPE.md).
- Use **Direct** routing. Every scoped scanner runs with a private Linux
  network namespace and uses the application gateway. HTTPS uses the
  application's certificate verification. Redirects are saved without
  following them.
- **Observations** indexes scoped scanner matches as endpoints. **Open HTTP
  exchange** opens the saved request and response. Existing scoped ffuf
  captures are indexed on demand. Parser upgrades can require preparing a
  fresh evidence-guided plan.
