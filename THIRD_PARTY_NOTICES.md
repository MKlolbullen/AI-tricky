# Third-party references

## Trickest recon example

The workflow `trickest-recon-adaptation` adapts the discovery / resolution / HTTP / Nuclei pipeline described by https://github.com/trickest/recon-and-vulnerability-scanner-template (README consulted 2026-10-31). MIT License, Copyright (c) 2022 Trickest. The full notice is in `third-party/trickest-recon/LICENSE`; the original service configuration is preserved as `config.yaml.reference` for provenance only. It is not executed or required.

The adaptation omits remote repository synchronization, SSH key inputs, Trickest-hosted machines and service-specific configuration. Its stages are independently represented using this project's declarative node schema; it is not a turnkey import of Trickest's hosted workflow.

## Remaining catalog

The Trickest open-source pack runs upstream `mksub` v1.1.1 and `mkpath` v1.1.0
through independently authored local adapters. Both upstream projects publish
the MIT License, Copyright (c) 2022 Trickest. Their versions and revision links
are recorded in `toolchains/trickest-oss.tsv` and `src/trickest-catalog.json`.
The local recon workflow uses the public recon example cited above.

All other tool descriptors and workflow graphs are independently authored. https://trickest.com/library provides public discovery references; no complete commercial catalog, proprietary wrapper code or original catalog descriptions are bundled. Upstream repository links document provenance. Binaries are installed by explicit operator commands. Readiness labels refer to this project's adapters.

Trickest and ProjectDiscovery are referenced for interoperability and inspiration; this project is independent and is not affiliated with them.

## mini-tricky catalog migration

The 151 tool specifications, 57 workflow templates, capability metadata and six small payload wordlists in `third-party/mini-tricky/` are adapted from [MKlolbullen/mini-tricky](https://github.com/MKlolbullen/mini-tricky), commit `96971000b0058423da52884d9028250ab76b0633`, under the MIT License. Copyright (c) 2026 MKlolbullen. The complete license is included in `third-party/mini-tricky/LICENSE`; provenance is recorded in `SOURCE.json`. The generated catalog is `src/mini-tricky-catalog.json`.

This license attribution concerns the catalog and examples. External security binaries retain their own licenses and are not bundled. The bundled GF URL-parameter patterns are independently authored local heuristics, not proof of vulnerabilities.
