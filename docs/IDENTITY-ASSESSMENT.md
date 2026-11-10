# Active Directory and Microsoft Entra ID

**Local workspace → Identity** builds an identity workflow on the canvas. Choose an existing graph export or a fixed collection profile, then optionally add identity-specialist and PoC-plan agent review. Loading a workflow sends no requests and invokes no model. Select the entered scope, check readiness and use the normal run controls to execute it.

The identity registry is independent of the pinned 151-tool / 57-workflow mini-tricky migration. Two native adapters are added:

- `native_identity_collect`: selected targets → captured export file. A fixed local binary profile uses the shared CLI launch budget and lifecycle controls.
- `native_identity_paths`: targets or captured files → identity observations. Local parsing and bounded candidate-path search; no network or environment changes.

Identity-only workflows skip unrelated web inventory/DNS expansion. Adding HTTP/TCP adapters restores their normal scope/host checks. Execution still uses the existing “Enable workflow execution and target traffic” control; an import-only graph does not itself generate target traffic.

## Tool coverage

| Tool / profile | Integration |
| --- | --- |
| Impacket `GetADUsers` | Runnable fixed Kerberos LDAP inventory profile, with `-all` |
| Impacket `GetUserSPNs` | Runnable fixed LDAP SPN inventory; no ticket/hash request flags |
| Impacket `findDelegation` | Runnable fixed delegation inventory; no impersonation or changes |
| AzureHound | Runnable `list az-ad` profile for an explicit tenant, using an existing Graph JWT |
| BloodHound.py CE / SharpHound | Supported subset of exported BloodHound JSON/ZIP; collectors remain operator-led |
| NetExec | External reference; no unrestricted protocol/module execution adapter |
| Certipy | External AD CS reference; no certificate enrollment, relay or account-change adapter |
| linWinPwn | External orchestration reference; broad wrapper execution is not attached to agents |
| ROADtools / ROADrecon | External Entra reference; its database/token workflows are not AzureHound imports |

Install the tools you select through their official distribution or a separate environment. The main application's dependency environment is not modified by an identity run. Preflight locates `impacket-GetADUsers`, `impacket-GetUserSPNs`, `impacket-findDelegation` (or their upstream `.py` aliases) and `azurehound`, and pins executable hashes. Binary presence is not version/behavior verification; incompatible flags fail with retained logs rather than silently switching profiles.

## AD scope and authentication

Enter and select the exact AD domain, the DC hostname, and the DC's literal IP or containing CIDR. For example, a lab could select `corp.test`, `dc.corp.test` and `10.0.0.10`. A wildcard that explicitly matches the DC may supply its hostname scope, but cannot replace the exact directory-domain entry. Resolved IP addresses never become additional authorized targets.

Register an existing Kerberos credential-cache file by absolute path in **Inputs**, select its reference in the collector, and enter the account name and DC metadata. Passwords, hashes, AES keys and arbitrary flags are not accepted. The cache is copied to a private job directory with mode 0600 and passed through child-only `KRB5CCNAME`; it is not exported as evidence or passed to a model. The selected input contents and binary are checked against run/recovery bindings.

The three Impacket profiles enumerate LDAP data. SPN inventory does not request roastable tickets; delegation inventory does not perform impersonation. Their table output is retained as enumeration evidence for agent review. It is not silently interpreted as a complete relationship graph: import BloodHound or a normalized graph to compute AD paths.

## Entra scope and authentication

Enter/select an exact tenant domain and supply the explicit tenant UUID. Register a file containing an existing Microsoft Graph access-token JWT, either plain text or `{"access_token":"…"}`, then select it in the collector. The application checks the token's tenant, Graph audience and expiry locally; these claim checks are not signature verification. Microsoft authenticates the token when the collector uses it. No password, refresh-token, token-acquisition or consent flow is launched.

The token is written to a private 0600 AzureHound configuration file, never argv. Ambient Azure/identity/proxy credentials are not inherited. Literal token values are redacted from retained tool streams. Only the declared JSON export and sanitized invocation output become artifacts; private authentication files are cleaned with the job. Available Graph permissions and the upstream collector determine completeness. Partial/unsupported data must not be read as absence of risk.

AzureHound may contact Microsoft authentication/resource endpoints internally. Its requested tenant is explicit, but input checks are not an OS egress sandbox or independent verification of every upstream API call. AD LDAP/Kerberos remains direct. AzureHound receives the selected local proxy flag in proxy mode and an additional CA bundle when selected; third-party TLS behavior is version-dependent. Tool HTTP bodies remain proxy-owned until imported through HTTP history. Neither LDAP traffic nor tool-internal HTTP uses the native request counter/journal; the CLI launch cap applies.

## Graph evidence and candidate paths

Register an export in Inputs and select it in **Identity graph export**, or connect the collector's captured file output. Supported inputs:

- BloodHound JSON with `meta.type` users, groups, computers, domains, OUs, GPOs or containers; JSON-only ZIPs are accepted.
- AzureHound JSON with `meta.type: azure`, including v5 objects and nested membership/ownership records.
- `ai-tricky.identity-graph/v1` normalized JSON. See [AD example](../examples/identity/ad-example.json) and [Entra example](../examples/identity/entra-example.json).

Example files are synthetic. Register the AD example, select `corp.test`, and choose start `user` and goal `goal` to inspect a two-step candidate. The Entra example uses tenant UUID `11111111-1111-1111-1111-111111111111` and domain `corp.onmicrosoft.com`.

Every normalized graph carries a platform/domain/tenant scope. BloodHound objects must declare the selected domain; AzureHound objects must declare the selected tenant. Imported relationships link only objects present in that scope. Foreign objects and unresolved references are excluded, not promoted into active scope. Same IDs with conflicting object kinds fail rather than merging identities. Imports retain original bytes and provenance after validation; selecting an unrelated credential file does not publish it as evidence.

Search requires explicit start and goal object IDs. Empty endpoints yield an inventory, never implicit ownership or privileged-target guessing. The graph supports these candidate relationships:

| Relationship | Interpretation / prerequisite |
| --- | --- |
| MemberOf | Verify current effective group membership and nesting |
| GenericAll, WriteDacl, WriteOwner, AddMember, ForceChangePassword | Reported object rights; effective ACLs, denies and protected-object restrictions still need checking |
| AllowedToAct, AllowedToDelegate | Reported delegation; SPNs, effective principals and protocol prerequisites still need checking |
| AdminTo | Reported administrative access; current usable access is not assumed |
| Owns | Reported Entra ownership; object/role restrictions and permissions matter |
| HasRole | Active tenant-wide assignment only; verify role permissions, PIM and policy |
| DCSync | Both GetChanges and GetChangesAll on the same AD domain are required to derive this candidate; no replication is attempted |

BloodHound sessions/trust traversal, AD CS rules, inferred implicit rights, Azure ARM rights, app-consent semantics, PIM eligibility and narrow directory scopes are not traversed. In particular, eligible roles are not active assignments, generic role presence does not imply Global Administrator, and matching hybrid IDs do not establish a cross-environment compromise path. Unknown/conditional relations are counted as missing coverage.

Paths assume control of the selected start principal and every displayed prerequisite. They are `CANDIDATE_PATH`, `executed: false`; they never verify findings. Operators inspect `identity-analysis-*.json` and the original import/collector artifacts in Runs or node evidence. Results preserve the source evidence IDs.

Limits: 10 MB per input/export, 25 MB combined/ZIP-expanded data, 32 JSON files per ZIP, 16 connected/registered exports, 10,000 objects, 30,000 supported edges, 1–6 hops, 30 returned paths and bounded search expansion. Unsafe ZIP paths, symlinks, duplicate members, duplicate JSON keys and non-finite numbers are rejected. Search limits and unsupported coverage are reported explicitly; no result is not proof of no attack path.

## Agents and reviews

Two optional roles appear in Team settings: **Active Directory path specialist** and **Entra identity path specialist**. Their model routing, fallback policy, worker ceiling and usage ledger use the existing contracts. The identity starter's optional team node selects the relevant specialist plus the PoC-plan specialist. Both receive bounded identity evidence with artifact references and no target tools; private authentication inputs are excluded. Default classic/specialist teams remain unchanged.

Candidate analysis and validation plans do not become tool execution. Fixed collection nodes run through normal workflow controls and shared CLI accounting; arbitrary exploit commands, password spraying, credential extraction, relay, delegation/ACL changes and tenant/account mutations have no identity adapter here. Existing workflow recovery binds selected file contents, context and executables into a fresh review. Source evidence is preserved. Model-backed review may send its bounded evidence preview to the configured remote provider only under existing provider gates.

## Sources and compatibility

The registry links to primary sources: [Impacket](https://github.com/fortra/impacket), [AzureHound](https://github.com/SpecterOps/AzureHound), [BloodHound.py CE](https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce), [SharpHound](https://github.com/SpecterOps/SharpHound), [NetExec](https://github.com/Pennyw0rth/NetExec), [Certipy](https://github.com/ly4k/Certipy), [linWinPwn](https://github.com/lefayjey/linWinPwn) and [ROADtools](https://github.com/dirkjanm/ROADtools). AzureHound's export/config structures were inspected at commit `b02d4577731f69c729a53055a09c44673689eefd`; the parser is an independently written bounded subset. Tool code and binaries are not vendored. Tests use local executable/JSON fixtures, not a live AD domain or Entra tenant.
