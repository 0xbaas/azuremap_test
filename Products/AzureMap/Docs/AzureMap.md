# AzureMap

AzureMap is the **read-only** Azure (ARM control-plane) security assessment tool of the AzureMap/EntraMap family.
It scans Azure subscriptions for misconfigurations, excessive permissions, and compliance gaps, models capability / attack-path risk from the results, and exports findings to CSV, JSON, and HTML. It never requests a Microsoft Graph token — for Entra ID tenant audits, use [EntraMap](../../EntraMap/Docs/EntraMap.md).

AzureMap never changes your environment. See [SAFETY.md](../../SAFETY.md) for the safety contract and [SAFE-RUN.md](../../SAFE-RUN.md) for the safe-run guide.

## What it covers

- **Azure checks** across Storage, Key Vault, Network, Compute, SQL, Messaging, Data Platform, Monitoring, Identity/RBAC, and public exposure (36 checks).
- **Capability insights (B2)**: read-only modeling that connects findings into higher-order risk — e.g. public exposure + privileged identity, Shared Key + key-capable RBAC, monitoring gaps on exposed resources. Shown as a top-5 CLI summary, an HTML "Capability Insights" section, and a full graph in JSON.
- **Environment footprint** with applicability gating (checks report "Not in scope" only when the environment is proven to lack relevant resources).
- **Data-plane checks (opt-in)**: anonymous blob container access and Key Vault secret expiry — disabled by default, enabled only with `-IncludeDataPlane`, and limited to safe metadata.

## Requirements

- PowerShell 7.0+ or Windows PowerShell 5.1 with compatible Az modules.
- Required Az modules: `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.Sql`, `Az.Compute`, `Az.Network`, `Az.KeyVault`, `Az.Monitor`.
- Optional modules enable additional checks (safe skip when missing): `Az.Aks`, `Az.ResourceGraph`, `Az.CosmosDB`, `Az.ContainerRegistry`, `Az.EventHub`, `Az.ServiceBus`, `Az.ApiManagement`, `Az.Synapse`, `Az.Automation`, `Az.Websites`, `Az.LogicApp`.
- An existing Azure sign-in. AzureMap never calls `Connect-AzAccount` for you, and never probes Microsoft Graph:

```powershell
# Required for all AzureMap checks (ARM only)
Connect-AzAccount
```

## Running AzureMap

From the repository root:

```powershell
# Full Azure audit (ARM control plane only; no Graph token requested).
.\azuremap.ps1 -VerboseOutput

# Azure + data-plane checks (safe metadata only; see below).
.\azuremap.ps1 -VerboseOutput -IncludeDataPlane

# Redact sensitive identifiers in exports/console:
.\azuremap.ps1 -VerboseOutput -RedactSensitive -RedactPublicIps
```

Useful switches:

- `-IncludeDataPlane` — enable data-plane checks (off by default; see below).
- `-RedactSensitive` — mask emails/GUIDs in exports and console output.
- `-RedactPublicIps` — mask public IP addresses in exports and console output.
- `-VerboseOutput` / `-Quiet` / `-NoColor` — console behavior. The normal CLI stays clean: no raw finding blocks, no remediation commands, no module warnings.
- `-ShowFindings` / `-ShowRemediation` / `-DetailedSummary` — opt-in detail that the clean CLI intentionally hides.
- `-SeverityLevel`, `-Services` — scope findings/checks. The `-Services` ValidateSet still accepts the legacy Entra service names for CLI compatibility; they match zero checks here (Entra checks live in `entramap.ps1`).
- `-ConfigPath`, `-ExclusionPath` — JSON config overrides and exclusion/baseline rules.
- `-SkipModuleCheck` — skip Azure module dependency validation.

Deprecated switches (kept for CLI compatibility; both refer to the split):

- `-SkipEntra` — deprecated no-op: `azuremap.ps1` is always Azure-only now. An INFO note is logged when it is passed.
- `-EntraOnly` — deprecated: prints guidance to use `entramap.ps1` and stops before any Azure work.

## What `-IncludeDataPlane` does — and does not do

Data-plane checks are **off by default**; AzureMap then reads only the ARM control plane. With `-IncludeDataPlane`, two additional checks run:

- `STORAGE-004` — lists blob container **names and public-access levels** per storage account (anonymous access detection).
- `KEYVAULT-003` — reads secret **metadata** per vault (name, enabled, created, expiry) for expiry hygiene.

Even when enabled, these checks read **safe metadata only**. AzureMap never retrieves:

- secret values, account keys, or key material of any kind
- SAS tokens or connection strings
- blob/file content
- anything via `listKeys`, `listSecrets`, or `Get-AzStorageAccountKey`

Permission problems degrade cleanly: affected checks report `Partially checked` or `Could not check` — never a false "Clean".

## Capability insights (read-only modeling)

After the checks complete, AzureMap builds a capability model from already-collected data (findings, cached inventory, cached RBAC, role definitions, environment footprint). It performs **no additional API calls** and models, among others:

- storage key capability where Shared Key is enabled and a principal's role grants the key-retrieval action (matched from role definitions — never invoked)
- public storage exposure combined with weak authentication
- internet-facing workloads attached to privileged managed identities
- managed identity blast radius at subscription/resource-group scope
- Key Vault exposure combinations (public + legacy policies + missing purge protection)
- broad outbound exfiltration paths and monitoring gaps on exposed resources

Severity escalates only when multiple confirmed conditions combine; confidence labels distinguish confirmed metadata from inference. The model is **read-only inference, not proof of exploitability**. (Capability modeling is an AzureMap feature; EntraMap skips it.)

## Exports

Each run writes (gitignored; treat as sensitive — they contain tenant/subscription/resource identifiers):

- `AzureSecurityAudit-<timestamp>.csv` — grouped findings
- `AzureSecurityAudit-<timestamp>-Detailed.csv` — full evidence rows
- `AzureSecurityAudit-<timestamp>.json` — summary, coverage, performance, capability model, findings
- `AzureSecurityAudit-<timestamp>.html` — interactive report (coverage, findings, capability insights, per-check detail)
- `AzureMap-<timestamp>.log` — run log

## Expected runtime

After the performance phase, an AzureMap run over ~49 subscriptions / ~5,700 resources takes **~21 minutes** (down from ~55). Runtime scales with subscription count, resource count, and which reads your permissions allow (denied calls are classified once and not retried). The CLI and JSON include a Performance section with per-phase totals and the slowest checks/subscriptions.

## Known limitations

- **Coverage depends on your permissions.** What the signed-in identity cannot read is reported as `Could not check` / `Partially checked` — never silently passed.
- **Data-plane metadata** requires explicit `-IncludeDataPlane` *and* data-plane permissions; without them, those checks degrade instead of evaluating.
- **Azure Resource Graph may be unavailable** (module or permission); the footprint then falls back to `Get-AzResource`, which is slower but equivalent.
- **Some checks are still being modernized** to the coverage-aware status model; legacy checks keep explicit statuses but do not prove evaluation coverage (shown in the coverage summary).
- **Performance varies** with subscription/resource count and permission shape.
- **Capability insights are read-only inference** from configuration and RBAC metadata — an indication of what a principal *could* do, not proof that a path is exploitable.

## Tests

```powershell
# Unit tests (no cloud access needed)
Invoke-Pester -Path .\Tests\Unit -Output Normal

# Integration tests (offline equivalence checks)
Invoke-Pester -Path .\Tests\Integration -Output Normal
```

The suite includes safety guards that grep the runtime source to prove no key/secret/content retrieval paths exist, and split guards that prove the AzureMap session carries no Microsoft Graph surface.

## More documentation

- [EntraMap](../../EntraMap/Docs/EntraMap.md) — the Entra ID (Microsoft Graph) product
- [SAFE-RUN.md](../../SAFE-RUN.md) — safe-run guide and release smoke checklist
- [SAFETY.md](../../SAFETY.md) — safety rules (what the tools may and may not do)
- [ARCHITECTURE.md](../../ARCHITECTURE.md) — module layout, status×coverage contract, caching, capability model
- [CHANGELOG.md](../../CHANGELOG.md) — release history
