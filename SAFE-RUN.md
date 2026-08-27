# AzureMap / EntraMap — Safe Run Guide

AzureMap and EntraMap are **read-only** security auditors. They inspect
configuration and report findings. They do not change your environment.

## Read-only by design

By default the tools perform **only read/list/get** operations: AzureMap
against Azure Resource Manager and Azure Resource Graph, EntraMap against
Microsoft Graph. By design they do **not**:

- perform any write, create, update, or delete operations;
- call `listKeys`, action endpoints, or otherwise read secret/key **values**;
- access data-plane contents (blob data, secret material, database rows);
- authenticate you automatically — they never call `Connect-AzAccount` for you.

If you ever need to confirm this, every Graph call is forced to `GET` and the
Azure calls are `Get-*` cmdlets.

## Authentication

Each tool uses your existing Azure PowerShell sign-in. Sign in yourself first.

**AzureMap** needs an ARM context only. It never requests a Microsoft Graph
token — the Graph code is not loaded into its session:

```powershell
# Azure Resource Manager (required for all AzureMap checks)
Connect-AzAccount
```

**EntraMap** needs a Microsoft Graph token, acquired through the Az context as
the token vehicle. It performs no subscription discovery and no ARM resource
scanning:

```powershell
Connect-AzAccount -AuthScope "https://graph.microsoft.com"
```

A preflight step validates the required context/token before any check runs.
If it is missing, the tool prints guidance and stops. Tokens are never
printed, logged, or written to any export.

## Common runs — AzureMap

```powershell
# Full Azure audit (ARM control plane only).
.\azuremap.ps1 -VerboseOutput

# Azure + data-plane checks (opt-in; safe metadata only - never values).
.\azuremap.ps1 -VerboseOutput -IncludeDataPlane

# Redact sensitive identifiers (emails/GUIDs, public IPs) in console + exports.
.\azuremap.ps1 -VerboseOutput -RedactSensitive -RedactPublicIps
```

Relevant switches:

- `-IncludeDataPlane` — opt-in data-plane checks (STORAGE-004 anonymous blob
  access, KEYVAULT-003 secret expiry). Off by default. Even when enabled,
  only safe metadata is read: container names/public-access levels and secret
  name/enabled/created/expires. Never secret values, keys, SAS tokens,
  connection strings, or blob/file content.
- `-RedactSensitive` / `-RedactPublicIps` — mask emails/GUIDs and public IP
  addresses in console output and exports.
- `-Quiet` — suppress console output (the log file and exports are still written).
- `-VerboseOutput` / `-DebugOutput` — more operational detail on the console.
  These add counts and labels only; they never print raw objects, tokens, or
  identifiers.
- `-SkipEntra` — **deprecated no-op** (Azure-only is now the only mode); an
  INFO note is logged when passed.
- `-EntraOnly` — **deprecated**: prints guidance to use `entramap.ps1` and
  stops before any Azure work.

The console summary includes a **Capability insights** section (top 5): read-only
modeling that connects findings into higher-order risk (public exposure +
privileged identity, Shared Key + key-capable RBAC, and similar). The full
capability graph is in the JSON export (`CapabilityModel`) and the HTML
"Capability Insights" section. It is inference from collected metadata, not
exploitation.

## Common runs — EntraMap

```powershell
# Full tenant audit (Microsoft Graph, GET-only).
.\entramap.ps1 -VerboseOutput

# Include PIM eligible/active assignment checks (beta endpoints).
.\entramap.ps1 -VerboseOutput -UseGraphBeta

# Redact sensitive identifiers in console + exports.
.\entramap.ps1 -VerboseOutput -RedactSensitive
```

Relevant switches:

- `-UseGraphBeta` — enable the beta endpoint for the PIM schedule checks
  (ENTRA-02). Off by default; without it PIM data is not collected and an
  INFO finding notes the gap.
- `-Services` — limit scope to specific Entra service areas.
- `-RedactSensitive` — mask emails/GUIDs in console output and exports.
- `-Quiet`, `-VerboseOutput`, `-DebugOutput` — same console discipline as
  AzureMap.

The console summary includes a **Capability insights** section (top 5): read-only
modeling that connects findings into higher-order risk (standing privileged
roles without PIM or MFA, dangerous app permissions combined with weak
ownership or federation, guest privileged access, Conditional Access gaps).
The full model is in the JSON export (`CapabilityModel`) and the HTML
"Capability Insights" section. It is inference from collected metadata, not
exploitation.

## Release smoke checklist

Run these in order before tagging a release. Steps 1–2 need no cloud access;
steps 3–7 read your environment (read-only).

- [ ] **1. Unit tests** — `Invoke-Pester -Path .\Tests -Output Normal` — all pass (whole tree: `.\Tests\AzureMap`, `.\Tests\EntraMap`, `.\Tests\Shared`; per-folder runs also work).
- [ ] **2. Integration tests** — `Invoke-Pester -Path .\Tests\Integration -Output Normal` — all pass.
- [ ] **3. AzureMap run** — `.\azuremap.ps1 -VerboseOutput`
- [ ] **4. AzureMap data-plane run (optional)** — `.\azuremap.ps1 -VerboseOutput -IncludeDataPlane`
- [ ] **5. AzureMap redaction run (optional)** — `.\azuremap.ps1 -VerboseOutput -RedactSensitive -RedactPublicIps`
- [ ] **6. EntraMap run** — `Connect-AzAccount -AuthScope "https://graph.microsoft.com"`, then `.\entramap.ps1 -VerboseOutput`
- [ ] **7. EntraMap redaction run (optional)** — `.\entramap.ps1 -VerboseOutput -RedactSensitive`

For each AzureMap run (3–5), verify:

- no interactive prompts (the run completes unattended, exit code 0);
- no raw `[Severity/Finding/Count]` finding blocks, no Az module warning
  leaks, no remediation commands, no `Source` line in the normal CLI;
- permission problems appear as clean `Could not check` / `Partially checked`
  summaries — no Forbidden/403 spam;
- the CLI summary shows Scope, Status, Findings, Capability insights (top 5),
  Performance, and Exports sections;
- `AzureSecurityAudit-<timestamp>.csv / -Detailed.csv / .json / .html` are all
  generated; JSON contains `CapabilityModel` and the correct
  `DataPlaneIncluded` flag; HTML contains the "Capability Insights" section;
- finding group counts, affected resources, and severity distribution match
  the previous accepted run (no lost findings, no false "Clean");
- with `-IncludeDataPlane`: STORAGE-004 / KEYVAULT-003 run with safe metadata
  only; with redaction switches: identifiers are masked in exports.

For the EntraMap run (6), verify:

- Graph preflight succeeds without any subscription prompt or discovery;
- the **Assessment scope** block shows mode `Entra-only`, tenant, account,
  Graph access `available`, and `Azure subscriptions: not scanned`;
- the **Discovery** block shows real tenant counts (users, groups, service
  principals, app registrations, directory roles, role assignments, CA
  policies, guest users, app credentials); denied dimensions degrade to
  `unavailable (reason)` — never raw Graph error text;
- the **assessment plan** prints relevant vs permission-limited counts (no
  limited count when the token's scopes cannot be decoded);
- per-check lines render grouped under the six human groups (Identity &
  roles, Applications, Conditional Access, Authentication, Collaboration,
  Workload identity);
- Entra checks (ENTRA-01..12) and the relocated identity checks
  (IDENTITY-001/002/004) register and execute;
- IDENTITY-002 reports its RBAC correlation as `Could not check` (no Azure
  subscription scope) — never a false "Clean"; IDENTITY-004 likewise;
- permission/collection failures become `Error` / `Could not check` /
  diagnostic items — never a false "Clean";
- the CLI summary shows a **Capability insights** section (top 5); the HTML
  report contains the "Capability Insights" section and the JSON export a
  `CapabilityModel` block;
- the exports (`AzureSecurityAudit-<timestamp>.*`) and the
  `EntraMap-<timestamp>.log` run log are generated; the run completes
  unattended (no prompts, exit code 0).

For the EntraMap redaction run (7), additionally verify: UPNs/emails
(including guest `#EXT#` UPNs, with no unmasked remnant), the tenant ID, and
app/object GUIDs are masked in the CSV, JSON, and HTML exports.

**Live-validation note:** live EntraMap validation requires a session that
can acquire a Microsoft Graph token. The current COA session blocks this via
Conditional Access, so steps 6–7 may be blocked in this environment; the
mocked test suites (including a fully mocked end-to-end run) cover the same
behaviors until a Graph-capable session is available. Do not attempt to
bypass Conditional Access or weaken authentication to run them.

## Sensitive output warning

Exported reports (`AzureSecurityAudit-*.csv/json/html`) and the run logs
(`AzureMap-*.log`, `EntraMap-*.log`) can contain **sensitive identifiers** —
tenant IDs, subscription IDs, object IDs, principal names, and resource IDs.
Treat these files as sensitive:

- Do **not** commit them to source control. They are covered by `.gitignore`
  (`*.log`, `AzureSecurityAudit-*.*`, `testResults.xml`, and the `output/`,
  `logs/`, `exports/`, `debug/`, `raw/` directories).
- Store and share them only through approved, access-controlled channels.
- Use `-RedactSensitive` / `-RedactPublicIps` when reports must leave the
  secured environment with identifiers masked.

The supported entry points are `azuremap.ps1` (Azure) and `entramap.ps1`
(Entra ID) — thin root wrappers that pass all parameters through to the real
entrypoints in `Products/AzureMap/` and `Products/EntraMap/`, which load the
modular `Shared/Core/`, per-product `Core/`/`Capability/`/`Checks/`, and
`Shared/Export/` components.
