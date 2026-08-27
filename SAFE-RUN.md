# AzureMap — Safe Run Guide

AzureMap is a **read-only** Azure and Entra ID security auditor. It inspects
configuration and reports findings. It does not change your environment.

## Read-only by design

By default AzureMap performs **only read/list/get** operations against Azure
Resource Manager and (when in scope) Microsoft Graph. By design it does **not**:

- perform any write, create, update, or delete operations;
- call `listKeys`, action endpoints, or otherwise read secret/key **values**;
- access data-plane contents (blob data, secret material, database rows);
- authenticate you automatically — it never calls `Connect-AzAccount` for you.

If you ever need to confirm this, every Graph call is forced to `GET` and the
Azure calls are `Get-*` cmdlets.

## Authentication

AzureMap uses your existing Azure PowerShell sign-in. Sign in yourself first:

```powershell
# Azure Resource Manager (required for all Azure checks)
Connect-AzAccount
```

Entra ID checks additionally require a Microsoft Graph token. If it is missing,
AzureMap prints guidance and does not proceed with Entra work. To grant it:

```powershell
Connect-AzAccount -AuthScope "https://graph.microsoft.com"
```

A preflight step validates the ARM context and (only when Entra is in scope) the
Graph token. Tokens are never printed, logged, or written to any export.

## Common run modes

```powershell
# Full audit (Azure + Entra). Requires ARM + Graph auth.
.\azuremap.ps1 -VerboseOutput

# Azure-only. No Graph token is requested; no tenant-wide identity collection.
.\azuremap.ps1 -SkipEntra -VerboseOutput

# Azure-only + data-plane checks (opt-in; safe metadata only - never values).
.\azuremap.ps1 -SkipEntra -VerboseOutput -IncludeDataPlane

# Proceed even if Graph auth is unavailable: runs Azure-only and marks Entra /
# tenant-dependent checks as NotEvaluated (never a false "clean" pass).
.\azuremap.ps1 -ContinueWithoutEntra -VerboseOutput

# Redact sensitive identifiers (emails/GUIDs, public IPs) in console + exports.
.\azuremap.ps1 -SkipEntra -VerboseOutput -RedactSensitive -RedactPublicIps
```

Relevant switches:

- `-SkipEntra` — Azure-only. Skips the Graph token, Entra collection, and all
  Graph/AAD-backed tenant identity collection.
- `-IncludeDataPlane` — opt-in data-plane checks (STORAGE-004 anonymous blob
  access, KEYVAULT-003 secret expiry). Off by default. Even when enabled,
  only safe metadata is read: container names/public-access levels and secret
  name/enabled/created/expires. Never secret values, keys, SAS tokens,
  connection strings, or blob/file content.
- `-ContinueWithoutEntra` — if Graph authentication is unavailable, continue with
  the Azure-only checks instead of stopping; Entra checks report `NotEvaluated`.
- `-RedactSensitive` / `-RedactPublicIps` — mask emails/GUIDs and public IP
  addresses in console output and exports.
- `-Quiet` — suppress console output (the log file and exports are still written).
- `-VerboseOutput` / `-DebugOutput` — more operational detail on the console.
  These add counts and labels only; they never print raw objects, tokens, or
  identifiers.

The console summary includes a **Capability insights** section (top 5): read-only
modeling that connects findings into higher-order risk (public exposure +
privileged identity, Shared Key + key-capable RBAC, and similar). The full
capability graph is in the JSON export (`CapabilityModel`) and the HTML
"Capability Insights" section. It is inference from collected metadata, not
exploitation.

## Release smoke checklist

Run these in order before tagging a release. Steps 1–2 need no cloud access;
steps 3–5 read your Azure environment (read-only).

- [ ] **1. Unit tests** — `Invoke-Pester -Path .\Tests\Unit -Output Normal` — all pass.
- [ ] **2. Integration tests** — `Invoke-Pester -Path .\Tests\Integration -Output Normal` — all pass.
- [ ] **3. Azure-only run** — `.\azuremap.ps1 -SkipEntra -VerboseOutput`
- [ ] **4. Data-plane run (optional)** — `.\azuremap.ps1 -SkipEntra -VerboseOutput -IncludeDataPlane`
- [ ] **5. Redaction run (optional)** — `.\azuremap.ps1 -SkipEntra -VerboseOutput -RedactSensitive -RedactPublicIps`

For each run (3–5), verify:

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

### Full run with Graph auth

```powershell
Connect-AzAccount -AuthScope "https://graph.microsoft.com"
.\azuremap.ps1 -VerboseOutput
```

Expected:
- Graph preflight succeeds;
- Entra checks register and execute;
- permission/collection failures become `Error` / `NotEvaluated` / diagnostic
  items — never a false `PASS`;
- a clean summary and successful export.

## Sensitive output warning

Exported reports (`AzureSecurityAudit-*.csv/json/html`) and the run log
(`*.log`) can contain **sensitive identifiers** — tenant IDs, subscription IDs,
object IDs, principal names, and resource IDs. Treat these files as sensitive:

- Do **not** commit them to source control. They are covered by `.gitignore`
  (`*.log`, `AzureSecurityAudit-*.*`, `testResults.xml`, and the `output/`,
  `logs/`, `exports/`, `debug/`, `raw/` directories).
- Store and share them only through approved, access-controlled channels.
- Use `-RedactSensitive` / `-RedactPublicIps` when reports must leave the
  secured environment with identifiers masked.

The supported entry point is `azuremap.ps1`, which loads the modular `Core/`,
`Checks/`, and `Export/` components.
