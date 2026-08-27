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
.\AzureMap.ps1 -VerboseOutput

# Azure-only. No Graph token is requested; no tenant-wide identity collection.
.\AzureMap.ps1 -SkipEntra -VerboseOutput

# Proceed even if Graph auth is unavailable: runs Azure-only and marks Entra /
# tenant-dependent checks as NotEvaluated (never a false "clean" pass).
.\AzureMap.ps1 -ContinueWithoutEntra -VerboseOutput
```

Relevant switches:

- `-SkipEntra` — Azure-only. Skips the Graph token, Entra collection, and all
  Graph/AAD-backed tenant identity collection.
- `-ContinueWithoutEntra` — if Graph authentication is unavailable, continue with
  the Azure-only checks instead of stopping; Entra checks report `NotEvaluated`.
- `-Quiet` — suppress console output (the log file and exports are still written).
- `-VerboseOutput` / `-DebugOutput` — more operational detail on the console.
  These add counts and labels only; they never print raw objects, tokens, or
  identifiers.

## Pre-live validation sequence

Run these in order. Steps 1 and 3 need no cloud access; steps 2 and 4 read your
Azure environment (read-only).

### 1. Unit tests (no cloud access)

```powershell
Invoke-Pester -Path .\Tests\Unit -Output Detailed
```

Expected: all unit tests pass.

### 2. Azure-only smoke test

```powershell
.\AzureMap.ps1 -SkipEntra -VerboseOutput
```

Expected:
- no Microsoft Graph token request;
- no Entra collection;
- no tenant-wide identity collection;
- no `MicrosoftGraphEndpointResourceId` error;
- no mass "The property 'Id' cannot be found" errors from the engine;
- no summary/export crash;
- a clean Check Execution Summary.

### 3. Full run without Graph auth

```powershell
.\AzureMap.ps1 -VerboseOutput
```

Expected:
- clean, actionable guidance:
  `Connect-AzAccount -AuthScope "https://graph.microsoft.com"`;
- no raw stack trace;
- no reconnect loop and no automatic `Connect-AzAccount`.

### 4. Full run with Graph auth

```powershell
Connect-AzAccount -AuthScope "https://graph.microsoft.com"
.\AzureMap.ps1 -VerboseOutput
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

## Legacy files (retained, not used by the modular tool)

These remain in the repository for reference and have **not** been deleted:

- `AzureMap - Copy - Copy.ps1` — the original monolithic script.
- `azure_resources.ps1` — legacy standalone script.

The supported entry point is `azuremap.ps1` (invoked as `.\AzureMap.ps1`), which
loads the modular `Core/`, `Checks/`, and `Export/` components.
