# AzureMap

AzureMap is a PowerShell-based Azure subscription and Entra ID security assessment tool.
It collects subscription and tenant data, evaluates configurable security checks, and exports findings in CSV, JSON, and HTML formats.

## What it covers

- Azure subscription security checks across Storage, SQL, Key Vault, Network, Compute, Messaging, Monitoring, and more
- Entra ID checks for privileged assignments, applications, OAuth consent, group membership, PIM, and tenant-wide risk
- Centralized check registration and execution with per-subscription and tenant-wide phases
- Optional module-driven checks with safe skip behavior when modules are not installed
- Microsoft Graph REST integration for Entra data, plus Azure Resource Graph query support

## Requirements

- PowerShell 7.0+ or Windows PowerShell 5.1 with compatible Az modules
- Required Az PowerShell modules:
  - `Az.Accounts`
  - `Az.Resources`
  - `Az.Storage`
  - `Az.Sql`
  - `Az.Compute`
  - `Az.Network`
  - `Az.KeyVault`
  - `Az.Monitor`

Optional modules for additional checks:

- `Az.Aks`
- `Az.ResourceGraph`
- `Az.CosmosDB`
- `Az.ContainerRegistry`
- `Az.EventHub`
- `Az.ServiceBus`
- `Az.ApiManagement`
- `Az.Synapse`
- `Az.Automation`
- `Az.Websites`
- `Az.LogicApp`

### Notes

- Missing optional modules do not fail the audit; they only skip checks that depend on them.
- Required Az modules are validated at startup.

## Running AzureMap

1. Open a PowerShell session.
2. Change to the repository root:

```powershell
cd "c:\Users\ns\Tools\Azure\AzureGhostMap_latest - Copy\AzureMap"
```

3. Run the audit:

```powershell
.
```

Replace `.` with the actual script file name, for example:

```powershell
.\AzureMap.ps1
```

### Example

```powershell
.\AzureMap.ps1 -SeverityLevel All -Services All
```

## Configuration

- Use `-ConfigPath` to pass a JSON configuration file.
- Use `-ExclusionPath` to pass an exclusion file.
- Use `-SkipModuleCheck` to bypass module validation when dependencies are satisfied elsewhere.
- Use `-SkipEntra` to skip Entra checks or `-EntraOnly` to run only Entra checks.
- Use `-UseGraphBeta` to request the Graph beta endpoint for checks that require it.

## Tests

Run Pester tests from the repository root:

```powershell
Invoke-Pester -Path .\Tests -Verbose
```

## Operational notes

- The tool is designed to be read-only during audit execution.
- Entra checks require Microsoft Graph access via the Azure login token.
- Audit results are exported via the built-in CSV, JSON, and HTML export modules.
