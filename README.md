# AzureMap / EntraMap

A family of **read-only** PowerShell security assessment tools for Azure and Entra ID, built on one shared core.
Neither tool ever changes your environment. See [SAFETY.md](SAFETY.md) for the safety contract and [SAFE-RUN.md](SAFE-RUN.md) for the safe-run guide.

## Which tool for which job

- **AzureMap** (`azuremap.ps1`) — audits **Azure subscriptions** on the ARM control plane: Storage, Key Vault, Network, Compute, SQL, Messaging, Data Platform, Monitoring, Identity/RBAC, and public exposure, plus read-only capability/attack-path insights. It never requests a Microsoft Graph token.
- **EntraMap** (`entramap.ps1`) — audits an **Entra ID tenant** via Microsoft Graph: privileged roles, PIM, applications, service principals, OAuth consent, groups, external collaboration, Conditional Access, authentication methods, break-glass and credential hygiene. It performs no subscription discovery and no ARM resource scanning.

## Quick start

Both tools need PowerShell 7.0+ or Windows PowerShell 5.1, and use your existing Azure sign-in — neither ever calls `Connect-AzAccount` for you.

```powershell
# --- AzureMap: Azure subscriptions (ARM only) ---
Connect-AzAccount
.\azuremap.ps1 -VerboseOutput

# --- EntraMap: Entra ID tenant (Microsoft Graph) ---
# EntraMap needs an Az context as the token vehicle (Get-AzAccessToken),
# but performs no subscription scanning.
Connect-AzAccount -AuthScope "https://graph.microsoft.com"
.\entramap.ps1 -VerboseOutput
```

## Documentation

- [Docs/AzureMap.md](Docs/AzureMap.md) — AzureMap: modes/flags, data-plane contract, redaction, capability insights, runtime, limitations
- [Docs/EntraMap.md](Docs/EntraMap.md) — EntraMap: Graph auth, collected tenant data, checks and permissions, limitations
- [SAFE-RUN.md](SAFE-RUN.md) — safe-run guide and release smoke checklists
- [SAFETY.md](SAFETY.md) — safety rules (what the tools may and may not do)
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, product split, status×coverage contract, caching, capability model
- [CHANGELOG.md](CHANGELOG.md) — release history

## Tests

```powershell
# Unit tests (no cloud access needed)
Invoke-Pester -Path .\Tests\Unit -Output Normal

# Integration tests (offline equivalence checks)
Invoke-Pester -Path .\Tests\Integration -Output Normal
```

The suite includes safety guards that grep the runtime source to prove no key/secret/content retrieval paths exist, and split guards that prove each product session carries only its own surface (no Graph code in AzureMap, no ARM discovery code in EntraMap).
