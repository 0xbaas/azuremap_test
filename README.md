# AzureMap

A **read-only** PowerShell security assessment tool for Azure, built on a shared core that also hosts a parked Entra ID product.
AzureMap never changes your environment. See [SAFETY.md](SAFETY.md) for the safety contract and [SAFE-RUN.md](SAFE-RUN.md) for the safe-run guide.

## Which tool for which job

- **AzureMap** (`azuremap.ps1`) — the active product. Audits **Azure subscriptions** on the ARM control plane: Storage, Key Vault, Network, Compute, SQL, Messaging, Data Platform, Monitoring, Identity/RBAC, and public exposure, plus read-only capability/attack-path insights. It never requests a Microsoft Graph token.
- **EntraMap** — **parked for a future phase** under [`Future/EntraMap/`](Future/EntraMap/), not part of the active workflow. It audits an **Entra ID tenant** via Microsoft Graph (privileged roles, PIM, applications, OAuth consent, Conditional Access, and more). See [Future/EntraMap/Docs/EntraMap.md](Future/EntraMap/Docs/EntraMap.md).

## Quick start

AzureMap needs PowerShell 7.0+ or Windows PowerShell 5.1, and uses your existing Azure sign-in — it never calls `Connect-AzAccount` for you.

```powershell
# AzureMap: Azure subscriptions (ARM only)
Connect-AzAccount
.\azuremap.ps1 -VerboseOutput
```

The HTML report uses the Pentester dashboard layout by default; pass `-ReportLayout Classic` for the legacy layout.

## Documentation

- [Products/AzureMap/Docs/AzureMap.md](Products/AzureMap/Docs/AzureMap.md) — AzureMap: modes/flags, data-plane contract, redaction, capability insights, runtime, limitations
- [Future/EntraMap/Docs/EntraMap.md](Future/EntraMap/Docs/EntraMap.md) — EntraMap (parked): Graph auth, collected tenant data, checks and permissions, limitations
- [SAFE-RUN.md](SAFE-RUN.md) — safe-run guide and release smoke checklists
- [SAFETY.md](SAFETY.md) — safety rules (what the tools may and may not do)
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, product split, status×coverage contract, caching, capability model
- [CHANGELOG.md](CHANGELOG.md) — release history

## Tests

```powershell
# Full suite (no cloud access needed; unit + integration in one run)
Invoke-Pester -Path .\Tests -Output Normal

# Per area
Invoke-Pester -Path .\Tests\AzureMap -Output Normal    # AzureMap product tests
Invoke-Pester -Path .\Tests\Shared -Output Normal      # shared framework + product-split guards
Invoke-Pester -Path .\Tests\Integration -Output Normal # offline equivalence checks
```

EntraMap's own tests are parked with the product under `Future/EntraMap/Tests` and do not run as part of `.\Tests`.

The suite includes safety guards that grep the runtime source to prove no key/secret/content retrieval paths exist, and split guards that prove the AzureMap session carries no Microsoft Graph surface.
