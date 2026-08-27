# EntraMap

EntraMap is the **read-only** Entra ID (Microsoft Graph) security assessment tool of the AzureMap/EntraMap family.
It scans an Entra ID tenant for misconfigurations, excessive permissions, and credential hygiene gaps, and exports findings to CSV, JSON, and HTML. For Azure subscription (ARM) audits, use [AzureMap](AzureMap.md).

EntraMap never changes your environment: every Microsoft Graph call is a `GET`, and no write, create, update, or delete operation is ever performed. See [SAFETY.md](../SAFETY.md) for the safety contract and [SAFE-RUN.md](../SAFE-RUN.md) for the safe-run guide.

## Requirements

- PowerShell 7.0+ or Windows PowerShell 5.1.
- Required Az module: `Az.Accounts` only. It is the **token vehicle** — Graph tokens are acquired via `Get-AzAccessToken` — but EntraMap performs **no subscription discovery and no ARM resource scanning**.
- An existing Azure sign-in with a Microsoft Graph auth scope. EntraMap never calls `Connect-AzAccount` for you:

```powershell
# Required: Graph token acquisition rides on the Az context
Connect-AzAccount -AuthScope "https://graph.microsoft.com"
```

If no Graph token can be acquired, preflight stops the run with the guidance above — before any check runs.

## Running EntraMap

From the repository root:

```powershell
# Full tenant audit (all Entra checks).
.\entramap.ps1 -VerboseOutput

# Include PIM eligible/active assignment checks (beta endpoints).
.\entramap.ps1 -VerboseOutput -UseGraphBeta

# Limit scope to specific service areas.
.\entramap.ps1 -VerboseOutput -Services EntraRoles,EntraPIM

# Redact sensitive identifiers in exports/console:
.\entramap.ps1 -VerboseOutput -RedactSensitive
```

Useful switches:

- `-UseGraphBeta` — use the Microsoft Graph beta endpoint; required for the PIM schedule checks (ENTRA-02). Off by default.
- `-Services` — scope checks: `EntraRoles`, `EntraApps`, `EntraGroups`, `EntraOwnership`, `EntraOAuth`, `EntraOverview`, `EntraExternalCollab`, `EntraPIM`, `EntraConditionalAccess`, `EntraAuthMethods`, `EntraBreakGlass`, `EntraWorkloadIdentity`, `Identity`, `All`.
- `-RedactSensitive` — mask emails/GUIDs in exports and console output.
- `-VerboseOutput` / `-Quiet` / `-NoColor` — console behavior.
- `-ShowFindings` / `-ShowRemediation` / `-DetailedSummary` — opt-in detail that the clean CLI intentionally hides.
- `-SeverityLevel` — scope findings.
- `-ConfigPath`, `-ExclusionPath` — JSON config overrides and exclusion/baseline rules.
- `-SkipModuleCheck` — skip module dependency validation.

## What tenant data is collected

Collection runs once per audit, tenant-scoped, and stores everything in memory (never written to disk except via the findings exports). Two collectors are used:

Microsoft Graph (`Invoke-EntraCollection`, all calls forced to `GET`):

- role definitions and role assignments, with principal resolution (display name, type, UPN, account state)
- security groups, and members of role-assignable groups
- service principals (application type) and their app role assignments
- applications, including password/key credential **metadata** (never secret values), and application owners
- service principal owners
- OAuth2 permission grants (consent)
- cross-tenant access policy
- PIM eligible and active role assignment schedules (beta endpoints, only with `-UseGraphBeta`)

Az.Resources, best effort (`Get-TenantWideData`, used by the relocated identity checks):

- tenant applications and service principals via `Get-AzADApplication` / `Get-AzADServicePrincipal`. These cmdlets may not return all objects in large tenants (counts ≥ 1000 are flagged as potentially paginated); findings from this data are best-effort.

Reference data used for classification (read from the repo, never modified): `ReferenceData/privileged-roles.json` and `ReferenceData/permission-escalation-map.json`.

## Checks

Fifteen checks run, all tenant-wide (no per-subscription phase):

| CheckId | Check | Graph permissions (app roles) |
|---|---|---|
| ENTRA-01 | Privileged Role Assignments | `RoleManagement.Read.Directory` |
| ENTRA-02 | PIM Eligible Assignments (beta-gated) | `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory` |
| ENTRA-03 | Dangerous Service Principal Permissions | `Application.Read.All` |
| ENTRA-04 | Ownership Risks | `Application.Read.All` |
| ENTRA-05 | Role-Assignable Groups | `Group.Read.All`, `RoleManagement.Read.Directory` |
| ENTRA-06 | OAuth Consent Risks | `DelegatedPermissionGrant.Read.All` |
| ENTRA-07 | App Credential Hygiene | `Application.Read.All` |
| ENTRA-08 | External Collaboration Risks | `Policy.Read.All` |
| ENTRA-09 | Conditional Access | `Policy.Read.All` |
| ENTRA-10 | Authentication Methods | `Policy.Read.All` |
| ENTRA-11 | Break-Glass Hygiene | `RoleManagement.Read.Directory`, `Directory.Read.All` |
| ENTRA-12 | Workload Identity Federated Credentials | `Application.Read.All` |
| IDENTITY-001 | Long-Lived Credentials (relocated from AzureMap) | tenant data via Az.Resources |
| IDENTITY-002 | Dormant Service Principals (relocated from AzureMap) | tenant data via Az.Resources |
| IDENTITY-004 | Expired Credentials (relocated from AzureMap) | tenant data via Az.Resources |

The relocated IDENTITY checks keep their original CheckIds and logic; only their home changed (they are tenant-wide checks and belong with the Graph product).

### IDENTITY-002 without an Azure subscription scope

IDENTITY-002 correlates tenant-wide service principals that have no credentials against ARM RBAC role assignments. EntraMap runs without any subscription scope, so the tenant side is evaluated but the RBAC correlation is reported as **NotEvaluated** ("no Azure subscription scope") — never as a clean pass. The full correlation requires an Azure subscription scope, which EntraMap intentionally does not use.

## Exports

Each run writes (gitignored; treat as sensitive — they contain tenant and object identifiers):

- `AzureSecurityAudit-<timestamp>.csv` — grouped findings
- `AzureSecurityAudit-<timestamp>-Detailed.csv` — full evidence rows
- `AzureSecurityAudit-<timestamp>.json` — summary, coverage, performance, findings
- `AzureSecurityAudit-<timestamp>.html` — interactive report
- `EntraMap-<timestamp>.log` — run log

(The export file prefix is shared with AzureMap; the log file carries the product name.)

## Known limitations

- **Coverage depends on the signed-in identity's Graph permissions.** What the identity cannot read is reported as `Could not check` / `Partially checked` — never silently passed.
- **PIM checks require `-UseGraphBeta`**; without it, PIM data is not collected and an INFO finding notes the gap.
- **Tenant-wide identity data via Az.Resources is best effort** and may be incomplete in large tenants (pagination limits are flagged in the log).
- **IDENTITY-002 RBAC correlation** is NotEvaluated without an Azure subscription scope (see above).
- **No capability modeling**: the capability/attack-path model is an AzureMap feature and is skipped in EntraMap.

## More documentation

- [AzureMap](AzureMap.md) — the Azure (ARM) product
- [SAFE-RUN.md](../SAFE-RUN.md) — safe-run guide and release smoke checklist
- [SAFETY.md](../SAFETY.md) — safety rules (what the tools may and may not do)
- [ARCHITECTURE.md](../ARCHITECTURE.md) — module layout and the product split
- [CHANGELOG.md](../CHANGELOG.md) — release history
