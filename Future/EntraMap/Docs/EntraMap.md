# EntraMap

> **Parked:** EntraMap is parked for a future phase — it is not part of the
> active AzureMap workflow. Everything below still applies when you run it
> from this directory.

EntraMap is the **read-only** Entra ID (Microsoft Graph) security assessment tool of the AzureMap/EntraMap family.
It scans an Entra ID tenant for misconfigurations, excessive permissions, and credential hygiene gaps, and exports findings to CSV, JSON, and HTML. For Azure subscription (ARM) audits, use [AzureMap](../../Products/AzureMap/Docs/AzureMap.md).

EntraMap never changes your environment: every Microsoft Graph call is a `GET`, and no write, create, update, or delete operation is ever performed. See [SAFETY.md](../../../SAFETY.md) for the safety contract and [SAFE-RUN.md](../../../SAFE-RUN.md) for the safe-run guide.

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
.\Future\EntraMap\run-entramap.ps1 -VerboseOutput

# Include PIM eligible/active assignment checks (beta endpoints).
.\Future\EntraMap\run-entramap.ps1 -VerboseOutput -UseGraphBeta

# Limit scope to specific service areas.
.\Future\EntraMap\run-entramap.ps1 -VerboseOutput -Services EntraRoles,EntraPIM

# Redact sensitive identifiers in exports/console:
.\Future\EntraMap\run-entramap.ps1 -VerboseOutput -RedactSensitive
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

## Run flow: scope, discovery, plan

After authentication preflight, the CLI shows three up-front blocks before any check runs:

1. **Assessment scope** — the resolved run context: mode (`Entra-only`), tenant, account, Graph access state, and the explicit `Azure subscriptions: not scanned` line. Tenant/account honor `-RedactSensitive`.
2. **Discovery** — the tenant footprint (`Build-EntraFootprint`, safe read-only Graph metadata, cached in memory and never written to disk): tenant/account plus per-dimension counts for users, groups, service principals, app registrations, directory roles, role assignments, Conditional Access policies, guest users, and app credential **metadata** count, plus an availability flag for the authentication-methods policy. Each dimension degrades independently: a denied or failed dimension renders as `unavailable (reason)` with a generic reason (e.g. `missing Graph permission (Policy.Read.All)`) — never raw Graph error text. A 401/403-class denial is classified once per permission class; remaining dimensions in that class are not queried again. Dimensions whose data was already collected are reused instead of re-fetched.
3. **Assessment plan** — how many registered checks are relevant to this tenant vs excluded by the service filter or **limited by missing Graph permissions** (see below).

## Permission gating

Each Entra check registers the Graph permissions it needs (`RequiredPerms`; see the table below). EntraMap decodes the cached Graph token's `roles`/`scp` claims once per run (`Get-GraphTokenScopeInfo`; the token value is never logged or exported):

- **Assessment plan**: checks whose required permissions are provably absent from the token are counted as `limited (missing Graph permissions)` instead of relevant.
- **Execution**: such a check does not run and is reported as `Could not check` with a clear missing-permission reason — never as a false "Clean".
- **Fail-open on opaque tokens**: when the token's scopes cannot be decoded (no token, or a non-JWT/opaque token), the permission state is treated as unknown — no limited count is shown and checks are not gated off. Nothing is ever faked.

## What tenant data is collected

Collection runs once per audit, tenant-scoped, and stores everything in memory (never written to disk except via the findings exports). Two collectors are used:

Microsoft Graph (`Invoke-AzureMapCollection`, all calls forced to `GET`):

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

### Check groups

In the CLI (and the HTML check sections) the fifteen checks render under six human groups, and execute in that order:

| Group | Checks |
|---|---|
| Identity & roles | ENTRA-01, ENTRA-02, ENTRA-05, ENTRA-11 |
| Applications | ENTRA-03, ENTRA-04, ENTRA-06, ENTRA-07, IDENTITY-001, IDENTITY-002, IDENTITY-004 |
| Conditional Access | ENTRA-09 |
| Authentication | ENTRA-10 |
| Collaboration | ENTRA-08 |
| Workload identity | ENTRA-12 |

The grouping is EntraMap-only: AzureMap output keeps its own domain sections unchanged.

### IDENTITY-002 without an Azure subscription scope

IDENTITY-002 correlates tenant-wide service principals that have no credentials against ARM RBAC role assignments. EntraMap runs without any subscription scope, so the tenant side is evaluated but the RBAC correlation is reported as **NotEvaluated** ("no Azure subscription scope - expected in EntraMap, which performs no subscription scanning") — never as a clean pass. IDENTITY-004 (expired credentials) reports the same explicit NotEvaluated when no subscription context exists. The full correlation requires an Azure subscription scope, which EntraMap intentionally does not use.

## Capability insights

After the assessment, EntraMap builds a read-only **capability / attack-path model** (`Build-EntraCapabilityModel`) from already-collected data only — finding evidence, the Entra collection, tenant-wide data, and the tenant footprint. It makes **zero Graph/Azure API calls** of its own and never retrieves secrets, tokens, keys, or content. Ten insight types are modeled:

1. Permanent privileged role assignments (standing roles; CRITICAL only for the confirmed combination: Critical role + no PIM-eligible counterpart + no enabled admin-MFA policy)
2. PIM-eligible privileged roles without strong activation controls
3. Applications with high-privilege Graph permissions
4. Dangerous app permissions combined with weak (non-admin) ownership
5. Long-lived application credentials (metadata only — expiry dates, never secret values)
6. Role-assignable groups conferring indirect privilege
7. External/guest users with privileged access
8. Break-glass and Global Administrator hygiene gaps
9. Workload identity federation into privileged applications
10. Conditional Access coverage gaps for privileged or risky sign-ins

Severity discipline: CRITICAL only when multiple confirmed conditions combine into a realistic high-impact path; single weak signals (expired credentials, excessive owners without dangerous permissions, report-only policies) never escalate on their own. Confidence distinguishes directly confirmed metadata (High) from inferred combinations (Medium) and heuristic-only findings needing manual validation (Low).

Output: the CLI summary shows the **top 5** insights; the HTML report has a "Capability Insights" section with the **top 25** (insight cards + capped graph table); the JSON export carries the full `CapabilityModel` block (up to 100 insights, plus nodes/edges with caps of 500/1000).

## Exports

Each run writes (gitignored; treat as sensitive — they contain tenant and object identifiers):

- `AzureSecurityAudit-<timestamp>.csv` — grouped findings
- `AzureSecurityAudit-<timestamp>-Detailed.csv` — full evidence rows
- `AzureSecurityAudit-<timestamp>.json` — summary, coverage, performance, findings, and the `CapabilityModel` block
- `AzureSecurityAudit-<timestamp>.html` — interactive report (includes the "Capability Insights" section)
- `EntraMap-<timestamp>.log` — run log

(The export file prefix is shared with AzureMap; the log file carries the product name.)

### Redaction (`-RedactSensitive`)

Redaction is text-based and applies to every export sink (CSV via whole-file masking, JSON via the serialized text, HTML via the escaping pipeline) as well as the console scope block:

- **emails / UPNs** → `***@***` — including B2B guest UPNs with the `#EXT#` marker (masked in full, no unmasked local-part remnant)
- **GUIDs** → `********-****-****-****-************` — covers tenant IDs, app IDs, and all object IDs (user/group/service-principal), since every Entra object identifier is a GUID
- **IPv4 addresses** → `x.x.x.x` (only with `-RedactPublicIps`)

Free-text display names (person, app, and group names) cannot be detected reliably and are **not** masked — a documented limitation. Exports stay valid after masking (JSON still parses); structure is never redacted, only values.

## Live validation status

Live EntraMap validation requires a session that can acquire a Microsoft Graph token. The current COA session blocks this via Conditional Access, so the baseline so far is verified with mocked tests only (unit/integration suites plus a fully mocked end-to-end run of `entramap.ps1`). No bypass of Conditional Access or weakening of authentication is performed or recommended.

When a Graph-capable session is available, acceptance of a live run requires:

- a Graph token acquired via the existing sign-in (`Connect-AzAccount -AuthScope "https://graph.microsoft.com"` — done by the operator, never by the tool);
- **no subscription scanning** (no subscription prompt, no ARM discovery, `Azure subscriptions: not scanned`);
- the tenant footprint generated (Discovery block shows real counts; denied dimensions degrade cleanly);
- checks run (ENTRA-01..12 + IDENTITY-001/002/004), with permission gaps reported as `Could not check` — never false "Clean";
- exports generated (CSV, detailed CSV, JSON with `CapabilityModel`, HTML with the "Capability Insights" section, `EntraMap-<timestamp>.log`);
- no interactive prompts and no raw Graph error text on the console;
- capability insights appear in the CLI (top 5), HTML, and JSON;
- with `-RedactSensitive`: UPNs (including guest `#EXT#` UPNs), tenant ID, and object/app GUIDs are masked in all exports.

## Known limitations

- **Coverage depends on the signed-in identity's Graph permissions.** What the identity cannot read is reported as `Could not check` / `Partially checked` — never silently passed.
- **PIM checks require `-UseGraphBeta`**; without it, PIM data is not collected and an INFO finding notes the gap.
- **Tenant-wide identity data via Az.Resources is best effort** and may be incomplete in large tenants (pagination limits are flagged in the log).
- **IDENTITY-002 RBAC correlation** is NotEvaluated without an Azure subscription scope (see above).
- **Capability insights are read-only inference** from collected metadata — hypotheses about what a principal or app could do, not proof of exploitability.

## More documentation

- [AzureMap](../../../Products/AzureMap/Docs/AzureMap.md) — the Azure (ARM) product
- [SAFE-RUN.md](../../../SAFE-RUN.md) — safe-run guide and release smoke checklist
- [SAFETY.md](../../../SAFETY.md) — safety rules (what the tools may and may not do)
- [ARCHITECTURE.md](../../../ARCHITECTURE.md) — module layout and the product split
- [CHANGELOG.md](../../../CHANGELOG.md) — release history
