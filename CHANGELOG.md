# Changelog

All notable AzureMap phases, newest first. Tags mark each accepted phase.

## Unreleased — AzureMap reliability + parity pass

- P0 finding-evidence fixes:
  - Key Vault evidence split: KEYVAULT-002 emits distinct findings per signal
    (public network access, firewall default Allow, public + no firewall,
    purge protection, private endpoints, audit logging) instead of one mixed
    bucket; every finding carries its own evidence and remediation.
  - Finding schema gains `CountType` (UniqueResources / Containers /
    RoleAssignments / RiskSignals / Observations / NotEvaluatedItems) so a
    count says what it enumerates; NotEvaluatedItems are never counted as
    affected.
  - STORAGE-003/004/005/006 correctness fixes: STORAGE-004 distinguishes
    data-plane CONFIRMED public containers from the account-level
    control-plane signal; STORAGE-005 separates critical combinations, risk
    signals, and observations; NotEvaluated is reported explicitly instead of
    as clean.
- P1 new parity checks (7): IDENTITY-007 (RBAC privileged assignment
  decomposition), COMPUTE-006 (App Service FTP state), COMPUTE-007 (VM backup
  coverage), NETWORK-009 (App Gateway listener/TLS hygiene), NETWORK-010
  (sensitive PaaS private connectivity), MONITORING-004 (extended resource
  diagnostics), STORAGE-007 (infrastructure/double encryption). AzureMap now
  registers 45 checks.
- P2 report readability (display layer only — no severity/status changes):
  - Affected counts render with a CountType-derived label ("5 resources",
    "3 assignments", "12 risk signals", …; fallback "affected") in both HTML
    layouts and the CLI top-findings summary.
  - Static per-finding caveats in both HTML layouts (e.g. "Public network
    access does not mean anonymous data access.", "RBAC assignment counts are
    not unique users.", "NotEvaluated is not Pass.") from one shared map in
    `Shared/Core/Console.ps1`.

## Unreleased — AzureMap/EntraMap product split

- The combined `azuremap.ps1` is split into two products on one shared core:
  `azuremap.ps1` (AzureMap — Azure subscriptions, ARM control plane only,
  never touches Microsoft Graph) and `entramap.ps1` (EntraMap — Entra ID
  tenant via Microsoft Graph, no subscription discovery or ARM scanning).
- Shared core lives in `Shared/Core/` (Logging, Console, State, RunStatus,
  CheckRegistry, Retry, Cache, Config, Exclusions, Redaction, capability
  primitives) with exporters in `Shared/Export/`; product code lives in
  `Products/AzureMap/` (Core: ResourceGraph, Footprint, InventoryCache, Rbac,
  Preflight.Azure; Capability: CapabilityModel.Azure; Checks) and
  `Products/EntraMap/` (Core: Graph, Collection, TenantWide, Preflight.Entra;
  Capability: CapabilityModel.Entra; Checks).
- Tenant-wide identity checks IDENTITY-001 (long-lived credentials),
  IDENTITY-002 (dormant service principals) and IDENTITY-004 (expired
  credentials) relocated to EntraMap (`Products/EntraMap/Checks/TenantIdentity.ps1`) —
  CheckIds and check logic unchanged. In EntraMap (no Azure subscription
  scope) the IDENTITY-002 RBAC correlation is reported as NotEvaluated
  instead of a false clean pass.
- CLI compatibility notes:
  - `-SkipEntra` on `azuremap.ps1` is a deprecated no-op (Azure-only is now
    the only mode); an INFO note is logged.
  - `-EntraOnly` on `azuremap.ps1` prints guidance to use `entramap.ps1` and
    stops before any Azure work.
  - `-UseGraphBeta` moved to `entramap.ps1`; `-ContinueWithoutEntra` was
    removed (Entra work no longer exists in `azuremap.ps1`).
  - Entra service names remain in the `azuremap.ps1` `-Services` ValidateSet
    for compatibility but match zero checks there.
- Banner, CLI run-mode label and HTML report header are product-aware
  ("Azure Security Assessment" / "Entra ID Security Assessment").
- New Phase25 split tests prove each product session carries only its own
  surface (no Graph code in AzureMap, no ARM discovery code in EntraMap).
- EntraMap product baseline (Phases 26–28):
  - Tenant footprint/discovery (`Build-EntraFootprint`): tenant/account plus
    per-dimension counts (users, groups, service principals, app
    registrations, directory roles, role assignments, CA policies, guest
    users, app credential metadata) with per-dimension degradation and
    per-permission-class denial classification; in-memory only.
  - EntraMap CLI blocks: Assessment scope (mode/tenant/account/Graph access,
    "Azure subscriptions: not scanned"), Discovery, and an assessment plan
    with a permission-limited count; checks grouped under six human groups
    (Identity & roles, Applications, Conditional Access, Authentication,
    Collaboration, Workload identity).
  - Graph permission gating: checks register `RequiredPerms`; the token's
    `roles`/`scp` claims are decoded once per run — provably-underprivileged
    checks are planned as limited and reported `Could not check` with a
    clear reason; opaque/undecodable tokens fail open (never faked).
  - Entra capability model (`Build-EntraCapabilityModel` on the shared B2
    primitives): 10 insight types (standing privilege combinations, PIM
    control gaps, dangerous app permissions + weak ownership/federation,
    guest privileged access, CA gaps, ...), same severity/confidence
    discipline and output shape as AzureMap — CLI top 5, HTML top 25, JSON
    `CapabilityModel`. Zero Graph calls (runtime-pinned with stubs).
  - Redaction verified for Entra identifiers: `-RedactSensitive` masks
    UPNs/emails (including B2B guest `#EXT#` UPNs — fixed a local-part
    remnant gap) and all GUID classes (tenant/app/object IDs) in CSV, JSON,
    and HTML exports; AzureMap redaction behavior unchanged.
  - IDENTITY-002/004 report their no-subscription-scope degradation with
    explicit Entra-context wording (NotEvaluated, never a false clean pass).
  - Tests: Phase26 (product baseline, 28 tests), Phase27 (Entra capability
    model + Entra-wide static safety greps, 32 tests), Phase28 (Entra export
    redaction, 7 tests); synthetic Graph fixtures under `Tests/Fixtures/Entra/`.
- Repository layout refactor (structure-only; no logic changes):
  - Product trees `Products/AzureMap/` and `Products/EntraMap/` now hold each
    product's real entrypoint plus its `Core/`, `Capability/`, `Checks/`, and
    `Docs/`; the old top-level `Core/`, `Checks/`, `Export/`, and `Docs/`
    directories are gone.
  - Shared framework moved to `Shared/Core/` and `Shared/Export/`.
  - Root `azuremap.ps1` / `entramap.ps1` remain as thin compatibility
    wrappers (identical parameter surface, pass-through to the product
    entrypoints) — operator workflow and automation are unchanged.
  - Tests reorganized: `Tests/AzureMap/` and `Tests/EntraMap/` (per-product
    tests), `Tests/Shared/` (shared framework + product-split guards);
    `Tests/Integration/` and `Tests/Fixtures/` unchanged. Suite unchanged at
    532 unit + 16 integration tests, all green.
  - `ReferenceData/` intentionally stays at the repo root: both JSON files
    are currently consumed only by EntraMap collection.

## Release candidate (unreleased)

- Documentation baseline: rewritten README (run modes, switches, data-plane
  contract, redaction, exports, expected runtime, known limitations), updated
  SAFE-RUN (release smoke checklist) and SAFETY (full read-only contract).
- No functional changes.

## `azuremap-b2-capability-model` — Capability / attack-path insights

- Read-only capability model built after assessment from already-collected
  data only (findings, cached inventory/RBAC, role definitions, footprint) —
  no additional API calls.
- 7 insight builders: storage key capability (Shared Key + key-retrieval
  RBAC, matched from role-definition Actions — never invoked), public storage
  exposure combination, public workload + privileged identity, managed
  identity blast radius, Key Vault exposure combination, network exfiltration
  paths, monitoring gaps on exposed resources.
- Severity escalates only on combined confirmed conditions; confidence levels
  (High/Medium) distinguish confirmed metadata from inference.
- Output: CLI top-5 "Capability insights", HTML "Capability Insights" section
  with capped graph table, JSON `CapabilityModel` (nodes/edges/insights with
  caps: 100 insights / 500 nodes / 1000 edges / 50 resources per insight).
- Custom role definitions fetched by IDENTITY-005 are cached in-memory for
  key-list action matching.

## `azuremap-performance-phase` — Runtime optimization

- Azure-only runtime reduced from ~55 min to ~21 min (49 subscriptions /
  ~5,700 resources) with identical findings.
- Per-run in-memory inventory cache shared by all checks (each resource kind
  enumerated at most once per subscription); proven-empty gating via the
  environment footprint; denied fetches classified once and never retried.
- Cached subscription-scope RBAC reads reused across identity checks.
- Timing instrumentation: per-check durations, phase totals, slowest
  checks/subscriptions in CLI and JSON.
- Parallelism deliberately deferred (shared per-process state).

## `azuremap-b3-data-plane-gating` — Safe data-plane checks

- Data-plane checks (STORAGE-004 anonymous blob access, KEYVAULT-003 secret
  expiry) are opt-in via `-IncludeDataPlane`; disabled by default.
- Even when enabled, only safe metadata is read: container names/public-access
  levels and secret name/enabled/created/expires. Never secret values, keys,
  SAS tokens, connection strings, or blob/file content.
- Permission failures degrade cleanly to `Could not check` / `Partially
  checked`; JSON/HTML expose data-plane mode and coverage.

## `azuremap-b1-product-ux` — Product UX baseline

- Clean, sectioned CLI: human labels, grouped per-check status lines, top
  findings, needs-attention summary; raw finding blocks, remediation text,
  and the full check list are opt-in (`-ShowFindings`, `-ShowRemediation`,
  `-DetailedSummary`).
- Status × coverage contract: `Pass` must be proven by an explicit evaluation
  record — silence is never a pass; `NotApplicable` (proven empty scope) is
  distinct from `NotEvaluated` (could not prove evaluation).
- Unattended runs: no interactive prompts, no Az module warning leaks.
- Environment footprint pre-scan drives check applicability.

## Safety guarantees (all releases)

- Read-only by design; no remediation execution; no write/update/delete.
- No `listKeys` / `listSecrets` / `Get-AzStorageAccountKey`; no secret
  values, SAS tokens, connection strings, tokens, or blob/file content —
  enforced by source-grep tests.
- Data-plane checks opt-in and safe-metadata-only.
- Capability modeling is read-only inference, not exploitation.

## Known limitations

- Coverage depends on the signed-in identity's permissions (denied reads are
  summarized as `Could not check` / `Partially checked`, never hidden).
- Data-plane metadata requires `-IncludeDataPlane` plus data-plane permissions.
- Entra checks require a Microsoft Graph token and tenant collection.
- Azure Resource Graph may be unavailable; footprint falls back to
  `Get-AzResource`.
- Some checks are legacy (explicit status, no coverage proof) and are still
  being modernized to the coverage-aware model.
- Runtime scales with subscription/resource count and permission shape.
