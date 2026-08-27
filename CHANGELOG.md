# Changelog

All notable AzureMap phases, newest first. Tags mark each accepted phase.

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
