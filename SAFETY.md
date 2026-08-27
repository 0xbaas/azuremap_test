# AzureMap Safety Rules

AzureMap must remain safe and **read-only by design**. This file is the safety
contract; the test suite enforces it with source-level guards.

## Read-only by design

- AzureMap performs only read/list/get operations against Azure Resource
  Manager, Azure Resource Graph, and (when in scope) Microsoft Graph.
- It never executes remediation and never performs write, create, update, or
  delete actions against your environment.
- It never authenticates for you: no `Connect-AzAccount` inside runtime.
  The only context change allowed is `Set-AzContext` for local subscription
  switching.
- Every Graph call is forced to `GET`.

## Never retrieved — under any run mode

- no `listKeys` / `listSecrets` / `listCredentials` execution
- no `Get-AzStorageAccountKey`
- no secret values (Key Vault or otherwise)
- no SAS tokens
- no connection strings
- no tokens of any kind (tokens are never printed, logged, or exported)
- no blob/file content downloads
- no app settings dumps, Function keys, APIM secrets, or Automation
  credential secrets
- no exploitation or attack simulation

Capability detection is allowed and encouraged: AzureMap may reason about
whether a role **could** call a sensitive action (from role-definition
Actions) — but it never invokes that action.

## Data-plane checks (opt-in)

- Data-plane checks are **disabled by default**; a default run is
  control-plane only.
- `-IncludeDataPlane` enables exactly two checks: STORAGE-004 (anonymous blob
  container access) and KEYVAULT-003 (secret expiry).
- Even when enabled, these checks read **safe metadata only**: container names
  and public-access levels; secret name/enabled/created/expires.
- Permission failures degrade to `Partially checked` / `Could not check` —
  never to a false "Clean".

## Capability modeling (B2)

- The capability model is built from already-collected metadata (findings,
  cached inventory/RBAC, role definitions, footprint) with **no additional
  API calls**.
- It is read-only **inference** about what a principal could do — not proof
  of exploitability, and never an attempt to prove it.

## Enforcement

`Tests/Unit/Phase22.DataPlane.Tests.ps1` and
`Tests/Unit/Phase24.CapabilityModel.Tests.ps1` grep the runtime source for
forbidden call patterns (key/secret/content retrieval, invocation cmdlets in
the capability model) and fail the build if any appear. Static permission
strings used for read-only modeling are explicitly allowed; invocation is not.
