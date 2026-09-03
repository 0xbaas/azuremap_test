# EntraMap (parked)

EntraMap is the Entra ID security assessment product that was split out of the
AzureMap repo. It is at v1.0 RC1 level and is **parked as of the AzureMap
standalone UX pass** — it is not part of the active AzureMap workflow, and no
Entra checks should be added to AzureMap. EntraMap work will continue later in
a separate Kimi chat/session; this folder is self-describing so it can be
moved out of this repo (one directory up, next to it) and picked up there.

## Layout

- `entramap.ps1` — product entrypoint (composes Shared modules + this tree)
- `run-entramap.ps1` — thin wrapper that forwards all parameters to `entramap.ps1`
- `Core/` — Graph token handling (`Graph.ps1`), tenant-wide collection
  (`TenantWide.ps1`, `Collection.ps1`), Entra preflight (`Preflight.Entra.ps1`),
  footprint discovery (`Footprint.Entra.ps1`)
- `Checks/` — ENTRA-01..12 check modules plus the relocated tenant-identity
  checks (`TenantIdentity.ps1`: IDENTITY-001/002/004) and `Collect.ps1`
  (Graph data collection)
- `Capability/` — Entra capability model
- `Docs/EntraMap.md` — full product documentation (checks, permissions, scope)
- `Tests/` — the EntraMap Pester suite (see below)

## Running it (while still inside this repo)

Prerequisites: an Az context **and** a Microsoft Graph token, both acquired by
the operator — the tool never calls `Connect-AzAccount` itself:

```powershell
Connect-AzAccount -AuthScope "https://graph.microsoft.com"
```

Known limitation: the COA tenant's Conditional Access currently blocks Graph
token acquisition, so live runs against that tenant are not possible; the
baseline is verified with mocked tests only. Do not bypass CA to work around
this.

Then:

```powershell
.\run-entramap.ps1                 # wrapper (recommended)
# or
.\entramap.ps1 -SeverityLevel All  # entrypoint directly
```

Log and export files land in the caller's current directory.

## Tests

The EntraMap suite lives in `Tests/` next to the product code and runs
standalone from the repo root:

```powershell
Invoke-Pester -Path ./Future/EntraMap/Tests
```

(Parked tests resolve the repo root as three levels up from the test file.)

## Dependencies that are NOT self-contained yet

This folder still reaches outside itself. When EntraMap becomes standalone,
these must be copied along or extracted into a shared package:

- `Shared/Core/` — `entramap.ps1` explicitly dot-sources `State.ps1`,
  `Logging.ps1`, `Config.ps1`, `Exclusions.ps1`, then loads **every** other
  module in `Shared/Core/` (`Cache`, `Capability`, `CheckRegistry`, `Console`,
  `Preflight`, `Redaction`, `Retry`, `RunStatus`). Several of these contain
  EntraMap-aware branches (product-name labels, Entra run-mode labels, the
  Graph permission gate in `CheckRegistry.ps1`, Entra group mapping and
  `Test-EntraMapProductLoaded` in `Console.ps1`) that exist precisely so this
  parked tree keeps working; they are also load-bearing for AzureMap, which is
  why they stay in `Shared/` rather than moving here.
- `Shared/Export/` — all export modules (`Html.ps1`, `HtmlPentester.ps1`,
  `Json.ps1`, `Csv.ps1`, `Summary.ps1`), loaded wholesale by the entrypoint.
- `ReferenceData/` — `Checks/Collect.ps1` reads `privileged-roles.json` and
  `permission-escalation-map.json` from the repo root (resolves three levels
  up from this folder).
- `Tests/` dot-sources the same `Shared/Core` modules plus this tree.

Path assumptions: `entramap.ps1` computes the repo root as **two** levels up
from this folder; `Checks/Collect.ps1` and the tests compute it as **three**
levels up from their own location. If the folder moves, `Shared/`,
`ReferenceData/`, and the folder itself must keep the same relative layout
(e.g. all siblings under one workspace root) or the loaders must be adjusted.

## When it becomes standalone

1. Move this folder out of the repo (the AzureMap suite stays green without
   it — parked-layout tests skip cleanly).
2. Copy `Shared/Core`, `Shared/Export`, and `ReferenceData` next to it (or
   extract them into a versioned shared package both products import).
3. Run `Invoke-Pester -Path ./Tests` from the EntraMap root and adjust the
   repo-root depth in `entramap.ps1` / `Checks/Collect.ps1` / test files if
   the relative layout changed.
4. Continue EntraMap work in its own session; keep AzureMap free of Entra
   checks.
