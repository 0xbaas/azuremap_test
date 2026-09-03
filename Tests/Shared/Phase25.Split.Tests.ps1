#==============================================================================
# AzureMap v2 - Tests/Shared/Phase25.Split.Tests.ps1
# Phase 25 - product split (AzureMap active; EntraMap parked under
# Future/EntraMap). Mocked/local only: no Azure, no Graph, no authentication.
#
# Each product composition is probed in a child powershell.exe process that
# dot-sources exactly the module set its entrypoint loads (Shared\Core +
# product {Core,Capability,Checks} + Shared\Export), so function-surface
# claims (e.g. "AzureMap has no Graph token code") hold for the whole
# session. The EntraMap probe loads the parked tree (Future\EntraMap); the
# AzureMap probe loads Products\AzureMap.
#
# Covers:
#   (a) AzureMap load: no Entra checks, no Graph surface, ARM preflight ok
#   (b) EntraMap (parked) load: ENTRA-01..12 + IDENTITY-001/002/004, no ARM
#       discovery surface, Graph preflight ok without subscription discovery
#   (c) azuremap.ps1 deprecated switches (-EntraOnly parked guidance,
#       -SkipEntra note)
#   (d) product-aware labels (banner tagline, run-mode label, HTML source)
#   (e) IDENTITY-002 with no Azure subscription scope -> NotEvaluated, never a
#       false clean PASS
#   (f) repo layout: root has only azuremap.ps1 active, Products/ holds only
#       AzureMap, EntraMap is parked under Future/EntraMap
#
# Portability: the EntraMap composition probe and the parked-layout assertions
# are skipped (not failed) when Future/EntraMap is absent, so this file stays
# green both while the parked tree lives here and after it moves out.
#==============================================================================

# Discovery-time flag: It -Skip: is bound during discovery, before BeforeAll
# runs, so the presence check must happen at file scope.
$script:EntraMapRoot    = Join-Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) 'Future\EntraMap'
$script:EntraMapPresent = Test-Path $script:EntraMapRoot

BeforeAll {
    $script:ProjectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    # --- Probe harness -------------------------------------------------------
    # The probe script mirrors the entrypoint load composition and emits one
    # JSON line with every fact the assertions below need. It runs in a child
    # process so each product is evaluated in a clean session.
    $script:ProbeDir = Join-Path ([IO.Path]::GetTempPath()) ("amprobe-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:ProbeDir -ItemType Directory -Force
    $script:ProbeScript = Join-Path $script:ProbeDir 'Invoke-ProductProbe.ps1'

    $probeSource = @'
param(
    [Parameter(Mandatory)][ValidateSet('Azure','Entra')][string]$Product,
    [Parameter(Mandatory)][string]$ProjectRoot
)
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

$probe = [ordered]@{ Product = $Product }

# ---- Load exactly what the product entrypoint loads ----
# EntraMap is parked: its product tree lives under Future\EntraMap.
$productDir = if ($Product -eq 'Entra') { "$ProjectRoot\Future\EntraMap" } else { "$ProjectRoot\Products\AzureMap" }
. "$ProjectRoot\Shared\Core\State.ps1"
. "$ProjectRoot\Shared\Core\Logging.ps1"
. "$ProjectRoot\Shared\Core\Config.ps1"
. "$ProjectRoot\Shared\Core\Exclusions.ps1"
$alreadyLoaded = @('State.ps1', 'Logging.ps1', 'Config.ps1', 'Exclusions.ps1')
foreach ($coreDir in @("$ProjectRoot\Shared\Core", "$productDir\Core", "$productDir\Capability")) {
    foreach ($coreFile in Get-ChildItem -Path "$coreDir\*.ps1" -File) {
        if ($coreFile.Name -notin $alreadyLoaded) { . $coreFile.FullName }
    }
}
foreach ($checkFile in Get-ChildItem -Path "$productDir\Checks\*.ps1" -File) { . $checkFile.FullName }
foreach ($exportFile in Get-ChildItem -Path "$ProjectRoot\Shared\Export\*.ps1" -File) { . $exportFile.FullName }

# ---- Function-surface facts ----
$probe.HasGraphToken            = [bool](Get-Command -Name 'Get-GraphToken' -ErrorAction SilentlyContinue)
$probe.HasGraphTokenScopes      = [bool](Get-Command -Name 'Test-GraphTokenScopes' -ErrorAction SilentlyContinue)
$probe.HasEnvironmentFootprint  = [bool](Get-Command -Name 'Get-EnvironmentFootprint' -ErrorAction SilentlyContinue)
$probe.HasSubscriptionInventory = [bool](Get-Command -Name 'Get-SubscriptionInventory' -ErrorAction SilentlyContinue)
$probe.HasCapabilityModel       = [bool](Get-Command -Name 'Build-CapabilityModel' -ErrorAction SilentlyContinue)
$probe.HasDormantCheck          = [bool](Get-Command -Name 'Test-DormantServicePrincipals' -ErrorAction SilentlyContinue)

# ---- State + product labels ----
if ($Product -eq 'Entra') { $script:State = Initialize-EntraAuditState } else { $script:State = Initialize-AzureAuditState }
$script:State.Config.Quiet = $true
$probe.ProductName    = $script:State.Metadata.ProductName
$probe.RunModeLabel   = Get-RunModeLabel
$probe.ProductTagline = Get-ProductTagline

# Banner renders the product tagline (record UI lines instead of printing).
$script:uiLines = New-Object System.Collections.Generic.List[string]
function Write-UiHost { param([string]$Text = '', [string]$Color = 'Gray', [switch]$NoNewline) $script:uiLines.Add($Text) }
$script:State.Config.Quiet = $false
Show-Banner -SeverityLevel 'All' -Services @('All')
$probe.BannerContainsTagline = @($script:uiLines | Where-Object { $_ -match [regex]::Escape($probe.ProductTagline) }).Count -gt 0
$script:State.Config.Quiet = $true

# ---- Registration (mirrors the entrypoint loops) ----
if ($Product -eq 'Entra') {
    foreach ($regFunc in Get-Command -Name 'Register-Entra*Checks' -ErrorAction SilentlyContinue) {
        foreach ($def in @(& $regFunc.Name)) {
            if ($def -is [hashtable]) { Register-CheckDefinition -Definition $def }
        }
    }
} else {
    foreach ($regFunc in Get-Command -Name 'Register-Azure*Checks' -ErrorAction SilentlyContinue) { & $regFunc.Name }
}
$probe.RegisteredCheckIds = @($script:State.CheckRegistry | ForEach-Object { $_.CheckId } | Sort-Object)

# ---- Preflight under stubs (no Az module required) ----
if ($Product -eq 'Azure') {
    function Get-AzContext {
        [PSCustomObject]@{
            Account      = [PSCustomObject]@{ Id = 'probe@example.com' }
            Tenant       = [PSCustomObject]@{ Id = 'probe-tenant' }
            Subscription = [PSCustomObject]@{ Id = 'probe-sub'; Name = 'probe-sub' }
        }
    }
    $pre = Test-AzureAuthPreflight
    $probe.PreflightArmAvailable = [bool]$pre.ArmAvailable
    $probe.PreflightShouldStop   = [bool]$pre.ShouldStop
} else {
    # ARM context absent; Graph token present; any subscription discovery throws.
    function Get-AzContext { $null }
    function Get-GraphToken { 'probe-token' }
    $script:azSubscriptionCalled = $false
    function Get-AzSubscription { $script:azSubscriptionCalled = $true; throw 'Get-AzSubscription must never run in EntraMap' }
    $pre = Test-EntraAuthPreflight
    $probe.PreflightShouldStop         = [bool]$pre.ShouldStop
    $probe.PreflightEntraInScope       = [bool]$pre.EntraInScope
    $probe.PreflightGraphTokenAcquired = [bool]$pre.GraphTokenAcquired
    $probe.AzSubscriptionCalled        = [bool]$script:azSubscriptionCalled

    # ---- IDENTITY-002 with no Azure subscription scope ----
    $script:State.Config.SkipEntra = $false
    $sp = [PSCustomObject]@{ Id = 'sp-probe-1'; DisplayName = 'probe-sp'; PasswordCredentials = @(); KeyCredentials = @() }
    $script:State.TenantWideData = @{
        Applications      = @([PSCustomObject]@{ Id = 'app-probe-1' })
        ServicePrincipals = @($sp)
        TenantId          = 'probe-tenant'
        FetchedAt         = Get-Date
    }
    $script:State.Results.Clear()
    Test-DormantServicePrincipals -Subscriptions @() -Exclusions @{ Resources = @(); Findings = @(); Subscriptions = @(); Tags = @() }
    $last = $script:State.Results[-1]
    $probe.DormantStatus       = "$($last.Status)"
    $probe.DormantMessage      = "$($last.Finding)"
    $probe.DormantPassFindings = @($script:State.Results | Where-Object { $_.Status -eq 'PASS' }).Count
}

$probe | ConvertTo-Json -Compress -Depth 4
'@
    Set-Content -Path $script:ProbeScript -Value $probeSource -Encoding UTF8

    function Invoke-ProductProbe {
        param([ValidateSet('Azure','Entra')][string]$Product)
        Push-Location $script:ProbeDir
        try {
            $raw = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ProbeScript -Product $Product -ProjectRoot $script:ProjectRoot 2>$null
        } finally { Pop-Location }
        $jsonLine = @($raw | Where-Object { "$_".TrimStart().StartsWith('{') } | Select-Object -Last 1)
        if (-not $jsonLine) { throw "Probe '$Product' produced no JSON. Raw output: $($raw | Out-String)" }
        return ($jsonLine | ConvertFrom-Json)
    }

    $script:AzureProbe = Invoke-ProductProbe -Product 'Azure'
    # Recompute at run time: the file-scope $script:EntraMapPresent is set
    # during discovery (for It -Skip:) and is not visible in the run phase.
    if (Test-Path (Join-Path $script:ProjectRoot 'Future\EntraMap')) {
        $script:EntraProbe = Invoke-ProductProbe -Product 'Entra'
    }
}

AfterAll {
    if ($script:ProbeDir -and (Test-Path $script:ProbeDir)) {
        Remove-Item -Path $script:ProbeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "AzureMap composition (Azure-only product)" {

    It "registers no ENTRA-* checks" {
        @($script:AzureProbe.RegisteredCheckIds | Where-Object { $_ -like 'ENTRA-*' }).Count | Should -Be 0
    }

    It "still registers Azure checks (e.g. STORAGE and per-subscription IDENTITY)" {
        $script:AzureProbe.RegisteredCheckIds | Should -Contain 'STORAGE-001'
        $script:AzureProbe.RegisteredCheckIds | Should -Contain 'IDENTITY-003'
    }

    It "has no Microsoft Graph surface (no Get-GraphToken / Test-GraphTokenScopes)" {
        $script:AzureProbe.HasGraphToken       | Should -BeFalse
        $script:AzureProbe.HasGraphTokenScopes | Should -BeFalse
    }

    It "no longer exposes the relocated tenant-identity check functions" {
        $script:AzureProbe.HasDormantCheck | Should -BeFalse
    }

    It "ARM preflight succeeds with an Az context and never probes Graph" {
        $script:AzureProbe.PreflightArmAvailable | Should -BeTrue
        $script:AzureProbe.PreflightShouldStop   | Should -BeFalse
        # No Graph probe is possible: Get-GraphToken does not exist in this session.
        $script:AzureProbe.HasGraphToken | Should -BeFalse
    }

    It "labels the run as the Azure product" {
        $script:AzureProbe.ProductName    | Should -Be 'AzureMap'
        $script:AzureProbe.RunModeLabel   | Should -Be 'Azure-only'
        $script:AzureProbe.ProductTagline | Should -Be 'Azure Security Assessment'
        $script:AzureProbe.BannerContainsTagline | Should -BeTrue
    }
}

Describe "EntraMap composition (parked product, loaded from Future/EntraMap)" {

    It "registers all twelve Entra checks (ENTRA-01..ENTRA-12)" -Skip:(-not $script:EntraMapPresent) {
        1..12 | ForEach-Object {
            $script:EntraProbe.RegisteredCheckIds | Should -Contain ("ENTRA-{0:d2}" -f $_)
        }
    }

    It "registers the relocated tenant-identity checks and no Azure resource checks" -Skip:(-not $script:EntraMapPresent) {
        'IDENTITY-001', 'IDENTITY-002', 'IDENTITY-004' | ForEach-Object {
            $script:EntraProbe.RegisteredCheckIds | Should -Contain $_
        }
        $script:EntraProbe.RegisteredCheckIds | Should -Not -Contain 'STORAGE-001'
        $script:EntraProbe.RegisteredCheckIds | Should -Not -Contain 'IDENTITY-003'
        $script:EntraProbe.HasDormantCheck    | Should -BeTrue
    }

    It "has no ARM discovery/scanning surface" -Skip:(-not $script:EntraMapPresent) {
        $script:EntraProbe.HasEnvironmentFootprint  | Should -BeFalse
        $script:EntraProbe.HasSubscriptionInventory | Should -BeFalse
        $script:EntraProbe.HasCapabilityModel       | Should -BeFalse
    }

    It "Graph preflight succeeds without an ARM context and without subscription discovery" -Skip:(-not $script:EntraMapPresent) {
        $script:EntraProbe.PreflightShouldStop         | Should -BeFalse
        $script:EntraProbe.PreflightEntraInScope       | Should -BeTrue
        $script:EntraProbe.PreflightGraphTokenAcquired | Should -BeTrue
        $script:EntraProbe.AzSubscriptionCalled        | Should -BeFalse
    }

    It "labels the run as the Entra product" -Skip:(-not $script:EntraMapPresent) {
        $script:EntraProbe.ProductName    | Should -Be 'EntraMap'
        $script:EntraProbe.RunModeLabel   | Should -Be 'Entra-only (EntraMap)'
        $script:EntraProbe.ProductTagline | Should -Be 'Entra ID Security Assessment'
        $script:EntraProbe.BannerContainsTagline | Should -BeTrue
    }

    It "IDENTITY-002 with no Azure subscription scope is NotEvaluated, never a clean PASS" -Skip:(-not $script:EntraMapPresent) {
        $script:EntraProbe.DormantStatus       | Should -Be 'NotEvaluated'
        $script:EntraProbe.DormantMessage      | Should -Match 'no Azure subscription scope'
        $script:EntraProbe.DormantPassFindings | Should -Be 0
    }
}

Describe "Entrypoints and deprecated switches" {

    It "azuremap.ps1 loads only the Azure composition (no EntraMap product code / Graph calls)" {
        # Strip full-line comments: prose may reference the other product.
        # The root azuremap.ps1 is a thin wrapper; the real entrypoint lives
        # under Products\AzureMap and composes its modules from $scriptRoot, so
        # product identity is asserted via the Azure-only function surface.
        $src = (Get-Content -Path "$script:ProjectRoot\Products\AzureMap\azuremap.ps1" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $src | Should -Match 'Shared\\Core'
        $src | Should -Match 'Shared\\Export'
        $src | Should -Match 'Initialize-AzureAuditState'
        $src | Should -Match 'Test-AzureAuthPreflight'
        $src | Should -Match 'Register-Azure'
        $src | Should -Not -Match 'Initialize-EntraAuditState'
        $src | Should -Not -Match 'Test-EntraAuthPreflight'
        $src | Should -Not -Match 'Get-GraphToken'
        $src | Should -Not -Match 'Register-Entra'
        $src | Should -Not -Match 'Invoke-AzureMapCollection'
    }

    It "entramap.ps1 (parked) loads only the Entra composition (no AzureMap product code / subscription discovery)" -Skip:(-not $script:EntraMapPresent) {
        $src = (Get-Content -Path "$script:ProjectRoot\Future\EntraMap\entramap.ps1" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $src | Should -Match 'Shared\\Core'
        $src | Should -Match 'Shared\\Export'
        $src | Should -Match 'Initialize-EntraAuditState'
        $src | Should -Match 'Test-EntraAuthPreflight'
        $src | Should -Match 'Register-Entra\*Checks'
        $src | Should -Not -Match 'Initialize-AzureAuditState'
        $src | Should -Not -Match 'Test-AzureAuthPreflight'
        $src | Should -Not -Match 'Register-Azure'
        $src | Should -Not -Match 'Get-AzSubscription'
        $src | Should -Not -Match 'Get-EnvironmentFootprint'
    }

    It "-EntraOnly prints the EntraMap-parked guidance and stops before any Azure work" {
        # Exercises the root wrapper end-to-end: it must pass -EntraOnly through
        # to the real Products\AzureMap entrypoint unchanged.
        Push-Location $script:ProbeDir
        try {
            $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script:ProjectRoot\azuremap.ps1" -EntraOnly 2>&1 | Out-String
        } finally { Pop-Location }
        $out | Should -Match '-EntraOnly is no longer supported'
        $out | Should -Match 'parked'
        $out | Should -Match 'Future/EntraMap'
        $out | Should -Not -Match 'Running assessment'
    }

    It "-SkipEntra is a documented deprecated no-op in azuremap.ps1" {
        $src = Get-Content -Path "$script:ProjectRoot\Products\AzureMap\azuremap.ps1" -Raw
        $src | Should -Match '-SkipEntra is deprecated and ignored'
    }

    It "HTML report uses the product-aware labels" {
        $src = Get-Content -Path "$script:ProjectRoot\Shared\Export\Html.ps1" -Raw
        $src | Should -Match 'Get-RunModeLabel'
        $src | Should -Match 'Get-ProductTagline'
    }
}

Describe "Repo layout (EntraMap parked)" {

    It "repo root has only the azuremap.ps1 active wrapper (no root entramap.ps1)" {
        Test-Path "$script:ProjectRoot\azuremap.ps1" | Should -BeTrue
        Test-Path "$script:ProjectRoot\entramap.ps1" | Should -BeFalse
    }

    It "Products/ contains only the active AzureMap product" {
        $dirs = @(Get-ChildItem -Path "$script:ProjectRoot\Products" -Directory)
        $dirs.Name | Should -Be @('AzureMap')
    }

    It "EntraMap is parked under Future/EntraMap with entrypoint, wrapper and tests" -Skip:(-not $script:EntraMapPresent) {
        Test-Path "$script:ProjectRoot\Future\EntraMap\entramap.ps1"       | Should -BeTrue
        Test-Path "$script:ProjectRoot\Future\EntraMap\run-entramap.ps1"   | Should -BeTrue
        Test-Path "$script:ProjectRoot\Future\EntraMap\Core\Graph.ps1"     | Should -BeTrue
        Test-Path "$script:ProjectRoot\Future\EntraMap\Tests"              | Should -BeTrue
        Test-Path "$script:ProjectRoot\Future\EntraMap\Docs\EntraMap.md"   | Should -BeTrue
    }

    It "the parked wrapper invokes the sibling entramap.ps1 and carries the parked header" -Skip:(-not $script:EntraMapPresent) {
        $src = Get-Content -Path "$script:ProjectRoot\Future\EntraMap\run-entramap.ps1" -Raw
        $src | Should -Match 'parked for a future phase'
        $src | Should -Match 'Join-Path \$PSScriptRoot ''entramap\.ps1'''
        $src | Should -Not -Match 'Products\\EntraMap'
    }

    It "the parked entrypoint still resolves the repo root (two levels up to Shared\)" -Skip:(-not $script:EntraMapPresent) {
        $src = Get-Content -Path "$script:ProjectRoot\Future\EntraMap\entramap.ps1" -Raw
        $src | Should -Match 'Shared\\Core\\State\.ps1'
        # two-levels-up repoRoot computation unchanged by the move
        $src | Should -Match 'Split-Path -Path \(Split-Path -Path \$scriptRoot -Parent\) -Parent'
    }
}
