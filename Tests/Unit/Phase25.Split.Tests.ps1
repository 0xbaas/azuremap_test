#==============================================================================
# AzureMap v2 - Tests/Unit/Phase25.Split.Tests.ps1
# Phase 25 - product split (AzureMap / EntraMap). Mocked/local only: no Azure,
# no Graph, no authentication.
#
# Each product composition is probed in a child powershell.exe process that
# dot-sources exactly the module set its entrypoint loads (shared Core +
# Core\<Product> + Checks\<Product> + Export), so function-surface claims
# (e.g. "AzureMap has no Graph token code") hold for the whole session.
#
# Covers:
#   (a) AzureMap load: no Entra checks, no Graph surface, ARM preflight ok
#   (b) EntraMap load: ENTRA-01..12 + IDENTITY-001/002/004, no ARM discovery
#       surface, Graph preflight ok without subscription discovery
#   (c) azuremap.ps1 deprecated switches (-EntraOnly guidance, -SkipEntra note)
#   (d) product-aware labels (banner tagline, run-mode label, HTML source)
#   (e) IDENTITY-002 with no Azure subscription scope -> NotEvaluated, never a
#       false clean PASS
#==============================================================================

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
. "$ProjectRoot\Core\State.ps1"
. "$ProjectRoot\Core\Logging.ps1"
. "$ProjectRoot\Core\Config.ps1"
. "$ProjectRoot\Core\Exclusions.ps1"
$alreadyLoaded = @('State.ps1', 'Logging.ps1', 'Config.ps1', 'Exclusions.ps1')
foreach ($coreDir in @("$ProjectRoot\Core", "$ProjectRoot\Core\$Product")) {
    foreach ($coreFile in Get-ChildItem -Path "$coreDir\*.ps1" -File) {
        if ($coreFile.Name -notin $alreadyLoaded) { . $coreFile.FullName }
    }
}
foreach ($checkFile in Get-ChildItem -Path "$ProjectRoot\Checks\$Product\*.ps1" -File) { . $checkFile.FullName }
foreach ($exportFile in Get-ChildItem -Path "$ProjectRoot\Export\*.ps1" -File) { . $exportFile.FullName }

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
    $script:EntraProbe = Invoke-ProductProbe -Product 'Entra'
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

Describe "EntraMap composition (Entra-only product)" {

    It "registers all twelve Entra checks (ENTRA-01..ENTRA-12)" {
        1..12 | ForEach-Object {
            $script:EntraProbe.RegisteredCheckIds | Should -Contain ("ENTRA-{0:d2}" -f $_)
        }
    }

    It "registers the relocated tenant-identity checks and no Azure resource checks" {
        'IDENTITY-001', 'IDENTITY-002', 'IDENTITY-004' | ForEach-Object {
            $script:EntraProbe.RegisteredCheckIds | Should -Contain $_
        }
        $script:EntraProbe.RegisteredCheckIds | Should -Not -Contain 'STORAGE-001'
        $script:EntraProbe.RegisteredCheckIds | Should -Not -Contain 'IDENTITY-003'
        $script:EntraProbe.HasDormantCheck    | Should -BeTrue
    }

    It "has no ARM discovery/scanning surface" {
        $script:EntraProbe.HasEnvironmentFootprint  | Should -BeFalse
        $script:EntraProbe.HasSubscriptionInventory | Should -BeFalse
        $script:EntraProbe.HasCapabilityModel       | Should -BeFalse
    }

    It "Graph preflight succeeds without an ARM context and without subscription discovery" {
        $script:EntraProbe.PreflightShouldStop         | Should -BeFalse
        $script:EntraProbe.PreflightEntraInScope       | Should -BeTrue
        $script:EntraProbe.PreflightGraphTokenAcquired | Should -BeTrue
        $script:EntraProbe.AzSubscriptionCalled        | Should -BeFalse
    }

    It "labels the run as the Entra product" {
        $script:EntraProbe.ProductName    | Should -Be 'EntraMap'
        $script:EntraProbe.RunModeLabel   | Should -Be 'Entra-only (EntraMap)'
        $script:EntraProbe.ProductTagline | Should -Be 'Entra ID Security Assessment'
        $script:EntraProbe.BannerContainsTagline | Should -BeTrue
    }

    It "IDENTITY-002 with no Azure subscription scope is NotEvaluated, never a clean PASS" {
        $script:EntraProbe.DormantStatus       | Should -Be 'NotEvaluated'
        $script:EntraProbe.DormantMessage      | Should -Match 'no Azure subscription scope'
        $script:EntraProbe.DormantPassFindings | Should -Be 0
    }
}

Describe "Entrypoints and deprecated switches" {

    It "azuremap.ps1 loads only the Azure composition (no Core\Entra / Checks\Entra / Graph calls)" {
        # Strip full-line comments: prose may reference the other product's dirs.
        $src = (Get-Content -Path "$script:ProjectRoot\azuremap.ps1" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $src | Should -Match 'Core\\Azure'
        $src | Should -Match 'Checks\\Azure'
        $src | Should -Match 'Test-AzureAuthPreflight'
        $src | Should -Not -Match 'Core\\Entra'
        $src | Should -Not -Match 'Checks\\Entra'
        $src | Should -Not -Match 'Get-GraphToken'
        $src | Should -Not -Match 'Register-Entra'
        $src | Should -Not -Match 'Invoke-AzureMapCollection'
    }

    It "entramap.ps1 loads only the Entra composition (no Core\Azure / Checks\Azure / subscription discovery)" {
        $src = (Get-Content -Path "$script:ProjectRoot\entramap.ps1" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $src | Should -Match 'Core\\Entra'
        $src | Should -Match 'Checks\\Entra'
        $src | Should -Match 'Test-EntraAuthPreflight'
        $src | Should -Match 'Register-Entra\*Checks'
        $src | Should -Not -Match 'Core\\Azure'
        $src | Should -Not -Match 'Checks\\Azure'
        $src | Should -Not -Match 'Get-AzSubscription'
        $src | Should -Not -Match 'Get-EnvironmentFootprint'
    }

    It "-EntraOnly prints entramap.ps1 guidance and stops before any Azure work" {
        Push-Location $script:ProbeDir
        try {
            $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script:ProjectRoot\azuremap.ps1" -EntraOnly 2>&1 | Out-String
        } finally { Pop-Location }
        $out | Should -Match 'entramap\.ps1'
        $out | Should -Match '-EntraOnly is no longer supported'
        $out | Should -Not -Match 'Running assessment'
    }

    It "-SkipEntra is a documented deprecated no-op in azuremap.ps1" {
        $src = Get-Content -Path "$script:ProjectRoot\azuremap.ps1" -Raw
        $src | Should -Match '-SkipEntra is deprecated and ignored'
    }

    It "HTML report uses the product-aware labels" {
        $src = Get-Content -Path "$script:ProjectRoot\Export\Html.ps1" -Raw
        $src | Should -Match 'Get-RunModeLabel'
        $src | Should -Match 'Get-ProductTagline'
    }
}
