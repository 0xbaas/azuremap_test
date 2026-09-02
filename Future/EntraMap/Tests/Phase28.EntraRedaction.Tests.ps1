#==============================================================================
# AzureMap v2 - Tests/EntraMap/Phase28.EntraRedaction.Tests.ps1
# Phase 28 - EntraMap export redaction verification (-RedactSensitive).
# Mocked/local only: no Azure, no Graph, no authentication.
#
# Verifies that the shared redaction (Core/Redaction.ps1, applied by every
# export sink: Protect-SensitiveText in JSON + HTML escaping,
# Protect-SensitiveFile for CSV) masks the Entra-specific identifier classes:
#   * user emails / UPNs (including B2B guest '#EXT#' UPNs - no remnant)
#   * tenant ID, app IDs, object IDs (user/group/SP GUIDs)
# in the CSV, JSON and HTML exports of an EntraMap run, and that exports stay
# valid/parseable. AzureMap redaction behavior is pinned separately by
# Phase19 (must stay green; this file adds Entra-product coverage only).
#==============================================================================

BeforeAll {
    # Parked under Future/EntraMap/Tests: repo root is three levels up.
    $projectRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"
    . "$projectRoot\Shared\Export\Html.ps1"
    . "$projectRoot\Shared\Export\Json.ps1"
    . "$projectRoot\Shared\Export\Csv.ps1"

    # The HTML/JSON exporters probe Get-AzContext for account/tenant display.
    function global:Get-AzContext { $null }

    # Entra identifiers that must never survive a redacted export.
    $script:TenantGuid = '11111111-2222-3333-4444-555555555555'
    $script:AppGuid    = 'cccc0003-0000-4000-8000-0000000000a1'
    $script:UserGuid   = 'aaaa0001-0000-4000-8000-000000000001'
    $script:GuestGuid  = 'aaaa0001-0000-4000-8000-000000000003'
    $script:GroupGuid  = 'bbbb0002-0000-4000-8000-000000000001'
    $script:SpGuid     = 'dddd0004-0000-4000-8000-000000000001'
    $script:AdminUpn   = 'admin1@contoso.onmicrosoft.com'
    $script:GuestUpn   = 'extuser_vendor.com#EXT#@contoso.onmicrosoft.com'

    function script:New-EntraRedactState {
        $script:State = Initialize-EntraAuditState
        $script:State.Config.Quiet  = $true
        $script:State.Config.NoColor = $true
        $script:State.Config.RedactSensitive = $true
        $script:State.LogFile = Join-Path $TestDrive 'EntraMap-redact-test.log'
    }

    # Entra findings carrying every identifier class: UPNs (member + guest),
    # tenant ID, app/object/group/SP GUIDs - in messages AND evidence.
    function script:New-EntraRedactFindings {
        @(
            [PSCustomObject]@{
                FindingId = 'r-1'; CheckId = 'ENTRA-02'; Timestamp = '2026-08-27 12:00:00'
                Finding = "Standing privileged assignments without PIM eligibility incl. $script:AdminUpn"
                Count = 2; Status = 'FAIL'; Severity = 'HIGH'; Service = 'EntraPIM'
                Evidence = @(
                    [PSCustomObject]@{ PrincipalId = $script:UserGuid; PrincipalName = $script:AdminUpn; PrincipalType = 'User'; RoleName = 'Global Administrator'; HasPIMEligible = $false },
                    [PSCustomObject]@{ PrincipalId = $script:GuestGuid; PrincipalName = $script:GuestUpn; PrincipalType = 'User'; RoleName = 'Global Administrator'; HasPIMEligible = $false }
                )
            },
            [PSCustomObject]@{
                FindingId = 'r-2'; CheckId = 'ENTRA-03'; Timestamp = '2026-08-27 12:00:00'
                Finding = 'Service principals with dangerous Graph application permissions'
                Count = 1; Status = 'FAIL'; Severity = 'CRITICAL'; Service = 'EntraApps'
                Evidence = @(
                    [PSCustomObject]@{ SPId = $script:SpGuid; DisplayName = 'sp-ci-cd'; AppId = $script:AppGuid; TenantId = $script:TenantGuid; DangerousPermissions = @('RoleManagement.ReadWrite.Directory') }
                )
            },
            [PSCustomObject]@{
                FindingId = 'r-3'; CheckId = 'ENTRA-05'; Timestamp = '2026-08-27 12:00:00'
                Finding = 'Role-assignable groups with privileged roles'
                Count = 1; Status = 'FAIL'; Severity = 'HIGH'; Service = 'EntraGroups'
                Evidence = @(
                    [PSCustomObject]@{ GroupId = $script:GroupGuid; GroupName = 'sg-privileged-access'; AssignedRoles = @('Privileged Role Administrator'); MemberCount = 3 }
                )
            }
        )
    }

    function script:Assert-EntraIdentifiersRedacted {
        param([string]$Content, [string]$Because, [bool]$RequireGuidMask = $true, [bool]$RequireEmailMask = $true)
        $Content | Should -Not -Match ([regex]::Escape($script:AdminUpn)) -Because $Because
        # Guard the full guest UPN AND any unmasked local-part remnant of it.
        $Content | Should -Not -Match ([regex]::Escape($script:GuestUpn)) -Because $Because
        $Content | Should -Not -Match 'extuser_vendor' -Because "$Because (no unmasked '#EXT#' local-part remnant)"
        foreach ($g in @($script:TenantGuid, $script:AppGuid, $script:UserGuid, $script:GuestGuid, $script:GroupGuid, $script:SpGuid)) {
            $Content | Should -Not -Match ([regex]::Escape($g)) -Because "$Because (GUID $g)"
        }
        if ($RequireGuidMask) {
            $Content | Should -Match ([regex]::Escape('********-****-****-****-************')) -Because "$Because (GUID mask present)"
        }
        if ($RequireEmailMask) {
            $Content | Should -Match ([regex]::Escape('***@***')) -Because "$Because (email mask present)"
        }
    }
}

Describe "Protect-SensitiveText - Entra identifier classes" {

    BeforeEach { New-EntraRedactState }

    It "fully masks B2B guest '#EXT#' UPNs (no unmasked remnant)" {
        $t = Protect-SensitiveText -Text "guest $script:GuestUpn holds GA"
        $t | Should -Not -Match 'extuser_vendor'
        $t | Should -Not -Match '#EXT#'
        $t | Should -Match ([regex]::Escape('***@***'))
    }

    It "masks member UPNs and all Entra GUID classes (tenant/app/user/group/SP)" {
        $t = Protect-SensitiveText -Text "$script:AdminUpn $script:TenantGuid $script:AppGuid $script:UserGuid $script:GroupGuid $script:SpGuid"
        $t | Should -Not -Match ([regex]::Escape($script:AdminUpn))
        foreach ($g in @($script:TenantGuid, $script:AppGuid, $script:UserGuid, $script:GroupGuid, $script:SpGuid)) {
            $t | Should -Not -Match ([regex]::Escape($g))
        }
    }

    It "is a no-op for Entra identifiers when redaction is disabled" {
        $script:State.Config.RedactSensitive = $false
        $t = Protect-SensitiveText -Text "$script:AdminUpn $script:TenantGuid"
        $t | Should -Match ([regex]::Escape($script:AdminUpn))
        $t | Should -Match ([regex]::Escape($script:TenantGuid))
    }
}

Describe "EntraMap export redaction (-RedactSensitive)" {

    BeforeEach { New-EntraRedactState }

    It "redacts UPNs and GUIDs in both CSV exports" {
        $findings = @(New-EntraRedactFindings)
        $base = Join-Path $TestDrive 'entra-redact'
        Export-ResultsCsv -Results $findings -BaseName $base | Out-Null
        # Summary CSV carries no evidence (so no GUIDs) - UPN mask assertions only.
        Assert-EntraIdentifiersRedacted -Content (Get-Content "$base.csv" -Raw) -Because 'summary CSV must be redacted' -RequireGuidMask $false
        Assert-EntraIdentifiersRedacted -Content (Get-Content "$base-Detailed.csv" -Raw) -Because 'detailed CSV must be redacted'
        # The detailed CSV takes its columns from the first evidence row, so the
        # SP/app/tenant GUID fields need a homogeneous single-finding export to
        # be exercised (pre-existing Export-Csv shape limitation, not redaction).
        $baseB = Join-Path $TestDrive 'entra-redact-sp'
        Export-ResultsCsv -Results @($findings[1]) -BaseName $baseB | Out-Null
        Assert-EntraIdentifiersRedacted -Content (Get-Content "$baseB-Detailed.csv" -Raw) -Because 'detailed CSV (SP evidence) must be redacted' -RequireEmailMask $false
    }

    It "redacts the JSON export and keeps it valid JSON" {
        $base = Join-Path $TestDrive 'entra-redact-json'
        Export-ResultsJson -Results @(New-EntraRedactFindings) -BaseName $base | Out-Null
        $json = Get-Content "$base.json" -Raw
        Assert-EntraIdentifiersRedacted -Content $json -Because 'JSON export must be redacted'
        { $json | ConvertFrom-Json | Out-Null } | Should -Not -Throw
    }

    It "redacts the HTML export" {
        $out = Join-Path $TestDrive 'entra-redact.html'
        Export-ResultsHtml -Results @(New-EntraRedactFindings) -OutputPath $out | Out-Null
        Assert-EntraIdentifiersRedacted -Content (Get-Content $out -Raw) -Because 'HTML export must be redacted'
    }

    It "leaves Entra identifiers in place when redaction is off (control)" {
        $script:State.Config.RedactSensitive = $false
        $findings = @(New-EntraRedactFindings)
        $base = Join-Path $TestDrive 'entra-noredact'
        Export-ResultsCsv -Results @($findings[0]) -BaseName $base | Out-Null
        $csv = Get-Content "$base-Detailed.csv" -Raw
        $csv | Should -Match ([regex]::Escape($script:AdminUpn))
        $csv | Should -Match ([regex]::Escape($script:UserGuid))
        $baseB = Join-Path $TestDrive 'entra-noredact-sp'
        Export-ResultsCsv -Results @($findings[1]) -BaseName $baseB | Out-Null
        Get-Content "$baseB-Detailed.csv" -Raw | Should -Match ([regex]::Escape($script:TenantGuid))
        $baseJ = Join-Path $TestDrive 'entra-noredact-json'
        Export-ResultsJson -Results $findings -BaseName $baseJ | Out-Null
        Get-Content "$baseJ.json" -Raw | Should -Match ([regex]::Escape($script:GuestUpn))
    }
}
