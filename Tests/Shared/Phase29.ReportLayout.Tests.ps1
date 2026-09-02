#==============================================================================
# AzureMap v2 - Tests/Shared/Phase29.ReportLayout.Tests.ps1
# Phase 29 / Report UX v2 R1 - "Pentester Dashboard" HTML layout.
# Mocked/local only. No Azure, no Graph, no authentication, no data-plane.
#
# Pins:
#   * Pentester is the DEFAULT layout (no -ReportLayout): default in the
#     shared state config and in the param defaults of the active AzureMap
#     entrypoints (root azuremap.ps1 + Products/AzureMap/azuremap.ps1).
#   * -ReportLayout Classic selects the legacy Classic renderer
#     (byte-unchanged: Classic markers present, Pentester markers absent).
#   * -ReportLayout is accepted by the active AzureMap entrypoint AND the
#     root wrapper (static parameter inspection only - no execution); the
#     ValidateSet rejects values outside Classic/Pentester. (EntraMap is
#     parked under Future/EntraMap and is not an active entrypoint.)
#   * Pentester layout: section order (Findings before Coverage), narrow
#     6-column findings index, #fd-N anchor integrity, inline evidence with
#     the 50-row cap note, compact coverage status line, capability section,
#     redaction via the shared chokepoint, BAAS markers, no external refs,
#     explicit NOTEVALUATED preserved (never recomputed).
# Classic tests (Phase14/17/19/20/21/28) are untouched and must stay green.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"
    . "$projectRoot\Shared\Export\Html.ps1"
    . "$projectRoot\Shared\Export\HtmlPentester.ps1"
    . "$projectRoot\Shared\Export\Summary.ps1"

    # The HTML exporters probe Get-AzContext for account/tenant display.
    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }

    function script:New-P29Finding {
        param(
            [string]$CheckId = 'P29-TEST',
            [string]$Severity = 'HIGH',
            [string]$Service = 'Storage',
            [string]$Finding = 'synthetic p29 finding',
            [int]$Count = 1,
            [string]$Status = 'FAIL',
            [object[]]$Evidence,
            [string]$Remediation,
            [string]$SummaryText,
            [string]$CoverageSummary,
            [switch]$Partial,
            [switch]$DataPlane
        )
        [PSCustomObject]@{
            FindingId                = [guid]::NewGuid().ToString()
            CheckId                  = $CheckId
            Timestamp                = '2026-08-28 00:00:00'
            Severity                 = $Severity
            Service                  = $Service
            Finding                  = $Finding
            Count                    = $Count
            Status                   = $Status
            Confidence               = 'High'
            FindingType              = 'Misconfiguration'
            SubscriptionName         = 'sub1'
            SubscriptionId           = 'sub1'
            PartialEvaluation        = [bool]$Partial
            CompleteEvaluation       = (-not $Partial)
            SummaryText              = $SummaryText
            CoverageSummary          = $CoverageSummary
            SeverityReason           = $null
            Remediation              = $Remediation
            DataPlaneRequired        = [bool]$DataPlane
            ManualValidationRequired = $false
            IsInventoryOnly          = $false
            Evidence                 = $Evidence
        }
    }

    function script:New-P29ExecRecord {
        param(
            [string]$CheckId,
            [string]$Status = 'Pass',
            [object]$Coverage = $null,
            [string]$Detail,
            [string]$SummaryText,
            [switch]$DataPlane
        )
        [PSCustomObject]@{
            CheckId            = $CheckId
            Name               = "$CheckId check"
            Category           = 'Azure'
            Service            = 'Storage'
            Phase              = 'PerSubscription'
            Status             = $Status
            Detail             = $Detail
            SummaryText        = $SummaryText
            Coverage           = $Coverage
            DataPlaneRequired  = [bool]$DataPlane
            StartedAt          = Get-Date
            CompletedAt        = Get-Date
        }
    }

    # Populates a realistic AzureMap run: one CRITICAL exposure finding with 60
    # evidence rows (exercises the 50-row cap), one HIGH partial storage finding,
    # one explicit NOTEVALUATED record (must be preserved verbatim).
    function script:New-P29AzureState {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-p29-test.log'

        $bigEvidence = 0..59 | ForEach-Object {
            [PSCustomObject]@{ ResourceName = "ev-$_"; ResourceGroup = 'rg-demo'; Reason = 'public endpoint' }
        }
        $findings = @(
            (New-P29Finding -CheckId 'AZURE-EXPOSURE-001' -Severity 'CRITICAL' -Service 'Exposure' `
                -Finding 'Public-facing resource exposure' -Count 60 -Evidence $bigEvidence `
                -Remediation 'Reduce public exposure.' -SummaryText 'Public items expose attack surface.'),
            (New-P29Finding -CheckId 'STORAGE-002' -Severity 'HIGH' -Service 'Storage' `
                -Finding 'Storage accounts open to all networks' -Count 2 -Partial `
                -Evidence @([PSCustomObject]@{ StorageAccount = 'st1'; ResourceGroup = 'rg-demo' }) `
                -CoverageSummary '2 of 3 subscriptions evaluated' -Remediation 'Restrict network rules.'),
            (New-P29Finding -CheckId 'NETWORK-003' -Severity 'HIGH' -Service 'Network' `
                -Finding 'Public IP evaluation' -Count 0 -Status 'NOTEVALUATED')
        )
        foreach ($f in $findings) { $script:State.Results.Add($f) }

        $covComplete = [PSCustomObject]@{
            DiscoveredResourceCount = 60; EvaluatedResourceCount = 60
            SkippedResourceCount = 0; FailedCollectionCount = 0
            SubscriptionsEvaluated = @('sub1'); SubscriptionsSkipped = @()
            CompleteEvaluation = $true; PartialEvaluation = $false; Summary = 'complete'
        }
        $covPartial = [PSCustomObject]@{
            DiscoveredResourceCount = 3; EvaluatedResourceCount = 2
            SkippedResourceCount = 0; FailedCollectionCount = 1
            SubscriptionsEvaluated = @('sub1'); SubscriptionsSkipped = @('sub2')
            CompleteEvaluation = $false; PartialEvaluation = $true; Summary = '2 of 3 evaluated'
        }
        $script:State.ExecutedChecks.Add((New-P29ExecRecord -CheckId 'AZURE-EXPOSURE-001' -Status 'Fail' -Coverage $covComplete -SummaryText '60 public-facing items'))
        $script:State.ExecutedChecks.Add((New-P29ExecRecord -CheckId 'STORAGE-002' -Status 'Partial' -Coverage $covPartial -SummaryText '2 of 3 evaluated'))
        $script:State.ExecutedChecks.Add((New-P29ExecRecord -CheckId 'NETWORK-003' -Status 'NotEvaluated' -Detail 'RBAC unreadable'))

        # Minimal capability model so the shared capability section renders.
        $script:State.CapabilityModel = [PSCustomObject]@{
            Insights = @()
            Nodes    = @()
            Edges    = @()
            Summary  = [PSCustomObject]@{ NodeCount = 0; EdgeCount = 0; HighestSeverity = $null }
            Limits   = $null
        }
    }

    function script:Render-P29Pentester {
        $out = Join-Path $TestDrive 'p29-pentester.html'
        Export-ResultsHtmlPentester -Results @($script:State.Results) -OutputPath $out | Out-Null
        Get-Content $out -Raw
    }
}

Describe "Pentester is the default layout" {

    It "ReportLayout defaults to Pentester in the shared state config" {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.ReportLayout | Should -Be 'Pentester'
        $script:State = Initialize-EntraAuditState
        $script:State.Config.ReportLayout | Should -Be 'Pentester'
    }

    It "ReportLayout param defaults to Pentester in the active AzureMap entrypoints (root wrapper + product)" {
        foreach ($script in @(
            "$projectRoot\azuremap.ps1",
            "$projectRoot\Products\AzureMap\azuremap.ps1"
        )) {
            (Get-Content $script -Raw) | Should -Match '\$ReportLayout\s*=\s*''Pentester''' -Because "$script must default -ReportLayout to Pentester"
        }
    }

    It "Show-AuditSummary with default config dispatches to the Pentester renderer" {
        New-P29AzureState
        $script:State.Timestamp = '20990101-000000'
        $script:State.Config.ExportFormats = @('HTML')
        Push-Location $TestDrive
        try {
            Show-AuditSummary
            $html = Get-Content "AzureSecurityAudit-20990101-000000.html" -Raw
            $html | Should -Match 'id="fd-0"'
            $html | Should -Match 'Pentester Overview'
            $html | Should -Not -Match 'id="components"'
        } finally {
            Pop-Location
        }
    }
}

Describe "Classic layout (legacy opt-in)" {

    It "Classic render produces Classic markers and no Pentester markers" {
        New-P29AzureState
        $out = Join-Path $TestDrive 'p29-classic.html'
        Export-ResultsHtml -Results @($script:State.Results) -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match 'id="components"'
        $html | Should -Match 'Affected Components'
        $html | Should -Not -Match 'id="fd-0"'
        $html | Should -Not -Match 'Pentester Overview'
    }

    It "Show-AuditSummary with ReportLayout=Classic dispatches to the Classic renderer" {
        New-P29AzureState
        $script:State.Timestamp = '20990101-000002'
        $script:State.Config.ExportFormats = @('HTML')
        $script:State.Config.ReportLayout = 'Classic'
        Push-Location $TestDrive
        try {
            Show-AuditSummary
            $html = Get-Content "AzureSecurityAudit-20990101-000002.html" -Raw
            $html | Should -Match 'id="components"'
            $html | Should -Not -Match 'id="fd-0"'
        } finally {
            Pop-Location
        }
    }
}

Describe "Pentester layout structure" {

    BeforeEach { New-P29AzureState }

    It "sections appear in order: overview, findings, capability, attacksurface, resources, coverage, checks" {
        $html = Render-P29Pentester
        $pos = @{}
        foreach ($s in @('overview','findings','capability','attacksurface','resources','coverage','checks')) {
            $pos[$s] = $html.IndexOf("id=""$s""")
            $pos[$s] | Should -BeGreaterOrEqual 0 -Because "section #$s must exist"
        }
        $pos['findings']      | Should -BeGreaterThan $pos['overview']
        $pos['capability']    | Should -BeGreaterThan $pos['findings']
        $pos['attacksurface'] | Should -BeGreaterThan $pos['capability']
        $pos['resources']     | Should -BeGreaterThan $pos['attacksurface']
        $pos['coverage']      | Should -BeGreaterThan $pos['resources']
        $pos['checks']        | Should -BeGreaterThan $pos['coverage']
    }

    It "findings section appears before the coverage section" {
        $html = Render-P29Pentester
        $html.IndexOf('id="findings"') | Should -BeLessThan $html.IndexOf('id="coverage"')
    }

    It "narrow findings table has exactly the 6 pentester columns (no Summary/Recommendation th)" {
        $html = Render-P29Pentester
        $start = $html.IndexOf('<table id="findingsTable">')
        $start | Should -BeGreaterOrEqual 0
        $thead = $html.Substring($start, $html.IndexOf('</thead>', $start) - $start)
        @([regex]::Matches($thead, '<th>')).Count | Should -Be 6
        foreach ($col in @('Severity','Finding','Service','Affected','Coverage','View')) {
            $thead | Should -Match "<th>$col</th>"
        }
        $thead | Should -Not -Match '<th>Summary</th>'
        $thead | Should -Not -Match '<th>Recommendation</th>'
        $thead | Should -Not -Match '<th>Check</th>'
    }

    It "View links match the fd-N detail anchors (index-set equality)" {
        $html = Render-P29Pentester
        $linkIdx   = @([regex]::Matches($html, 'href="#fd-(\d+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $anchorIdx = @([regex]::Matches($html, 'id="fd-(\d+)"')   | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        ($linkIdx -join ',')   | Should -Be ($anchorIdx -join ',')
        ($anchorIdx -join ',') | Should -Be '0,1'
    }

    It "affected evidence renders inside the fd- details block with the 50-row cap note" {
        $html = Render-P29Pentester
        # fd-0 is the CRITICAL exposure group (severity rank sorts first)
        $start = $html.IndexOf('id="fd-0"')
        $start | Should -BeGreaterOrEqual 0
        $block = $html.Substring($start, $html.IndexOf('</details>', $start) - $start)
        $block | Should -Match 'Public-facing resource exposure'
        $block | Should -Match 'ev-0'
        $block | Should -Match 'showing first 50 of 60'
        $block | Should -Match 'Affected components'
    }

    It "Recommendation renders inside the details block" {
        $html = Render-P29Pentester
        $start = $html.IndexOf('id="fd-0"')
        $block = $html.Substring($start, $html.IndexOf('</details>', $start) - $start)
        $block | Should -Match 'Recommendation:'
        $block | Should -Match 'Reduce public exposure\.'
    }

    It "compact coverage status line is present before the findings section" {
        $html = Render-P29Pentester
        $html | Should -Match 'Coverage:\s*Partial'
        $html | Should -Match '1/2 coverage-aware checks complete'
        $html | Should -Match '1 not evaluated'
        $html | Should -Match 'Data-plane:\s*Off'
        $html | Should -Match 'Errors:\s*0'
        $html.IndexOf('class="statusline"') | Should -BeLessThan $html.IndexOf('id="findings"')
    }

    It "metrics strip uses 'Affected components' wording (not 'Affected resources')" {
        $html = Render-P29Pentester
        $html | Should -Match 'Affected components'
        # case-sensitive: the Classic "Affected Resources" card label must be gone
        # (lowercase prose like "(no affected resources)" is fine)
        $html | Should -Not -CMatch 'Affected Resources'
        $html | Should -Not -Match 'id="components"'
    }

    It "capability section renders via the shared renderer" {
        $html = Render-P29Pentester
        $html | Should -Match 'id="capability"'
        $html | Should -Match 'Capability Insights'
    }

    It "attack surface re-displays existing exposure findings and skips absent check ids silently" {
        $html = Render-P29Pentester
        $html | Should -Match 'id="attacksurface"'
        $html | Should -Match 'Public-facing items \(exposure inventory\)'
        # STORAGE-002 exists in the run; KEYVAULT-002 does not - absent silently
        $html | Should -Match 'Storage network exposure'
        $html | Should -Not -Match 'Key Vault network exposure'
        # its View link points back into the findings detail anchors
        $html | Should -Match 'href="#fd-0"'
    }

    It "is self-contained: no external references" {
        $html = Render-P29Pentester
        $html | Should -Not -Match 'href\s*=\s*"http'
        $html | Should -Not -Match 'src\s*=\s*"http'
        $html | Should -Match 'prefers-color-scheme'
    }

    It "BAAS house-style markers are present" {
        $html = Render-P29Pentester
        $html | Should -Match 'Created by BAAS'
        $html | Should -Match '0xbaas.com'
        $html | Should -Match 'Built by <span class="brand">BAAS</span>'
    }

    It "explicit NOTEVALUATED is preserved, never recomputed to PASS" {
        $html = Render-P29Pentester
        $html | Should -Match 'NOTEVALUATED'
        $html | Should -Match 'NETWORK-003'
        # the not-evaluated check shows up in the attention table
        $html | Should -Match 'Not Evaluated / Partial / Errors'
        # the Count=0 NOTEVALUATED record must not appear as a findings-table row
        $start = $html.IndexOf('<table id="findingsTable">')
        $tableEnd = $html.IndexOf('</table>', $start)
        $table = $html.Substring($start, $tableEnd - $start)
        $table | Should -Not -Match 'Public IP evaluation'
    }

    It "coverage section contains the Check Coverage and Data-Plane tables" {
        $html = Render-P29Pentester
        $html | Should -Match 'Check Coverage'
        $html | Should -Match 'Data-Plane Checks'
    }

    It "all nav anchors resolve to real sections" {
        $html = Render-P29Pentester
        $navStart = $html.IndexOf('<nav>')
        $nav = $html.Substring($navStart, $html.IndexOf('</nav>', $navStart) - $navStart)
        foreach ($m in [regex]::Matches($nav, 'href="#([\w-]+)"')) {
            $anchor = $m.Groups[1].Value
            $html | Should -Match "id=""$anchor""" -Because "nav anchor #$anchor must resolve"
        }
    }
}

Describe "Pentester redaction flows through the shared chokepoint" {

    It "with -RedactSensitive, UPNs and GUIDs in evidence are masked" {
        New-P29AzureState
        $script:State.Config.RedactSensitive = $true
        $upn  = 'admin1@contoso.onmicrosoft.com'
        $guid = 'aaaa0001-0000-4000-8000-000000000001'
        $script:State.Results.Add((New-P29Finding -CheckId 'P29-REDACT' -Severity 'MEDIUM' -Service 'Identity' `
            -Finding 'Privileged principals' -Count 1 `
            -Evidence @([PSCustomObject]@{ PrincipalName = $upn; PrincipalId = $guid; Role = 'Owner' })))
        $html = Render-P29Pentester
        $html | Should -Not -Match ([regex]::Escape($upn))
        $html | Should -Not -Match ([regex]::Escape($guid))
        $html | Should -Match ([regex]::Escape('***@***'))
        $html | Should -Match ([regex]::Escape('********-****-****-****-************'))
    }
}

Describe "Pentester layout - EntraMap product shape" {

    It "renders tenant counts and a muted not-applicable attack surface line" {
        $script:State = Initialize-EntraAuditState
        $script:State.Config.Quiet = $true
        $script:State.LogFile = Join-Path $TestDrive 'EntraMap-p29-test.log'
        $dims = [ordered]@{}
        foreach ($d in @(
            @{ Key = 'Users';             Label = 'Users';              Value = 120 },
            @{ Key = 'Groups';            Label = 'Groups';             Value = 45 },
            @{ Key = 'ServicePrincipals'; Label = 'Service principals'; Value = 30 },
            @{ Key = 'AppRegistrations';  Label = 'App registrations';  Value = 22 }
        )) {
            $dims[$d.Key] = [PSCustomObject]@{ Label = $d.Label; Value = $d.Value; Status = 'Available'; Reason = ''; Source = 'MicrosoftGraph' }
        }
        $script:State.EntraFootprint = [PSCustomObject]@{
            TenantId = 'tenant'; Account = 'acct'; GraphAccess = 'Available'
            Dimensions = $dims; Source = 'MicrosoftGraph'; Note = ''; FetchedAt = Get-Date
        }
        $script:State.Results.Add((New-P29Finding -CheckId 'ENTRA-02' -Severity 'CRITICAL' -Service 'EntraPIM' `
            -Finding 'Standing privileged assignments' -Count 3 `
            -Evidence @([PSCustomObject]@{ PrincipalName = 'user1'; Role = 'Global Administrator' })))
        $script:State.ExecutedChecks.Add((New-P29ExecRecord -CheckId 'ENTRA-02' -Status 'Fail'))

        $html = Render-P29Pentester
        $html | Should -Match 'id="overview"'
        $html | Should -Match '>120</div><div class="lbl">Users</div>'
        $html | Should -Match '>45</div><div class="lbl">Groups</div>'
        $html | Should -Match 'Attack surface mapping is not applicable'
        $html | Should -Match 'Tenant footprint'
        $html | Should -Match 'id="fd-0"'
    }
}

Describe "-ReportLayout parameter plumbing" {

    It "ReportLayout is accepted by the active AzureMap entrypoint and the root wrapper" {
        # EntraMap is parked under Future/EntraMap (not an active entrypoint),
        # so only the AzureMap scripts are asserted here.
        foreach ($script in @(
            "$projectRoot\Products\AzureMap\azuremap.ps1",
            "$projectRoot\azuremap.ps1"
        )) {
            $cmd = Get-Command $script
            $cmd.Parameters.ContainsKey('ReportLayout') | Should -BeTrue -Because "$script must expose -ReportLayout"
            $cmd.Parameters['ReportLayout'].ParameterType | Should -Be ([string])
        }
    }

    It "ReportLayout defaults to Pentester and rejects values outside the ValidateSet" {
        foreach ($script in @(
            "$projectRoot\Products\AzureMap\azuremap.ps1",
            "$projectRoot\azuremap.ps1"
        )) {
            $p = (Get-Command $script).Parameters['ReportLayout']
            $vs = @($p.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] })
            $vs.Count | Should -Be 1 -Because "$script must constrain -ReportLayout via ValidateSet"
            $vs[0].ValidValues | Should -Contain 'Classic'
            $vs[0].ValidValues | Should -Contain 'Pentester'
            $vs[0].ValidValues | Should -Not -Contain 'Bogus'
            # default value declared in the param block
            (Get-Content $script -Raw) | Should -Match '\$ReportLayout\s*=\s*''Pentester'''
        }
    }

    It "Show-AuditSummary with ReportLayout=Pentester dispatches to the Pentester renderer (same output path/name)" {
        New-P29AzureState
        $script:State.Timestamp = '20990101-000001'
        $script:State.Config.ExportFormats = @('HTML')
        $script:State.Config.ReportLayout = 'Pentester'
        Push-Location $TestDrive
        try {
            Show-AuditSummary
            Test-Path "AzureSecurityAudit-20990101-000001.html" | Should -BeTrue
            $html = Get-Content "AzureSecurityAudit-20990101-000001.html" -Raw
            $html | Should -Match 'id="fd-0"'
            $html | Should -Match 'Pentester Overview'
            $html | Should -Not -Match 'id="components"'
        } finally {
            Pop-Location
        }
    }
}
