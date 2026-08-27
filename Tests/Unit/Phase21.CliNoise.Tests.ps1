#==============================================================================
# AzureMap v2 - Tests/Unit/Phase21.CliNoise.Tests.ps1
# CLI noise-reduction pass: the normal run shows only clean grouped check rows.
#   * no remediation commands / raw finding blocks in normal output
#   * discovery source hidden from normal output (log/debug only)
#   * only relevant checks printed during "Running assessment" by default
#   * Inventory (never Clean) when exposure inventory records exist
#   * long display names can never collide with the status label
#   * CVSS severity colors fixed (LOW #9BE7A1, MEDIUM #D6A84B)
#   * "Could not check" rows carry a useful human reason
#   * Fail + incomplete sub-collections is explicit on the row
#   * final Check results section only under -DetailedSummary
#   * exports keep full detail and internal statuses regardless
# Mocked/local only. No Azure, no Graph, no data-plane.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Redaction.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\Retry.ps1"
    . "$projectRoot\Core\RunStatus.ps1"
    . "$projectRoot\Core\Azure\Footprint.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Core\Console.ps1"
    . "$projectRoot\Export\Json.ps1"
    . "$projectRoot\Export\Csv.ps1"

    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }
    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }

    function script:New-FxSub {
        [PSCustomObject]@{ Id = 'sub-1'; Name = 'fx-sub'; TenantId = 't-1'; SubscriptionId = 'sub-1' }
    }
}

Describe "Write-Finding - normal CLI carries no remediation commands or raw finding blocks" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        $script:captured = New-Object System.Collections.Generic.List[string]
        Mock Write-Host { param($Object, $ForegroundColor) [void]$script:captured.Add("$Object") }
    }

    It "default run prints nothing per finding, but the record is still exported" {
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'shared key enabled' -Count 3 `
            -Service 'Storage' -CheckId 'ZZ-REM' `
            -Remediation "Set-AzStorageAccount -ResourceGroupName <rg> -Name <sa> -AllowSharedKeyAccess `$false"
        ($script:captured -join "`n") | Should -BeNullOrEmpty
        @($script:State.Results | Where-Object { $_.CheckId -eq 'ZZ-REM' }).Count | Should -Be 1
        $script:State.Results[0].Remediation | Should -Match 'Set-AzStorageAccount'
    }

    It "-VerboseOutput adds detail but NEVER raw finding blocks (opt-in via -ShowFindings only)" {
        $script:State.Config.VerboseOutput = $true
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'shared key enabled' -Count 3 `
            -Service 'Storage' -CheckId 'ZZ-REM' -Remediation 'Set-AzStorageAccount -AllowSharedKeyAccess $false'
        $all = $script:captured -join "`n"
        $all | Should -Not -Match 'Finding: shared key enabled'
        $all | Should -Not -Match 'Severity: HIGH'
        $all | Should -Not -Match 'Set-AzStorageAccount'
        # The record itself is still preserved for the exports.
        @($script:State.Results | Where-Object { $_.CheckId -eq 'ZZ-REM' }).Count | Should -Be 1
    }

    It "-ShowFindings shows blocks without remediation; -ShowRemediation adds it" {
        $script:State.Config.ShowFindings = $true
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'block only' -Count 1 `
            -Service 'Storage' -CheckId 'ZZ-REM' -Remediation 'Set-AzStorageAccount foo'
        $all = $script:captured -join "`n"
        $all | Should -Match 'Finding: block only'
        $all | Should -Not -Match 'Set-AzStorageAccount'

        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.Config.ShowRemediation = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        $script:captured.Clear()
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'with remediation' -Count 1 `
            -Service 'Storage' -CheckId 'ZZ-REM' -Remediation 'Set-AzStorageAccount foo'
        $all2 = $script:captured -join "`n"
        $all2 | Should -Match 'Remediation: Set-AzStorageAccount foo'
    }
}

Describe "Invoke-AuditChecks - only relevant checks print during Running assessment" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        # High-confidence complete footprint containing only storage accounts,
        # so applicability gating is active (fail-safe does not kick in).
        $script:State.Footprint = [PSCustomObject]@{
            TypeCounts = @{ 'microsoft.storage/storageaccounts' = 5 }
            Source = 'ResourceGraph'; CoverageStatus = 'Complete'; Confidence = 'High'
        }
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
    }

    It "Not in scope rows are hidden by default and shown under -DetailedSummary" {
        function global:Test-RelCheck { param([array]$Subscriptions)
            Write-Finding -Severity 'INFO' -Status 'PASS' -Message 'all good' -Count 0 -Service 'Storage' -CheckId 'ZZ-REL'
        }
        function global:Test-GatedCheck { param([array]$Subscriptions) throw 'GATED CHECK MUST NOT EXECUTE' }
        Register-AuditCheck -CheckId 'ZZ-REL'   -Category 'Azure' -Service 'Storage' -Name 'relevant' -Function 'Test-RelCheck'   -Phase 'PerSubscription' -AlwaysRun $true
        Register-AuditCheck -CheckId 'ZZ-GATED' -Category 'Azure' -Service 'SQL'     -Name 'gated'    -Function 'Test-GatedCheck' -Phase 'PerSubscription' -RequiredResourceTypes @('microsoft.sql/servers')

        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $normal = $script:ui -join "`n"
        $normal | Should -Match 'ZZ-REL'
        $normal | Should -Not -Match 'ZZ-GATED'
        $normal | Should -Not -Match 'Not in scope'
        # The record is still captured for the summary counts and exports.
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-GATED' })[0]
        $rec.Status | Should -Be 'NotApplicable'

        # Detailed mode shows the Not in scope row with its reason.
        $script:State.Config.DetailedSummary = $true
        $script:ui.Clear()
        $script:State.ExecutedChecks.Clear()
        $script:State.Results.Clear()
        $script:State.CheckRegistry.Clear()
        Register-AuditCheck -CheckId 'ZZ-REL'   -Category 'Azure' -Service 'Storage' -Name 'relevant' -Function 'Test-RelCheck'   -Phase 'PerSubscription' -AlwaysRun $true
        Register-AuditCheck -CheckId 'ZZ-GATED' -Category 'Azure' -Service 'SQL'     -Name 'gated'    -Function 'Test-GatedCheck' -Phase 'PerSubscription' -RequiredResourceTypes @('microsoft.sql/servers')
        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $detailed = $script:ui -join "`n"
        $detailed | Should -Match 'ZZ-GATED'
        $detailed | Should -Match 'Not in scope'
        $detailed | Should -Match 'No servers resources in scope'
    }

    It "mode-skipped (Skipped) rows are hidden by default" {
        function global:Test-ModeEntra { throw 'MUST NOT RUN' }
        Register-AuditCheck -CheckId 'ZZ-ENTRA' -Category 'Entra' -Service 'EntraRoles' -Name 'entra' -Function 'Test-ModeEntra' -Phase 'TenantWide'
        Invoke-AuditChecks -SkipEntra -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $normal = $script:ui -join "`n"
        $normal | Should -Not -Match 'ZZ-ENTRA'
        $normal | Should -Not -Match '\bSkipped\b'
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-ENTRA' })[0]
        $rec.Status | Should -Be 'Skipped'
    }
}

Describe "Could not check rows carry a useful reason" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
    }

    It "surfaces the first NotEvaluated finding message on the check row" {
        function global:Test-EventHubish { param([array]$Subscriptions)
            Write-Finding -Severity 'MEDIUM' -Status 'NotEvaluated' -Count 0 `
                -Message 'Az.EventHub cmdlet unavailable' -Service 'EventHub' -CheckId 'ZZ-EH'
        }
        Register-AuditCheck -CheckId 'ZZ-EH' -Category 'Azure' -Service 'EventHub' -Name 'event hub' -Function 'Test-EventHubish' -Phase 'PerSubscription' -AlwaysRun $true
        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $all = $script:ui -join "`n"
        $all | Should -Match 'Could not check'
        $all | Should -Match 'Az\.EventHub cmdlet unavailable'
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-EH' })[0]
        $rec.SummaryText | Should -Be 'Az.EventHub cmdlet unavailable'
    }
}

Describe "Inventory vs Clean" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
    }

    It "inventory records mixed with empty PASS records resolve to Inventory, not Clean" {
        $findings = @(
            [PSCustomObject]@{ Status = 'PASS'; Count = 70; Severity = 'INFO'; IsInventoryOnly = $true },
            [PSCustomObject]@{ Status = 'PASS'; Count = 0;  Severity = 'INFO'; IsInventoryOnly = $false }
        )
        Resolve-CheckStatus -ProducedFindings $findings | Should -Be 'Inventory'
    }

    It "inventory-only records with zero items are a proven-empty scope (Pass/Clean)" {
        $findings = @(
            [PSCustomObject]@{ Status = 'PASS'; Count = 0; Severity = 'INFO'; IsInventoryOnly = $true }
        )
        Resolve-CheckStatus -ProducedFindings $findings | Should -Be 'Pass'
    }

    It "exposure-style run shows 'Inventory  70 public-facing items', never Clean" {
        function global:Test-Exposureish { param([array]$Subscriptions)
            foreach ($s in @($Subscriptions)) {
                Write-Finding -Severity 'INFO' -Status 'PASS' -Count 70 -Service 'Exposure' -CheckId 'ZZ-EXP' `
                    -Message 'Central public exposure inventory' -IsInventoryOnly $true
            }
        }
        Register-AuditCheck -CheckId 'ZZ-EXP' -Category 'Azure' -Service 'Exposure' -Name 'Public Exposure Inventory' -Function 'Test-Exposureish' -Phase 'PerSubscription' -AlwaysRun $true
        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-EXP' })[0]
        $rec.Status | Should -Be 'Inventory'
        $rec.SummaryText | Should -Be '70 public-facing items'
        $all = $script:ui -join "`n"
        $all | Should -Match 'Inventory'
        $all | Should -Match '70 public-facing items'
        $all | Should -Not -Match 'Clean'
    }
}

Describe "Fail with incomplete sub-collections is explicit on the row" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
    }

    It "appends an incomplete-evaluation marker to the check summary" {
        function global:Test-PartialApim { param([array]$Subscriptions)
            Write-Finding -Severity 'HIGH' -Status 'FAIL' -Count 5 -Service 'APIM' -CheckId 'ZZ-APIM' `
                -Message 'public services' `
                -DiscoveredResourceCount 6 -EvaluatedResourceCount 5 -FailedCollectionCount 1 `
                -CollectionStatus 'Partial' -PartialEvaluation $true
        }
        Register-AuditCheck -CheckId 'ZZ-APIM' -Category 'Azure' -Service 'APIM' -Name 'apim' -Function 'Test-PartialApim' -Phase 'PerSubscription' -AlwaysRun $true
        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-APIM' })[0]
        $rec.Status | Should -Be 'Fail'
        $rec.SummaryText | Should -Match '5 affected'
        $rec.SummaryText | Should -Match 'evaluation incomplete'
    }
}

Describe "Long display names never collide with the status label" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.Config.NoColor = $true
        $script:captured = New-Object System.Collections.Generic.List[string]
        Mock Write-Host { param($Object) [void]$script:captured.Add("$Object") }
    }

    It "every curated display name fits the name column with room to spare" {
        foreach ($k in $script:CheckDisplayNames.Keys) {
            # Name column is 40 wide with a 2-space indent: 37 chars max.
            $script:CheckDisplayNames[$k].Length | Should -BeLessOrEqual 37
        }
        # The previously colliding names were shortened.
        $script:CheckDisplayNames['ENTRA-03']     | Should -Be 'Dangerous app permissions'
        $script:CheckDisplayNames['IDENTITY-005'] | Should -Be 'Custom RBAC roles'
    }

    It "an over-long name is still separated from the status by whitespace" {
        $longName = 'A' * 45
        $check  = [PSCustomObject]@{ CheckId = 'ZZ-LONG'; Name = $longName; Service = 'Storage'; Category = 'Azure' }
        $record = [PSCustomObject]@{ Status = 'Pass' }
        Write-CheckStatusLine -Index 1 -Total 2 -Check $check -Record $record
        ($script:captured -join '') | Should -Match ('A{45}\s+Clean')
    }

    It "Format-UiColumn guarantees a trailing gap for over-wide text" {
        Format-UiColumn -Text ('X' * 50) -Width 40 | Should -Be (('X' * 50) + ' ')
        Format-UiColumn -Text 'abc' -Width 6       | Should -Be 'abc   '
    }
}

Describe "CVSS-like severity colors are fixed" {

    It "LOW uses the lighter green #9BE7A1" {
        $script:BaasAnsiColors['LightGreen'] | Should -Be '155;231;161'
    }

    It "the console palette matches the fixed CVSS ramp" {
        $script:BaasAnsiColors['Cyan']       | Should -Be '56;168;220'    # INFO / accent #38A8DC
        $script:BaasAnsiColors['LightGreen'] | Should -Be '155;231;161'   # LOW #9BE7A1
        $script:BaasAnsiColors['Yellow']     | Should -Be '214;168;75'    # MEDIUM #D6A84B
        $script:BaasAnsiColors['DarkYellow'] | Should -Be '230;138;58'    # HIGH #E68A3A
        $script:BaasAnsiColors['CritRed']    | Should -Be '240;82;82'     # CRITICAL #F05252
    }

    It "the HTML report palette matches the fixed CVSS ramp" {
        $html = Get-Content (Join-Path $projectRoot 'Export\Html.ps1') -Raw
        $html | Should -Match '--low:#9BE7A1'
        $html | Should -Match '--med:#D6A84B'
        $html | Should -Match '--high:#E68A3A'
        $html | Should -Match '--crit:#F05252'
        $html | Should -Match '--info:#38A8DC'
        $html | Should -Match '--accent:#38A8DC'
        # Section accent and MEDIUM severity are intentionally distinct.
        $html | Should -Not -Match '--med:#38A8DC'
    }
}

Describe "Show-AuditConsole - final Check results section is opt-in" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet  = $false
        $script:State.Config.NoColor = $true
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
        $script:State.ExecutedChecks.Add([PSCustomObject]@{
            CheckId = 'STORAGE-001'; Name = 'x'; Status = 'Fail'; Service = 'Storage'; Category = 'Azure'
            SummaryText = '1 risky'; Detail = $null; ErrorClass = $null; Coverage = $null
        })
    }

    It "normal summary omits the repeated per-check list" {
        Show-AuditConsole -ExportedFiles @()
        $all = $script:ui -join "`n"
        $all | Should -Not -Match 'Check results'
        # The compact sections remain.
        $all | Should -Match 'Summary'
        $all | Should -Match 'Status'
        $all | Should -Match 'Top findings'
        $all | Should -Match 'Needs attention'
        $all | Should -Match 'Exports'
    }

    It "-DetailedSummary renders the full Check results section" {
        $script:State.Config.DetailedSummary = $true
        Show-AuditConsole -ExportedFiles @()
        $all = $script:ui -join "`n"
        $all | Should -Match 'Check results'
        $all | Should -Match 'STORAGE-001'
    }
}

Describe "Exports preserve detailed evidence and internal statuses" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
    }

    It "JSON/CSV keep the internal status and the remediation text" {
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'shared key enabled' -Count 2 `
            -Service 'Storage' -CheckId 'ZZ-EXP-KEEP' `
            -Data @([PSCustomObject]@{ Name = 'res1' }, [PSCustomObject]@{ Name = 'res2' }) `
            -Remediation 'Set-AzStorageAccount -ResourceGroupName <rg> -Name <sa> -AllowSharedKeyAccess $false'
        $script:State.ExecutedChecks.Add([PSCustomObject]@{
            CheckId = 'ZZ-EXP-KEEP'; Name = 'x'; Status = 'NotApplicable'; Service = 'Storage'; Category = 'Azure'
            SummaryText = $null; Detail = 'No relevant resources'; ErrorClass = $null; Coverage = $null
        })

        $base = Join-Path $TestDrive 'keep'
        Export-ResultsJson -Results $script:State.Results -BaseName $base | Out-Null
        $raw = Get-Content "$base.json" -Raw
        $raw | Should -Match '"Status":\s*"FAIL"'
        $raw | Should -Match 'Set-AzStorageAccount'
        $raw | Should -Match '"Status":\s*"NotApplicable"'

        Export-ResultsCsv -Results $script:State.Results -BaseName $base | Out-Null
        # Summary CSV: one row per finding, carries the Remediation column.
        $sum = Get-Content "$base.csv" -Raw
        $sum | Should -Match 'Remediation'
        $sum | Should -Match 'Set-AzStorageAccount'
        # Detailed CSV: one row per evidence item, keeps the internal status.
        $det = Get-Content "$base-Detailed.csv" -Raw
        $det | Should -Match 'FindingStatus'
        $det | Should -Match 'FAIL'
    }
}
