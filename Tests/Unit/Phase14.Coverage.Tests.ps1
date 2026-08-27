#==============================================================================
# AzureMap v2 - Tests/Unit/Phase14.Coverage.Tests.ps1
# Phase B1 - coverage integrity + no false PASS foundation.
# Mocked/local only. No Azure, no Graph, no authentication, no listKeys.
#
# Covers:
#   * Resolve-CheckStatus B1 matrix (silence is NOT a Pass)
#   * New-AzureMapFinding / New-CheckExecutionRecord coverage schema
#   * Get-CheckCoverage aggregation (Max semantics, subscription union)
#   * Invoke-AuditChecks integration (coverage + summary on execution records)
#   * Get-RunDiagnostics Partial tally
#   * Export visibility: CSV / Detailed CSV / JSON / HTML preserve explicit
#     status and coverage (HTML must never render NotEvaluated as PASS)
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
    . "$projectRoot\Export\Csv.ps1"
    . "$projectRoot\Export\Json.ps1"
    . "$projectRoot\Export\Html.ps1"
    . "$projectRoot\Export\Summary.ps1"

    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }

    function New-B1Finding {
        param(
            [int]$Count = 0,
            [string]$Status = 'PASS',
            [hashtable]$Coverage = @{}
        )
        $params = @{
            Severity = 'HIGH'; Message = 'synthetic b1 finding'; Count = $Count
            Service  = 'Storage'; CheckId = 'B1-TEST'; Status = $Status
        }
        foreach ($k in $Coverage.Keys) { $params[$k] = $Coverage[$k] }
        New-AzureMapFinding @params
    }
}

Describe "Resolve-CheckStatus - B1 status matrix" {

    It "zero produced findings -> NotEvaluated (silence is never a Pass)" {
        Resolve-CheckStatus -ProducedFindings @() | Should -Be 'NotEvaluated'
    }

    It "explicit PASS record -> Pass" {
        $f = New-B1Finding -Count 0 -Status 'PASS' -Coverage @{ CompleteEvaluation = $true; EvaluatedResourceCount = 3 }
        Resolve-CheckStatus -ProducedFindings @($f) | Should -Be 'Pass'
    }

    It "real finding (Count>0) -> Fail" {
        $f = New-B1Finding -Count 2 -Status 'FAIL'
        Resolve-CheckStatus -ProducedFindings @($f) | Should -Be 'Fail'
    }

    It "PARTIAL record -> Partial" {
        $f = New-B1Finding -Count 0 -Status 'PARTIAL' -Coverage @{ PartialEvaluation = $true }
        Resolve-CheckStatus -ProducedFindings @($f) | Should -Be 'Partial'
    }

    It "PartialEvaluation flag (without PARTIAL status) -> Partial" {
        $f = New-B1Finding -Count 0 -Status 'PASS' -Coverage @{ PartialEvaluation = $true }
        Resolve-CheckStatus -ProducedFindings @($f) | Should -Be 'Partial'
    }

    It "Fail beats Partial when both exist" {
        $fail = New-B1Finding -Count 1 -Status 'FAIL'
        $part = New-B1Finding -Count 0 -Status 'PARTIAL' -Coverage @{ PartialEvaluation = $true }
        Resolve-CheckStatus -ProducedFindings @($fail, $part) | Should -Be 'Fail'
    }

    It "Partial beats NotEvaluated when both exist" {
        $part = New-B1Finding -Count 0 -Status 'PARTIAL' -Coverage @{ PartialEvaluation = $true }
        $ne   = New-B1Finding -Count 0 -Status 'NOTEVALUATED'
        Resolve-CheckStatus -ProducedFindings @($part, $ne) | Should -Be 'Partial'
    }

    It "NotEvaluated record -> NotEvaluated" {
        $f = New-B1Finding -Count 0 -Status 'NOTEVALUATED'
        Resolve-CheckStatus -ProducedFindings @($f) | Should -Be 'NotEvaluated'
    }

    It "WARNING record -> Warning" {
        $f = New-B1Finding -Count 0 -Status 'WARNING'
        Resolve-CheckStatus -ProducedFindings @($f) | Should -Be 'Warning'
    }

    It "Threw -> Error" {
        Resolve-CheckStatus -Threw -ProducedFindings @() | Should -Be 'Error'
    }
}

Describe "New-AzureMapFinding - coverage schema" {

    It "coverage fields default to null/false (unknown is not zero)" {
        $f = New-AzureMapFinding -Severity 'HIGH' -Message 'plain' -Count 0 -Service 'Storage' -CheckId 'B1-DEFAULT'
        $null -eq $f.DiscoveredResourceCount | Should -BeTrue
        $null -eq $f.EvaluatedResourceCount  | Should -BeTrue
        $f.CompleteEvaluation | Should -BeFalse
        $f.PartialEvaluation  | Should -BeFalse
        "$($f.CollectionStatus)" | Should -Be ''
        $f.DataPlaneRequired  | Should -BeFalse
    }

    It "stores coverage values and accepts PARTIAL status" {
        $f = New-AzureMapFinding -Severity 'HIGH' -Message 'cov' -Count 0 -Service 'Storage' -CheckId 'B1-COV' `
            -Status 'PARTIAL' -DiscoveredResourceCount 10 -EvaluatedResourceCount 7 -SkippedResourceCount 3 `
            -FailedCollectionCount 1 -SubscriptionsEvaluated @('subA') -SubscriptionsSkipped @('subB') `
            -CollectionStatus 'Partial' -PartialEvaluation $true `
            -CoverageSummary '7 of 10 evaluated' -SummaryText '7 of 10 evaluated' `
            -Confidence 'Medium' -FindingType 'Misconfiguration' -ApiSources @('ARM Get-AzStorageAccount') `
            -DataPlaneRequired $true -ManualValidationRequired $true
        "$($f.Status)"                   | Should -Be 'PARTIAL'
        [int]$f.DiscoveredResourceCount  | Should -Be 10
        [int]$f.EvaluatedResourceCount   | Should -Be 7
        [int]$f.SkippedResourceCount     | Should -Be 3
        [int]$f.FailedCollectionCount    | Should -Be 1
        @($f.SubscriptionsEvaluated)     | Should -Contain 'subA'
        @($f.SubscriptionsSkipped)       | Should -Contain 'subB'
        $f.PartialEvaluation             | Should -BeTrue
        $f.ManualValidationRequired      | Should -BeTrue
        $f.DataPlaneRequired             | Should -BeTrue
    }
}

Describe "New-CheckExecutionRecord - coverage fields" {
    It "record carries Coverage and SummaryText slots" {
        $check = [PSCustomObject]@{ CheckId = 'B1-REC'; Name = 'rec'; Category = 'Azure'; Service = 'Storage'; Phase = 'PerSubscription' }
        $rec = New-CheckExecutionRecord -Check $check
        $rec.PSObject.Properties.Name | Should -Contain 'Coverage'
        $rec.PSObject.Properties.Name | Should -Contain 'SummaryText'
        $rec.Status | Should -Be 'Pending'
    }
}

Describe "Get-CheckCoverage aggregation" {

    It "returns null when no finding carries coverage data" {
        $plain = [PSCustomObject]@{ Status = 'PASS'; Count = 0 }
        Get-CheckCoverage -Findings @($plain) | Should -BeNullOrEmpty
    }

    It "uses Max (not Sum) for counts describing the same population" {
        $a = New-B1Finding -Coverage @{ DiscoveredResourceCount = 5; EvaluatedResourceCount = 5; CompleteEvaluation = $true }
        $b = New-B1Finding -Coverage @{ DiscoveredResourceCount = 5; EvaluatedResourceCount = 5; CompleteEvaluation = $true }
        $cov = Get-CheckCoverage -Findings @($a, $b)
        [int]$cov.DiscoveredResourceCount | Should -Be 5
        $cov.CompleteEvaluation | Should -BeTrue
    }

    It "unions subscription lists and marks partial when any finding is partial" {
        $a = New-B1Finding -Coverage @{ EvaluatedResourceCount = 3; CompleteEvaluation = $true; SubscriptionsEvaluated = @('subA') }
        $b = New-B1Finding -Coverage @{ EvaluatedResourceCount = 3; PartialEvaluation = $true; FailedCollectionCount = 1; SubscriptionsSkipped = @('subB'); CoverageSummary = 'partial run' }
        $cov = Get-CheckCoverage -Findings @($a, $b)
        @($cov.SubscriptionsEvaluated) | Should -Contain 'subA'
        @($cov.SubscriptionsSkipped)   | Should -Contain 'subB'
        $cov.PartialEvaluation  | Should -BeTrue
        $cov.CompleteEvaluation | Should -BeFalse
        $cov.Summary            | Should -Be 'partial run'
    }
}

Describe "Invoke-AuditChecks - B1 execution records" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:FxSub = [PSCustomObject]@{ Id = 'S1'; Name = 'n1'; TenantId = 'T1' }
    }

    It "a check that produces nothing is NotEvaluated, never Pass" {
        function global:Test-B1Silent { param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0) }
        Register-AuditCheck -CheckId 'B1-SILENT' -Category 'Azure' -Service 'Storage' -Name 'silent' -Function 'Test-B1Silent' -Phase 'PerSubscription'
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'B1-SILENT' })[0]
        $rec.Status | Should -Be 'NotEvaluated'
    }

    It "a check with explicit PASS + coverage is Pass and carries coverage on the record" {
        function global:Test-B1Proven {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            Write-Finding -Severity 'HIGH' -Status 'PASS' -Message 'proven clean' -Count 0 -Service 'Storage' -CheckId 'B1-PROVEN' `
                -DiscoveredResourceCount 3 -EvaluatedResourceCount 3 -CollectionStatus 'Complete' -CompleteEvaluation $true `
                -CoverageSummary '3 storage accounts evaluated; 0 risky; coverage complete.' `
                -SummaryText '3 storage accounts evaluated; 0 risky; coverage complete.'
        }
        Register-AuditCheck -CheckId 'B1-PROVEN' -Category 'Azure' -Service 'Storage' -Name 'proven' -Function 'Test-B1Proven' -Phase 'PerSubscription'
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'B1-PROVEN' })[0]
        $rec.Status | Should -Be 'Pass'
        $rec.Coverage | Should -Not -BeNullOrEmpty
        [int]$rec.Coverage.EvaluatedResourceCount | Should -Be 3
        $rec.SummaryText | Should -BeLike '*coverage complete.*'
    }

    It "a PARTIAL check resolves to Partial with failed collection count" {
        function global:Test-B1Partial {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            Write-Finding -Severity 'HIGH' -Status 'PARTIAL' -Message 'partial run' -Count 0 -Service 'Storage' -CheckId 'B1-PARTIAL' `
                -DiscoveredResourceCount 5 -EvaluatedResourceCount 3 -FailedCollectionCount 1 `
                -CollectionStatus 'Partial' -PartialEvaluation $true -CoverageSummary '3 of 5 evaluated; 1 failed'
        }
        Register-AuditCheck -CheckId 'B1-PARTIAL' -Category 'Azure' -Service 'Storage' -Name 'partial' -Function 'Test-B1Partial' -Phase 'PerSubscription'
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'B1-PARTIAL' })[0]
        $rec.Status | Should -Be 'Partial'
        [int]$rec.Coverage.FailedCollectionCount | Should -Be 1
        $rec.Coverage.PartialEvaluation | Should -BeTrue
    }

    It "prints one human per-check status line (domain header, display label, summary, muted CheckId)" {
        function global:Test-B1Line {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            Write-Finding -Severity 'HIGH' -Status 'PASS' -Message 'proven clean' -Count 0 -Service 'Storage' -CheckId 'B1-LINE' `
                -EvaluatedResourceCount 3 -CompleteEvaluation $true -CollectionStatus 'Complete' `
                -SummaryText '3 resources evaluated; 0 risky; coverage complete.'
        }
        Register-AuditCheck -CheckId 'B1-LINE' -Category 'Azure' -Service 'Storage' -Name 'line check' -Function 'Test-B1Line' -Phase 'PerSubscription'
        $script:State.Config.Quiet = $false
        Mock Write-UiHost {}
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        # The line is emitted in segments (domain header, name, human status
        # label, summary, muted CheckId); assert the logical pieces across the
        # segment calls. No raw internal status tokens and no [NN/TT] counter.
        Assert-MockCalled Write-UiHost -Times 1 -Exactly -ParameterFilter { "$Text" -match '^Storage$' }
        Assert-MockCalled Write-UiHost -Times 1 -Exactly -ParameterFilter { "$Text" -match '^  line check\s+$' }
        Assert-MockCalled Write-UiHost -Times 1 -Exactly -ParameterFilter { "$Text" -match '^Clean\s+$' }
        Assert-MockCalled Write-UiHost -Times 1 -Exactly -ParameterFilter { "$Text" -match '0 risky' }
        Assert-MockCalled Write-UiHost -Times 1 -Exactly -ParameterFilter { "$Text" -match '^\s*B1-LINE$' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match '^\[\d{2}/\d{2}\]' }
    }

    It "legacy FAIL without explicit summary gets an affected-count summary" {
        function global:Test-B1Legacy {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'risky legacy' -Count 2 -Service 'Storage' -CheckId 'B1-LEG'
        }
        Register-AuditCheck -CheckId 'B1-LEG' -Category 'Azure' -Service 'Storage' -Name 'legacy fail' -Function 'Test-B1Legacy' -Phase 'PerSubscription'
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'B1-LEG' })[0]
        $rec.Status | Should -Be 'Fail'
        $rec.SummaryText | Should -Be '2 affected'
    }
}

Describe "Write-Finding - finding-block console dedupe" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        # Finding blocks are strictly opt-in (Phase B3 hardening): -ShowFindings
        # enables them; the dedupe contract is exercised under that flag.
        $script:State.Config.ShowFindings = $true
    }

    It "identical finding blocks print once plus one suppression note; all records kept" {
        Mock Write-Host {}
        1..3 | ForEach-Object {
            Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'same noisy finding' -Count 1 -Service 'Storage' -CheckId 'B1-DUP'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Finding: same noisy finding' }
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Identical finding repeated' }
        # exports keep every record - only console rendering is deduped
        @($script:State.Results | Where-Object { $_.CheckId -eq 'B1-DUP' }).Count | Should -Be 3
    }

    It "distinct findings are not deduped" {
        Mock Write-Host {}
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'finding A' -Count 1 -Service 'Storage' -CheckId 'B1-DUP'
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'finding B' -Count 1 -Service 'Storage' -CheckId 'B1-DUP'
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Finding: finding A' }
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Finding: finding B' }
    }
}

Describe "Get-RunDiagnostics - Partial tally" {
    It "counts Partial execution records" {
        $script:State = Initialize-AuditState
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId='P-1'; Status='Partial' })
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId='P-2'; Status='Pass' })
        $d = Get-RunDiagnostics
        $d.Partial | Should -Be 1
        $d.Passed  | Should -Be 1
    }
}

Describe "Exports preserve explicit status and coverage" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true

        Write-Finding -Severity 'HIGH' -Status 'PARTIAL' -Message 'partial storage run' -Count 0 -Service 'Storage' -CheckId 'B1-EXP' `
            -DiscoveredResourceCount 5 -EvaluatedResourceCount 3 -FailedCollectionCount 1 `
            -CollectionStatus 'Partial' -PartialEvaluation $true -CoverageSummary '3 of 5 evaluated' `
            -SummaryText '3 of 5 evaluated'
        Write-Finding -Severity 'CRITICAL' -Status 'FAIL' -Message 'risky thing' -Count 2 `
            -Data @([PSCustomObject]@{ Name = 'res1' }, [PSCustomObject]@{ Name = 'res2' }) -Service 'Storage' -CheckId 'B1-EXP2'

        $check = [PSCustomObject]@{ CheckId = 'B1-EXP'; Name = 'partial storage'; Category = 'Azure'; Service = 'Storage'; Phase = 'PerSubscription' }
        $rec = New-CheckExecutionRecord -Check $check
        $rec.Status = 'Partial'
        $rec.CompletedAt = Get-Date
        $rec.Coverage = Get-CheckCoverage -Findings @($script:State.Results[0])
        $rec.SummaryText = '3 of 5 evaluated'
        $script:State.ExecutedChecks.Add($rec)
    }

    It "summary CSV carries CheckId and coverage columns" {
        $base = Join-Path $TestDrive 'rep'
        Export-ResultsCsv -Results $script:State.Results -BaseName $base | Out-Null
        $header = (Get-Content "$base.csv" -TotalCount 1)
        $header | Should -Match 'CheckId'
        $header | Should -Match 'DiscoveredResourceCount'
        $header | Should -Match 'EvaluatedResourceCount'
        $header | Should -Match 'FailedCollectionCount'
        $header | Should -Match 'CompleteEvaluation'
        $header | Should -Match 'CoverageSummary'
    }

    It "detailed CSV carries the finding status" {
        $base = Join-Path $TestDrive 'repdet'
        Export-ResultsCsv -Results $script:State.Results -BaseName $base | Out-Null
        $header = (Get-Content "$base-Detailed.csv" -TotalCount 1)
        $header | Should -Match 'FindingStatus'
        $header | Should -Match 'FindingCheckId'
    }

    It "JSON findings carry coverage fields and the summary has ChecksPartial" {
        $base = Join-Path $TestDrive 'repjson'
        Export-ResultsJson -Results $script:State.Results -BaseName $base | Out-Null
        $json = Get-Content "$base.json" -Raw | ConvertFrom-Json
        $json.Summary.PSObject.Properties.Name | Should -Contain 'ChecksPartial'
        $f = @($json.Findings | Where-Object { $_.CheckId -eq 'B1-EXP' })[0]
        "$($f.Status)" | Should -Be 'PARTIAL'
        [int]$f.EvaluatedResourceCount | Should -Be 3
        $f.PartialEvaluation | Should -BeTrue
    }

    It "HTML preserves explicit NOTEVALUATED (never recomputed to PASS) and shows check coverage" {
        Write-Finding -Severity 'HIGH' -Status 'NOTEVALUATED' -Message 'could not evaluate' -Count 0 -Service 'Storage' -CheckId 'B1-NE'
        $out = Join-Path $TestDrive 'rep.html'
        Export-ResultsHtml -Results $script:State.Results -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match 'NOTEVALUATED'
        $html | Should -Match 'Check Coverage'
        $html | Should -Match 'B1-EXP'
        # The partial check line must show PARTIAL, not a recomputed PASS
        $html | Should -Match 'PARTIAL'
    }

    It "HTML report has the required sections, is self-contained, and shows affected components" {
        Write-Finding -Severity 'CRITICAL' -Status 'FAIL' -Message 'risky storage account' -Count 1 `
                      -Service 'Storage' -CheckId 'B1-COMP' `
                      -Data ([PSCustomObject]@{ StorageAccountName = 'st-demo-01'; ResourceGroup = 'rg-demo'; Issue = 'public access' }) `
                      -Remediation 'Fix it' -DataPlaneRequired $true
        $out = Join-Path $TestDrive 'full.html'
        Export-ResultsHtml -Results $script:State.Results -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw

        # required sections
        $html | Should -Match 'Executive Summary'
        $html | Should -Match 'Coverage Summary'
        $html | Should -Match 'Findings Overview'
        $html | Should -Match 'Affected Components'
        $html | Should -Match 'Per-Check Detail'
        $html | Should -Match 'Not Evaluated / Partial / Errors'

        # self-contained: embedded CSS, dark-mode support, no external refs
        # (a minimal inline <script> for the findings filter is allowed; no external loads)
        $html | Should -Match 'prefers-color-scheme'
        $html | Should -Not -Match 'src\s*=\s*"http'
        $html | Should -Not -Match 'href\s*=\s*"http'

        # BAAS house style: branding and filter UI present
        $html | Should -Match 'Created by BAAS'
        $html | Should -Match '0xbaas.com'
        $html | Should -Match 'Built by <span class="brand">BAAS</span>'
        $html | Should -Match 'filterbar'

        # affected component evidence rendered in a table
        $html | Should -Match 'st-demo-01'
        $html | Should -Match 'rg-demo'
        # data-plane badge visible
        $html | Should -Match 'data-plane required'
    }
}


Describe "Show-AuditSummary - default export path includes HTML" {
    It "default ExportFormats emit CSV + JSON + HTML and the HTML file is created" {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:State.Timestamp = '20990101-000000'
        # product default: HTML ships alongside CSV/JSON unless explicitly disabled
        $script:State.Config.ExportFormats | Should -Contain 'HTML'

        Write-Finding -Severity 'HIGH' -Status 'FAIL' -Message 'export-path finding' -Count 1 -Service 'Storage' -CheckId 'B1-SUM'

        Push-Location $TestDrive
        try {
            Show-AuditSummary
            Test-Path "AzureSecurityAudit-20990101-000000.csv"  | Should -BeTrue
            Test-Path "AzureSecurityAudit-20990101-000000.json" | Should -BeTrue
            Test-Path "AzureSecurityAudit-20990101-000000.html" | Should -BeTrue
            $html = Get-Content "AzureSecurityAudit-20990101-000000.html" -Raw
            $html | Should -Match 'B1-SUM'
            $html | Should -Match 'Executive Summary'
        } finally {
            Pop-Location
        }
    }
}
