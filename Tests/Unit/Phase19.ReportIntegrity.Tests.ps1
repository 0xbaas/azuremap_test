#==============================================================================
# AzureMap v2 - Tests/Unit/Phase19.ReportIntegrity.Tests.ps1
# Report integrity round:
#   * STORAGE-005 summary counts UNIQUE risky accounts + separate risk signals
#     (never "92 of 60 storage accounts risky").
#   * Findings Overview / Affected Components aggregate per-subscription records
#     into one row/section per finding group.
#   * Coverage headline shows structured counts (coverage-aware/complete/partial/
#     legacy), not a bare percentage.
#   * Low-confidence footprint -> prominent warning banner in HTML.
#   * -RedactSensitive masks emails/GUIDs (and IPs with -RedactPublicIps) in
#     HTML/JSON/CSV exports.
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
    . "$projectRoot\Core\Footprint.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Core\Console.ps1"
    . "$projectRoot\Export\Csv.ps1"
    . "$projectRoot\Export\Json.ps1"
    . "$projectRoot\Export\Html.ps1"
    . "$projectRoot\Checks\Azure\Storage.ps1"

    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }
    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }
    function global:Get-AzStorageAccount {
        param([switch]$IncludeAccountSASPolicy, [Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxAccountsThrow) { throw "403 AuthorizationFailed" }
        $global:FxAccounts
    }
    function global:Get-AzStorageAccountNetworkRuleSet { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxNet }

    function script:Get-Res {
        param([string]$CheckId)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ($item.CheckId -eq $CheckId) { $items += $item }
        }
        return ,$items
    }

    function script:New-ExposureRecord {
        param([string]$SubName, [int]$Count)
        [PSCustomObject]@{
            CheckId = 'AZURE-EXPOSURE-001'; Service = 'Exposure'; Severity = 'INFO'; Status = 'PASS'
            Finding = 'Central public exposure inventory'; Count = $Count
            SubscriptionName = $SubName; SubscriptionId = $SubName
            Confidence = 'Medium'; FindingType = 'Inventory'; IsInventoryOnly = $true
            SummaryText = 'inventory'; CoverageSummary = ''
            CompleteEvaluation = $true; PartialEvaluation = $false
            DataPlaneRequired = $false; ManualValidationRequired = $false
            Remediation = 'review'
            Evidence = @([PSCustomObject]@{ ResourceName = "res-$SubName"; ResourceGroup = 'rg'; Reason = 'public' })
        }
    }
}

Describe "STORAGE-005 unique accounts vs risk signals" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:StorageSasPolicySupported = $true
        $global:FxNet = $null
        $global:FxAccountsThrow = $false
        # Two accounts, each hitting TWO buckets (critical combo + cross-tenant):
        # 4 signals across 2 unique accounts.
        $global:FxAccounts = @(
            [PSCustomObject]@{ StorageAccountName = 'sa1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/rg1/sa1'; AllowCrossTenantReplication = $true },
            [PSCustomObject]@{ StorageAccountName = 'sa2'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/rg1/sa2'; AllowCrossTenantReplication = $true }
        )
    }

    It "summary reports unique accounts and signal breakdown, never 'N of M' with N > M" {
        $sub = [PSCustomObject]@{ Id = 'S1'; Name = 'sub1'; TenantId = 'T1' }
        Test-StorageExfiltrationVectors -Subscriptions @($sub) -Exclusions @{}
        $all = (script:Get-Res -CheckId 'STORAGE-005')
        $withSummary = @($all | Where-Object { ($_.PSObject.Properties.Name -contains 'SummaryText') -and $_.SummaryText })
        $withSummary.Count | Should -BeGreaterThan 0
        foreach ($r in $withSummary) {
            "$($r.SummaryText)" | Should -Not -Match '4 of 2'
        }
        $main = $withSummary[0]
        "$($main.SummaryText)" | Should -Match '2 storage accounts evaluated'
        "$($main.SummaryText)" | Should -Match '4 risk signals found'
        "$($main.SummaryText)" | Should -Match '2 critical combinations'
        "$($main.SummaryText)" | Should -Match '2 SAS/cross-tenant risks'
        "$($main.SummaryText)" | Should -Match '2 unique account'
    }
}

Describe "Findings aggregation (Group-HtmlFindings)" {

    It "groups identical per-subscription records into one row" {
        $recs = @((script:New-ExposureRecord 'sub-a' 10), (script:New-ExposureRecord 'sub-b' 20), (script:New-ExposureRecord 'sub-c' 40))
        $g = @(Group-HtmlFindings -Findings $recs)
        $g.Count | Should -Be 1
        $g[0].Count | Should -Be 70
        $g[0].SubscriptionSpan | Should -Be 3
        $g[0].RecordCount | Should -Be 3
        @($g[0].Evidence).Count | Should -Be 3
    }

    It "does not merge distinct findings and ignores the 'Multiple' marker for span" {
        $a = script:New-ExposureRecord 'sub-a' 5
        $b = script:New-ExposureRecord 'Multiple' 5
        $c = script:New-ExposureRecord 'sub-a' 5; $c.Finding = 'Other finding'
        $g = @(Group-HtmlFindings -Findings @($a, $b, $c))
        $g.Count | Should -Be 2
        $exp = @($g | Where-Object { $_.Finding -eq 'Central public exposure inventory' })[0]
        $exp.SubscriptionSpan | Should -Be 1
        $exp.Count | Should -Be 10
    }

    It "any partial record makes the group partial" {
        $a = script:New-ExposureRecord 'sub-a' 5
        $b = script:New-ExposureRecord 'sub-b' 5
        $b.PartialEvaluation = $true; $b.CompleteEvaluation = $false
        $g = @(Group-HtmlFindings -Findings @($a, $b))
        $g[0].PartialEvaluation | Should -BeTrue
        $g[0].CompleteEvaluation | Should -BeFalse
    }
}

Describe "HTML report structure" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
    }

    It "Findings Overview shows one aggregated row with subscription span" {
        $recs = @((script:New-ExposureRecord 'sub-a' 10), (script:New-ExposureRecord 'sub-b' 20), (script:New-ExposureRecord 'sub-c' 40))
        $out = Join-Path $TestDrive 'agg.html'
        Export-ResultsHtml -Results $recs -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match 'across 3 subscriptions'
        # one aggregated overview row, not one per subscription
        ([regex]::Matches($html, 'data-sev="INFO"')).Count | Should -Be 1
        $html | Should -Match 'Full per-subscription detail in the CSV/JSON exports'
    }

    It "coverage headline uses structured counts, not a bare percentage" {
        $out = Join-Path $TestDrive 'cov.html'
        Export-ResultsHtml -Results @() -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match 'Coverage-aware Checks'
        $html | Should -Match 'Legacy Checks \(no coverage data\)'
        $html | Should -Match 'Coverage-aware checks complete'
    }

    It "low-confidence footprint renders a warning banner" {
        $script:State.Footprint = [PSCustomObject]@{
            Subscriptions = 49; ResourceGroups = 1; Resources = 80; ResourceTypeCount = 1
            RegionCount = 1; Regions = @('westeurope'); TopTypes = @(); TypeCounts = @{}
            Source = 'ResourceGraph'; SubscriptionsExpected = 49; SubscriptionsCovered = 1
            CoverageStatus = 'Partial'; Confidence = 'Low'; Note = 'partial coverage note'
        }
        $out = Join-Path $TestDrive 'warn.html'
        Export-ResultsHtml -Results @() -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match 'Environment footprint incomplete'
        $html | Should -Match 'warn-banner'
        $html | Should -Match 'partial coverage note'
    }

    It "high-confidence footprint renders no warning banner" {
        $script:State.Footprint = [PSCustomObject]@{
            Subscriptions = 3; ResourceGroups = 4; Resources = 100; ResourceTypeCount = 5
            RegionCount = 1; Regions = @('westeurope'); TopTypes = @(); TypeCounts = @{}
            Source = 'ResourceGraph'; SubscriptionsExpected = 3; SubscriptionsCovered = 3
            CoverageStatus = 'Complete'; Confidence = 'High'; Note = ''
        }
        $out = Join-Path $TestDrive 'ok.html'
        Export-ResultsHtml -Results @() -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Not -Match 'Environment footprint incomplete'
    }
}

Describe "Redaction (-RedactSensitive)" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
    }

    It "masks emails and GUIDs when enabled" {
        $script:State.Config.RedactSensitive = $true
        $t = Protect-SensitiveText -Text 'owner admin@contoso.com sub 11111111-2222-3333-4444-555555555555'
        $t | Should -Not -Match 'admin@contoso.com'
        $t | Should -Not -Match '11111111-2222'
        $t | Should -Match '\*\*\*@\*\*\*'
    }

    It "is a no-op when disabled" {
        $script:State.Config.RedactSensitive = $false
        $t = Protect-SensitiveText -Text 'admin@contoso.com 11111111-2222-3333-4444-555555555555'
        $t | Should -Match 'admin@contoso.com'
        $t | Should -Match '11111111-2222'
    }

    It "masks IPv4 only with -RedactPublicIps" {
        $script:State.Config.RedactSensitive = $true
        $script:State.Config.RedactPublicIps = $false
        (Protect-SensitiveText -Text 'ip 20.30.40.50 open') | Should -Match '20\.30\.40\.50'
        $script:State.Config.RedactPublicIps = $true
        (Protect-SensitiveText -Text 'ip 20.30.40.50 open') | Should -Match 'x\.x\.x\.x'
    }

    It "redacts evidence inside the HTML export" {
        $script:State.Config.RedactSensitive = $true
        $r = script:New-ExposureRecord 'sub-a' 1
        $r.Evidence = @([PSCustomObject]@{ ResourceName = 'res'; Owner = 'admin@contoso.com'; ResourceId = '/subscriptions/11111111-2222-3333-4444-555555555555/rg/x' })
        $out = Join-Path $TestDrive 'red.html'
        Export-ResultsHtml -Results @($r) -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Not -Match 'admin@contoso\.com'
        $html | Should -Not -Match '11111111-2222'
    }

    It "redacts the JSON export" {
        $script:State.Config.RedactSensitive = $true
        $r = script:New-ExposureRecord 'sub-a' 1
        $r.Remediation = 'contact admin@contoso.com about 11111111-2222-3333-4444-555555555555'
        $base = Join-Path $TestDrive 'redjson'
        Export-ResultsJson -Results @($r) -BaseName $base | Out-Null
        $json = Get-Content "$base.json" -Raw
        $json | Should -Not -Match 'admin@contoso\.com'
        $json | Should -Not -Match '11111111-2222'
        # still valid JSON
        { $json | ConvertFrom-Json | Out-Null } | Should -Not -Throw
    }

    It "redacts both CSV exports" {
        $script:State.Config.RedactSensitive = $true
        $r = script:New-ExposureRecord 'sub-a' 1
        $r.Remediation = 'contact admin@contoso.com'
        $base = Join-Path $TestDrive 'redcsv'
        Export-ResultsCsv -Results @($r) -BaseName $base | Out-Null
        $csv = Get-Content "$base.csv" -Raw
        $csv | Should -Not -Match 'admin@contoso\.com'
        if (Test-Path "$base-Detailed.csv") {
            (Get-Content "$base-Detailed.csv" -Raw) | Should -Not -Match 'admin@contoso\.com'
        }
    }
}
