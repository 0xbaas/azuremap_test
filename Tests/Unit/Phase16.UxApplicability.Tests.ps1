#==============================================================================
# AzureMap v2 - Tests/Unit/Phase16.UxApplicability.Tests.ps1
# Product UX phase: environment footprint, check applicability (NOTAPPLICABLE),
# per-check error summarization, NoColor output, severity calibration fields.
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
    . "$projectRoot\Export\Csv.ps1"
    . "$projectRoot\Export\Json.ps1"
    . "$projectRoot\Export\Html.ps1"

    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }
    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }

    function script:New-Footprint {
        param([hashtable]$TypeCounts)
        [PSCustomObject]@{
            Subscriptions = 2; ResourceGroups = 4; Resources = 10
            ResourceTypeCount = $TypeCounts.Count; RegionCount = 1; Regions = @('westeurope')
            TopTypes = @($TypeCounts.GetEnumerator() | ForEach-Object {
                [PSCustomObject]@{ Type = $_.Key; Label = ($_.Key -split '/')[-1]; Count = $_.Value }
            })
            TypeCounts = $TypeCounts; Source = 'ResourceGraph'
            SubscriptionsExpected = 2; SubscriptionsCovered = 2
            CoverageStatus = 'Complete'; Confidence = 'High'; Note = ''
        }
    }
}

Describe "Get-EnvironmentFootprint" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
    }

    It "builds a footprint from Resource Graph results" {
        function global:Search-AzGraph {
            param([string]$Query, [string[]]$Subscription, [Parameter(ValueFromRemainingArguments)]$r)
            if ($Query -match 'summarize Count=count\(\) by type') {
                return @(
                    [PSCustomObject]@{ type = 'microsoft.storage/storageaccounts'; Count = 60 },
                    [PSCustomObject]@{ type = 'microsoft.keyvault/vaults'; Count = 41 }
                )
            }
            if ($Query -match 'by location') { return @([PSCustomObject]@{ location = 'westeurope'; Count = 101 }) }
            if ($Query -match 'project subscriptionId') { return @($Subscription | ForEach-Object { [PSCustomObject]@{ subscriptionId = $_ } }) }
            if ($Query -match 'ResourceContainers') { return @([PSCustomObject]@{ Count = 12 }) }
            return @()
        }
        try {
            $fp = Get-EnvironmentFootprint -Subscriptions @([PSCustomObject]@{ Id = 'S1'; Name = 'sub1' })
            $fp.Source | Should -Be 'ResourceGraph'
            $fp.Resources | Should -Be 101
            $fp.TypeCounts['microsoft.storage/storageaccounts'] | Should -Be 60
            $fp.ResourceGroups | Should -Be 12
            $fp.Regions | Should -Contain 'westeurope'
        } finally {
            Remove-Item function:global:Search-AzGraph -ErrorAction SilentlyContinue
        }
    }

    It "falls back to Get-AzResource when ARG is unavailable" {
        function global:Search-AzGraph { param([Parameter(ValueFromRemainingArguments)]$r) throw 'arg unavailable' }
        function global:Get-AzResource {
            @([PSCustomObject]@{ ResourceType = 'Microsoft.Storage/storageAccounts'; Location = 'westeurope'; ResourceGroupName = 'rg1' })
        }
        try {
            $fp = Get-EnvironmentFootprint -Subscriptions @([PSCustomObject]@{ Id = 'S1'; Name = 'sub1' })
            $fp.Source | Should -Be 'Get-AzResource'
            $fp.Resources | Should -Be 1
            $fp.TypeCounts['microsoft.storage/storageaccounts'] | Should -Be 1
            $fp.ResourceGroups | Should -Be 1
        } finally {
            Remove-Item function:global:Search-AzGraph -ErrorAction SilentlyContinue
            Remove-Item function:global:Get-AzResource -ErrorAction SilentlyContinue
        }
    }

    It "never throws when everything fails; Source = Unavailable" {
        function global:Search-AzGraph { param([Parameter(ValueFromRemainingArguments)]$r) throw 'arg unavailable' }
        function global:Get-AzResource { throw 'denied' }
        try {
            $fp = Get-EnvironmentFootprint -Subscriptions @([PSCustomObject]@{ Id = 'S1'; Name = 'sub1' })
            $fp.Source | Should -Be 'Unavailable'
        } finally {
            Remove-Item function:global:Search-AzGraph -ErrorAction SilentlyContinue
            Remove-Item function:global:Get-AzResource -ErrorAction SilentlyContinue
        }
    }
}

Describe "Get-CheckApplicability" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
    }

    It "marks a check NotApplicable when its resource types are absent from the footprint" {
        $script:State.Footprint = script:New-Footprint -TypeCounts @{ 'microsoft.storage/storageaccounts' = 60 }
        $check = [PSCustomObject]@{ CheckId = 'MESSAGING-003'; RequiredResourceTypes = @('Microsoft.ApiManagement/service'); AlwaysRun = $false }
        $a = Get-CheckApplicability -Check $check
        $a.Applicable | Should -BeFalse
        $a.Reason | Should -Match 'service'
    }

    It "keeps checks applicable when the footprint contains the type (case-insensitive)" {
        $script:State.Footprint = script:New-Footprint -TypeCounts @{ 'microsoft.storage/storageaccounts' = 60 }
        $check = [PSCustomObject]@{ CheckId = 'STORAGE-001'; RequiredResourceTypes = @('Microsoft.Storage/storageAccounts'); AlwaysRun = $false }
        (Get-CheckApplicability -Check $check).Applicable | Should -BeTrue
    }

    It "never marks NotApplicable when the footprint is unavailable (unknown != empty)" {
        $script:State.Footprint = $null
        $check = [PSCustomObject]@{ CheckId = 'SQL-001'; RequiredResourceTypes = @('Microsoft.Sql/servers'); AlwaysRun = $false }
        (Get-CheckApplicability -Check $check).Applicable | Should -BeTrue
    }

    It "AlwaysRun checks are applicable regardless of footprint" {
        $script:State.Footprint = script:New-Footprint -TypeCounts @{}
        $check = [PSCustomObject]@{ CheckId = 'AZURE-GOV-001'; RequiredResourceTypes = @(); AlwaysRun = $true }
        (Get-CheckApplicability -Check $check).Applicable | Should -BeTrue
    }
}

Describe "Invoke-AuditChecks - applicability gate" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:FxSub = [PSCustomObject]@{ Id = 'S1'; Name = 'n1'; TenantId = 'T1' }
    }

    It "a check whose resource types are absent is NotApplicable and its function never runs" {
        $script:State.Footprint = script:New-Footprint -TypeCounts @{ 'microsoft.storage/storageaccounts' = 5 }
        $global:ApimRan = $false
        function global:Test-ApimUx { param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0) $global:ApimRan = $true }
        Register-AuditCheck -CheckId 'UX-APIM' -Category 'Azure' -Service 'APIM' -Name 'apim' -Function 'Test-ApimUx' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('Microsoft.ApiManagement/service')
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'UX-APIM' })[0]
        $rec.Status | Should -Be 'NotApplicable'
        $rec.Detail | Should -Match 'No .* in scope'
        $global:ApimRan | Should -BeFalse
    }

    It "applicable checks still run and report normally" {
        $script:State.Footprint = script:New-Footprint -TypeCounts @{ 'microsoft.storage/storageaccounts' = 5 }
        function global:Test-StorageUx {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            Write-Finding -Severity 'HIGH' -Status 'PASS' -Message 'clean' -Count 0 -Service 'Storage' -CheckId 'UX-STOR' `
                -EvaluatedResourceCount 5 -CompleteEvaluation $true -CollectionStatus 'Complete' `
                -SummaryText '5 storage accounts evaluated; 0 risky; coverage complete.'
        }
        Register-AuditCheck -CheckId 'UX-STOR' -Category 'Azure' -Service 'Storage' -Name 'stor' -Function 'Test-StorageUx' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('Microsoft.Storage/storageAccounts')
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'UX-STOR' })[0]
        $rec.Status | Should -Be 'Pass'
    }

    It "summarizes repeated per-check errors into bucketed entries" {
        function global:Test-NoisyUx {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            foreach ($s in @('sub-a', 'sub-b', 'sub-c')) {
                Write-AuditLog -Message "Failed to check widget security in subscription ${s}: boom" -Level WARN
            }
            Write-Finding -Severity 'HIGH' -Status 'NOTEVALUATED' -Message 'widget check failed' -Count 0 -Service 'APIM' -CheckId 'UX-NOISY'
        }
        $script:State.Subscriptions = @([PSCustomObject]@{ Id = 'a'; Name = 'sub-a' }, [PSCustomObject]@{ Id = 'b'; Name = 'sub-b' }, [PSCustomObject]@{ Id = 'c'; Name = 'sub-c' })
        Register-AuditCheck -CheckId 'UX-NOISY' -Category 'Azure' -Service 'APIM' -Name 'noisy' -Function 'Test-NoisyUx' -Phase 'PerSubscription'
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @($script:FxSub) -Exclusions @{} -Services @('All')
        # three subscription-specific messages collapse into one bucketed entry
        $bucket = $script:State.CheckErrors['UX-NOISY']
        @($bucket.Keys).Count | Should -Be 1
        [int]$bucket[@($bucket.Keys)[0]] | Should -Be 3
        # and every original line is still in the log buffer
        @($script:State.LogBuffer | Where-Object { $_ -match 'Failed to check widget security' }).Count | Should -Be 3
    }
}

Describe "NOTAPPLICABLE status model" {

    It "Resolve-CheckStatus maps an explicit NOTAPPLICABLE record to NotApplicable" {
        $script:State = Initialize-AuditState
        $f = Write-Finding -Severity 'INFO' -Status 'NOTAPPLICABLE' -Message 'no widgets in scope' -Count 0 -Service 'APIM' -CheckId 'UX-NA'
        # Write-Finding returns nothing; read from Results
        $rec = @($script:State.Results | Where-Object { $_.CheckId -eq 'UX-NA' })
        Resolve-CheckStatus -ProducedFindings $rec | Should -Be 'NotApplicable'
    }

    It "IsInventoryOnly records never fail a check (and never show plain PASS)" {
        $script:State = Initialize-AuditState
        Write-Finding -Severity 'INFO' -Status 'PASS' -Message 'public ip inventory' -Count 7 -Service 'PublicIP' -CheckId 'UX-INV' -IsInventoryOnly $true
        $rec = @($script:State.Results | Where-Object { $_.CheckId -eq 'UX-INV' })
        # Phase 18: inventory-only output resolves to the INVENTORY display state,
        # not Fail (no risk proven) and not plain Pass (records were produced).
        Resolve-CheckStatus -ProducedFindings $rec | Should -Be 'Inventory'
    }

    It "Get-RunDiagnostics tallies NotApplicable" {
        $script:State = Initialize-AuditState
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId = 'N-1'; Status = 'NotApplicable' })
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId = 'N-2'; Status = 'Pass' })
        $d = Get-RunDiagnostics
        $d.NotApplicable | Should -Be 1
        $d.Passed | Should -Be 1
    }

    It "HTML renders explicit NotApplicable as N/A and JSON tallies it" {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $check = [PSCustomObject]@{ CheckId = 'UX-NA2'; Name = 'apim'; Category = 'Azure'; Service = 'APIM'; Phase = 'PerSubscription' }
        $rec = New-CheckExecutionRecord -Check $check
        $rec.Status = 'NotApplicable'
        $rec.Detail = 'No service resources in scope (footprint: ResourceGraph)'
        $rec.CompletedAt = Get-Date
        $script:State.ExecutedChecks.Add($rec)

        $out = Join-Path $TestDrive 'na.html'
        Export-ResultsHtml -Results @() -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match '>N/A</span>'
        $html | Should -Match 'No service resources in scope'

        $base = Join-Path $TestDrive 'najson'
        Export-ResultsJson -Results @() -BaseName $base | Out-Null
        $json = Get-Content "$base.json" -Raw | ConvertFrom-Json
        [int]$json.Summary.ChecksNotApplicable | Should -Be 1
    }
}

Describe "Banner and NoColor" {

    BeforeEach {
        $script:State = Initialize-AuditState
    }

    It "banner shows branding and version" {
        $script:State.Config.Quiet = $false
        Mock Write-UiHost {}
        Show-Banner -SeverityLevel 'All' -Services @('All')
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'AZUREMAP V' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '0xbaas.com' }
    }

    It "Write-UiHost omits color when Config.NoColor is set" {
        $script:State.Config.NoColor = $true
        Mock Write-Host {}
        Write-UiHost -Text 'plain' -Color 'Red'
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { -not $PSBoundParameters.ContainsKey('ForegroundColor') -and "$Object" -eq 'plain' }
    }

    It "Write-UiHost passes color when colors are enabled" {
        $script:State.Config.NoColor = $false
        if ($env:NO_COLOR) { $env:NO_COLOR = $null }
        Mock Write-Host {}
        Write-UiHost -Text 'colored' -Color 'Red'
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { $ForegroundColor -eq 'Red' }
    }

    It "NO_COLOR env var disables color" {
        $script:State.Config.NoColor = $false
        $env:NO_COLOR = '1'
        try {
            Mock Write-Host {}
            Write-UiHost -Text 'plain2' -Color 'Red'
            Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { -not $PSBoundParameters.ContainsKey('ForegroundColor') }
        } finally {
            Remove-Item env:NO_COLOR -ErrorAction SilentlyContinue
        }
    }
}

Describe "Run summary shows footprint and applicability" {

    It "HTML includes the Environment Footprint section when footprint exists" {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:State.Footprint = script:New-Footprint -TypeCounts @{ 'microsoft.storage/storageaccounts' = 60 }
        $out = Join-Path $TestDrive 'fp.html'
        Export-ResultsHtml -Results @() -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match 'Environment Footprint'
        $html | Should -Match 'storageaccounts'
        $html | Should -Match 'Top services'
    }

    It "Show-AuditConsole prints duration, scope, status totals and coverage lines" {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.Footprint = script:New-Footprint -TypeCounts @{ 'microsoft.storage/storageaccounts' = 60 }
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId = 'S-1'; Name = 'x'; Status = 'Pass' })
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId = 'S-2'; Name = 'y'; Status = 'NotApplicable'; Detail = 'no resources' })
        Mock Write-UiHost {}
        Show-AuditConsole -ExportedFiles @('x.csv')
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'Clean\s+1' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'Not in scope\s+1' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'Resources\s+10' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'Duration\s+\d' }
    }
}
