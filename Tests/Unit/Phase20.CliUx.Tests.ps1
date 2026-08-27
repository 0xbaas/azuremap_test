#==============================================================================
# AzureMap v2 - Tests/Unit/Phase20.CliUx.Tests.ps1
# Human CLI output pass: display status labels vs internal statuses, curated
# display names, domain-grouped per-check lines, log-file-only raw errors,
# mode-skip wording (-SkipEntra -> Skipped), footprint discovery wording,
# assessment plan, CVSS-like severity colors.
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
    . "$projectRoot\Core\Azure\Rbac.ps1"
    . "$projectRoot\Core\Console.ps1"

    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }
    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }

    function script:New-FxSub {
        [PSCustomObject]@{ Id = 'sub-1'; Name = 'fx-sub'; TenantId = 't-1'; SubscriptionId = 'sub-1' }
    }
}

Describe "Get-StatusDisplayInfo - human display labels" {

    It "maps every internal status to its human CLI label" {
        (Get-StatusDisplayInfo -Status 'Pass').Label          | Should -Be 'Clean'
        (Get-StatusDisplayInfo -Status 'Fail').Label          | Should -Be 'Needs review'
        (Get-StatusDisplayInfo -Status 'Warning').Label       | Should -Be 'Needs review'
        (Get-StatusDisplayInfo -Status 'Partial').Label       | Should -Be 'Partially checked'
        (Get-StatusDisplayInfo -Status 'NotEvaluated').Label  | Should -Be 'Could not check'
        (Get-StatusDisplayInfo -Status 'NotApplicable').Label | Should -Be 'Not in scope'
        (Get-StatusDisplayInfo -Status 'Skipped').Label       | Should -Be 'Skipped'
        (Get-StatusDisplayInfo -Status 'Error').Label         | Should -Be 'Tool error'
        (Get-StatusDisplayInfo -Status 'Inventory').Label     | Should -Be 'Inventory'
    }

    It "derives the Needs review color from severity (CVSS-like ramp)" {
        (Get-StatusDisplayInfo -Status 'Fail' -Severity 'CRITICAL').Color | Should -Be 'CritRed'
        (Get-StatusDisplayInfo -Status 'Fail' -Severity 'HIGH').Color     | Should -Be 'DarkYellow'
        (Get-StatusDisplayInfo -Status 'Fail' -Severity 'MEDIUM').Color   | Should -Be 'Yellow'
        (Get-StatusDisplayInfo -Status 'Fail' -Severity 'LOW').Color      | Should -Be 'LightGreen'
        (Get-StatusDisplayInfo -Status 'Fail' -Severity 'INFO').Color     | Should -Be 'Cyan'
        (Get-StatusDisplayInfo -Status 'Fail').Color                      | Should -Be 'DarkYellow'
    }

    It "uses distinct palette entries for LOW, MEDIUM and the section accent" {
        # LOW light green (#9BE7A1), MEDIUM yellow (#D6A84B), section accent cyan (#38A8DC).
        $script:BaasAnsiColors['LightGreen'] | Should -Be '155;231;161'
        $script:BaasAnsiColors['CritRed']    | Should -Be '240;82;82'
        $script:BaasAnsiColors['LightGreen'] | Should -Not -Be $script:BaasAnsiColors['Cyan']
        $script:BaasAnsiColors['Yellow']     | Should -Not -Be $script:BaasAnsiColors['Cyan']
        # Console fallbacks for non-ConsoleColor palette names are valid.
        [Enum]::GetNames([System.ConsoleColor]) | Should -Contain $script:BaasConsoleFallback['LightGreen']
        [Enum]::GetNames([System.ConsoleColor]) | Should -Contain $script:BaasConsoleFallback['CritRed']
    }
}

Describe "Get-CheckDisplayName / Get-CheckDomain" {

    It "uses curated display names for known checks" {
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'STORAGE-001'; Name = 'Shared Key Authentication' }))  | Should -Be 'Shared key authentication'
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'AZURE-GOV-001'; Name = 'Defender for Cloud & Policy Coverage' })) | Should -Be 'Defender for Cloud coverage'
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'IDENTITY-003'; Name = 'Excessive RBAC Privileges' })) | Should -Be 'Privileged RBAC assignments'
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'KEYVAULT-003'; Name = 'Key Vault Secrets Expiry' }))  | Should -Be 'Secret expiration hygiene'
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'MESSAGING-003'; Name = 'API Management Security' }))  | Should -Be 'API Management exposure'
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'NETWORK-001'; Name = 'NSG Permissive Rules' }))       | Should -Be 'Sensitive inbound exposure'
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'ENTRA-07'; Name = 'Test-EntraAppCredentialHygiene' })) | Should -Be 'App credential hygiene'
    }

    It "de-camelcases unmapped Test-* function names as fallback" {
        (Get-CheckDisplayName -Check ([PSCustomObject]@{ CheckId = 'ENTRA-99'; Name = 'Test-EntraSomethingNew' })) | Should -Be 'Entra Something New'
    }

    It "no curated display name is truncated with an ellipsis" {
        foreach ($k in $script:CheckDisplayNames.Keys) {
            $script:CheckDisplayNames[$k] | Should -Not -Match '\.\.\.'
            $script:CheckDisplayNames[$k].Length | Should -BeLessThan 40
        }
    }

    It "groups checks into human domains" {
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'Storage';  Category = 'Azure' })) | Should -Be 'Storage'
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'KeyVault'; Category = 'Azure' })) | Should -Be 'Key Vault'
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'Network';  Category = 'Azure' })) | Should -Be 'Networking'
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'EntraRoles'; Category = 'Entra' })) | Should -Be 'Identity'
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'Governance'; Category = 'Azure' })) | Should -Be 'Monitoring & governance'
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'APIM';     Category = 'Azure' })) | Should -Be 'Messaging & integration'
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'Exposure'; Category = 'Azure' })) | Should -Be 'Exposure'
    }
}

Describe "Write-CheckStatusLine - human output" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet  = $false
        $script:State.Config.NoColor = $true
        $script:UiForceAnsi = $null
        $script:captured = New-Object System.Collections.Generic.List[string]
        Mock Write-Host { param($Object) [void]$script:captured.Add("$Object") }
    }

    AfterEach { $script:UiForceAnsi = $null }

    It "shows 'Could not check' for NotEvaluated, never raw NOTEVAL/NOTEVALUATED" {
        $check  = [PSCustomObject]@{ CheckId = 'MESSAGING-003'; Name = 'API Management Security'; Service = 'APIM'; Category = 'Azure' }
        $record = [PSCustomObject]@{ Status = 'NotEvaluated'; Detail = 'Az module compatibility issue' }
        Write-CheckStatusLine -Index 1 -Total 41 -Check $check -Record $record
        $line = ($script:captured -join '')
        $line | Should -Match 'Could not check'
        $line | Should -Match 'Az module compatibility issue'
        $line | Should -Not -Match 'NOTEVAL'
        $line | Should -Not -Match 'NOTEVALUATED'
    }

    It "emits the domain header once for consecutive checks in the same domain" {
        $c1 = [PSCustomObject]@{ CheckId = 'STORAGE-001'; Name = 'x'; Service = 'Storage'; Category = 'Azure' }
        $c2 = [PSCustomObject]@{ CheckId = 'STORAGE-002'; Name = 'y'; Service = 'Storage'; Category = 'Azure' }
        $rec = [PSCustomObject]@{ Status = 'Pass' }
        Write-CheckStatusLine -Index 1 -Total 2 -Check $c1 -Record $rec
        Write-CheckStatusLine -Index 2 -Total 2 -Check $c2 -Record $rec
        @($script:captured | Where-Object { $_ -eq 'Storage' }).Count | Should -Be 1
    }

    It "keeps the CheckId as muted secondary metadata at the end of the line" {
        $script:State.Config.NoColor = $false
        $script:UiForceAnsi = $false
        $prevNoColor = $env:NO_COLOR; $env:NO_COLOR = $null   # host shells may set NO_COLOR=1
        try {
            $script:colored = New-Object System.Collections.Generic.List[string]
            Mock Write-Host { param($Object, $ForegroundColor) [void]$script:colored.Add("$ForegroundColor|$Object") }
            $check  = [PSCustomObject]@{ CheckId = 'KEYVAULT-002'; Name = 'x'; Service = 'KeyVault'; Category = 'Azure'; DefaultSeverity = 'CRITICAL' }
            $record = [PSCustomObject]@{ Status = 'Fail'; SummaryText = '41 vaults exposed' }
            Write-CheckStatusLine -Index 1 -Total 41 -Check $check -Record $record
            $segments = @($script:colored)
            ($segments | Where-Object { $_ -match 'KEYVAULT-002' }) | Should -Match '^DarkGray\|'
            # CRITICAL fail derives the CritRed status color.
            ($segments | Where-Object { $_ -match 'Needs review' }) | Should -Match '^Red\|'   # ConsoleColor fallback of CritRed
        } finally {
            $env:NO_COLOR = $prevNoColor
        }
    }

    It "-NoColor output contains no ANSI escape sequences" {
        $script:UiForceAnsi = $true   # even when the host supports truecolor
        $check  = [PSCustomObject]@{ CheckId = 'STORAGE-001'; Name = 'x'; Service = 'Storage'; Category = 'Azure' }
        $record = [PSCustomObject]@{ Status = 'Fail'; SummaryText = '1 risky' }
        Write-CheckStatusLine -Index 1 -Total 41 -Check $check -Record $record
        ($script:captured -join '') | Should -Not -Match "$([char]27)\["
    }
}

Describe "Invoke-AuditChecks - mode skip, domain order, error summarization" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
    }

    It "Entra checks under -SkipEntra are recorded Skipped with a mode reason, never executed" {
        function global:Test-EntraMustNotRun { throw 'ENTRA CHECK EXECUTED UNDER -SkipEntra' }
        Register-AuditCheck -CheckId 'ENTRA-99' -Category 'Entra' -Service 'EntraRoles' -Name 'Test-EntraMustNotRun' -Function 'Test-EntraMustNotRun' -Phase 'TenantWide'
        Invoke-AuditChecks -SkipEntra -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ENTRA-99' })[0]
        $rec.Status | Should -Be 'Skipped'
        $rec.Detail | Should -Be 'Entra checks disabled by -SkipEntra'
    }

    It "executes checks in domain order so CLI sections are contiguous" {
        $script:execOrder = New-Object System.Collections.Generic.List[string]
        function global:Test-NetZ { param([array]$Subscriptions) [void]$script:execOrder.Add('NET') }
        function global:Test-StoA { param([array]$Subscriptions) [void]$script:execOrder.Add('STO') }
        Register-AuditCheck -CheckId 'ZZ-NET' -Category 'Azure' -Service 'Network' -Name 'net' -Function 'Test-NetZ' -Phase 'PerSubscription'
        Register-AuditCheck -CheckId 'ZZ-STO' -Category 'Azure' -Service 'Storage' -Name 'sto' -Function 'Test-StoA' -Phase 'PerSubscription'
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        # Storage (domain index 2) runs before Networking (domain index 3).
        $script:execOrder[0] | Should -Be 'STO'
        $script:execOrder[1] | Should -Be 'NET'
    }

    It "repeated per-subscription errors collapse to one 'Details saved to' console line" {
        function global:Test-SpammyErrors {
            param([array]$Subscriptions)
            foreach ($s in @($Subscriptions)) {
                Write-AuditLog -Message "Failed to check things in subscription $($s.Name): boom" -Level ERROR
                Write-AuditLog -Message "Failed to check things in subscription $($s.Name): boom" -Level ERROR
            }
        }
        Register-AuditCheck -CheckId 'ZZ-SPAM' -Category 'Azure' -Service 'Storage' -Name 'spam' -Function 'Test-SpammyErrors' -Phase 'PerSubscription'
        $script:State.Config.Quiet = $false
        $script:uiCalls = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text) [void]$script:uiCalls.Add("$Text") }
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $all = $script:uiCalls -join "`n"
        @($script:uiCalls | Where-Object { $_ -match 'Details saved to' }).Count | Should -Be 1
        # Raw timestamped ERROR lines never reach the console in normal mode.
        $all | Should -Not -Match '\[ERROR\]'
        # The normalized failure reason surfaces as the check-line summary.
        $all | Should -Match 'Failed to check things in subscription'
    }
}

Describe "Show-EnvironmentFootprint - product wording" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $false
        Mock Write-UiHost {}
    }

    It "complete discovery prints 'Environment discovery' without warnings or the technical source line" {
        $fp = [PSCustomObject]@{
            Subscriptions = 49; ResourceGroups = 95; Resources = 5663
            ResourceTypeCount = 81; RegionCount = 6; Regions = @('westeurope')
            TopTypes = @([PSCustomObject]@{ Type = 'microsoft.storage/storageaccounts'; Label = 'Storage accounts'; Count = 60; CountText = $null })
            TypeCounts = @{}; Source = 'ResourceGraph+Get-AzResource'
            SubscriptionsExpected = 49; SubscriptionsCovered = 49
            CoverageStatus = 'Complete'; Confidence = 'High'; Note = ''
        }
        Show-EnvironmentFootprint -Footprint $fp
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '^Environment discovery$' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '49 subscriptions, 95 resource groups, 5,663 resources' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'WARN' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'incomplete' }
        # The discovery source is log/debug-only; it must never reach normal CLI.
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'Source:' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'ResourceGraph' }
        # Human service label, not the raw type segment.
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'Storage accounts' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'storageaccounts\s' }
    }

    It "incomplete discovery warns visibly, explains the fail-safe, and hides the source" {
        $fp = [PSCustomObject]@{
            Subscriptions = 49; ResourceGroups = 1; Resources = 80
            ResourceTypeCount = 1; RegionCount = 1; Regions = @('westeurope')
            TopTypes = @(); TypeCounts = @{}; Source = 'ResourceGraph'
            SubscriptionsExpected = 49; SubscriptionsCovered = 35
            CoverageStatus = 'Partial'; Confidence = 'Low'; Note = 'note text'
        }
        Show-EnvironmentFootprint -Footprint $fp
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '^Environment discovery incomplete$' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '14 of 49 subscriptions' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'Applicability decisions disabled' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'source:' }
    }
}

Describe "Show-AssessmentPlan" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $false
        Mock Write-UiHost {}
    }

    It "counts planned, relevant and skipped-by-mode checks" {
        function global:Test-PlanAz { param([array]$Subscriptions) }
        function global:Test-PlanEntra { }
        Register-AuditCheck -CheckId 'ZZ-PAZ'   -Category 'Azure' -Service 'Storage' -Name 'az'    -Function 'Test-PlanAz'    -Phase 'PerSubscription' -AlwaysRun $true
        Register-AuditCheck -CheckId 'ZZ-PENTRA' -Category 'Entra' -Service 'EntraRoles' -Name 'ent' -Function 'Test-PlanEntra' -Phase 'TenantWide'
        Show-AssessmentPlan -SkipEntra -Services @('All')
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '2 checks planned' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '1 relevant to this environment' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '1 skipped by mode \(Azure-only mode\)' }
    }
}
