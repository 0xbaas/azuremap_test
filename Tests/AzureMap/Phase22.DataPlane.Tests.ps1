#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase22.DataPlane.Tests.ps1
# Phase B3: data-plane gating and safety hardening.
#   * -IncludeDataPlane switch exists; Config.IncludeDataPlane defaults to $false
#   * RequiresDataPlane checks (STORAGE-004, KEYVAULT-003) never run by default
#   * gated checks record Skipped with a clear human reason, visible in normal CLI
#   * NotApplicable still wins when the footprint proves no resources in scope
#   * -IncludeDataPlane re-enables the checks
#   * CLI scope line shows Data-plane checks: disabled/enabled
#   * JSON run metadata carries DataPlaneIncluded
#   * safety grep: runtime code never retrieves keys/secrets/SAS/connection
#     strings and never downloads blob/file content
# Mocked/local only. No Azure, no Graph, no data-plane.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Products\AzureMap\Core\Footprint.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"
    . "$projectRoot\Shared\Export\Json.ps1"

    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }
    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }

    function script:New-FxSub {
        [PSCustomObject]@{ Id = 'sub-1'; Name = 'fx-sub'; TenantId = 't-1'; SubscriptionId = 'sub-1' }
    }
}

Describe "Phase B3 switch surface" {

    It "azuremap.ps1 declares -IncludeDataPlane" {
        $src = Get-Content (Join-Path $projectRoot 'Products\AzureMap\azuremap.ps1') -Raw
        $src | Should -Match '\[switch\]\$IncludeDataPlane'
        $src | Should -Match 'Config\.IncludeDataPlane\s*=\s*\$IncludeDataPlane\.IsPresent'
    }

    It "IncludeDataPlane defaults to false (safely read-only)" {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.IncludeDataPlane | Should -BeFalse
    }

    It "STORAGE-004 and KEYVAULT-003 are registered as data-plane checks" {
        $storage  = Get-Content (Join-Path $projectRoot 'Products\AzureMap\Checks\Storage.ps1')  -Raw
        $keyvault = Get-Content (Join-Path $projectRoot 'Products\AzureMap\Checks\KeyVault.ps1') -Raw
        # Registration blocks pair the CheckId with -RequiresDataPlane $true.
        $storage  | Should -Match '(?s)STORAGE-004.*?-RequiresDataPlane\s+\$true'
        $keyvault | Should -Match '(?s)KEYVAULT-003.*?-RequiresDataPlane\s+\$true'
    }
}

Describe "Invoke-AuditChecks - data-plane gate" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $false
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        # High-confidence complete footprint with storage accounts present, so
        # the data-plane check is APPLICABLE and the gate is what stops it.
        $script:State.Footprint = [PSCustomObject]@{
            TypeCounts = @{ 'microsoft.storage/storageaccounts' = 5 }
            Source = 'ResourceGraph'; CoverageStatus = 'Complete'; Confidence = 'High'
        }
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
    }

    It "default run does not execute a data-plane check; records Skipped with a clear reason" {
        function global:Test-DpGated { param([array]$Subscriptions) throw 'DATA-PLANE CHECK MUST NOT EXECUTE' }
        Register-AuditCheck -CheckId 'ZZ-DP' -Category 'Azure' -Service 'Storage' -Name 'Anonymous blob access' `
            -Function 'Test-DpGated' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.storage/storageaccounts') -RequiresDataPlane $true

        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')

        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-DP' })[0]
        $rec.Status | Should -Be 'Skipped'
        $rec.Detail  | Should -Be 'Data-plane checks disabled'
        $rec.DataPlaneRequired | Should -BeTrue
    }

    It "the gated row is visible in NORMAL output: 'Skipped  Data-plane checks disabled'" {
        function global:Test-DpGated2 { param([array]$Subscriptions) throw 'DATA-PLANE CHECK MUST NOT EXECUTE' }
        Register-AuditCheck -CheckId 'ZZ-DP2' -Category 'Azure' -Service 'Storage' -Name 'Anonymous blob access' `
            -Function 'Test-DpGated2' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.storage/storageaccounts') -RequiresDataPlane $true

        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $all = $script:ui -join "`n"
        $all | Should -Match 'Anonymous blob access'
        $all | Should -Match 'Skipped'
        $all | Should -Match 'Data-plane checks disabled'
        $all | Should -Match 'ZZ-DP2'
    }

    It "other Skipped rows (mode skip) stay hidden in normal output" {
        function global:Test-DpOther { param([array]$Subscriptions) }
        Register-AuditCheck -CheckId 'ZZ-DP-ENTRA' -Category 'Entra' -Service 'EntraRoles' -Name 'entra' -Function 'Test-DpOther' -Phase 'TenantWide'
        Invoke-AuditChecks -SkipEntra -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $all = $script:ui -join "`n"
        $all | Should -Not -Match 'ZZ-DP-ENTRA'
    }

    It "NotApplicable still wins when the footprint proves no relevant resources" {
        function global:Test-DpNoScope { param([array]$Subscriptions) throw 'MUST NOT RUN' }
        Register-AuditCheck -CheckId 'ZZ-DP-NA' -Category 'Azure' -Service 'SQL' -Name 'dp no scope' `
            -Function 'Test-DpNoScope' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.sql/servers') -RequiresDataPlane $true

        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-DP-NA' })[0]
        $rec.Status | Should -Be 'NotApplicable'
        $rec.Detail | Should -Match 'No servers resources in scope'
    }

    It "-IncludeDataPlane executes the data-plane check (safe metadata path)" {
        $script:State.Config.IncludeDataPlane = $true
        function global:Test-DpRuns { param([array]$Subscriptions)
            Write-Finding -Severity 'INFO' -Status 'PASS' -Count 0 -Service 'Storage' -CheckId 'ZZ-DP-RUN' `
                -Message 'evaluated' -DataPlaneRequired $true
        }
        Register-AuditCheck -CheckId 'ZZ-DP-RUN' -Category 'Azure' -Service 'Storage' -Name 'dp runs' `
            -Function 'Test-DpRuns' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.storage/storageaccounts') -RequiresDataPlane $true

        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-DP-RUN' })[0]
        $rec.Status | Should -Be 'Pass'
        $rec.DataPlaneRequired | Should -BeTrue
    }
}

Describe "CLI scope and assessment plan show the data-plane mode" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $false
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        $script:State.Footprint = [PSCustomObject]@{
            TypeCounts = @{ 'microsoft.storage/storageaccounts' = 5 }
            Source = 'ResourceGraph'; CoverageStatus = 'Complete'; Confidence = 'High'
        }
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
    }

    It "run context shows 'Data-plane checks: disabled' by default" {
        Show-RunContext
        ($script:ui -join "`n") | Should -Match 'Data-plane checks: disabled'
    }

    It "run context shows 'Data-plane checks: enabled' with -IncludeDataPlane" {
        $script:State.Config.IncludeDataPlane = $true
        Show-RunContext
        ($script:ui -join "`n") | Should -Match 'Data-plane checks: enabled'
    }

    It "run context shows the report layout (Pentester by default)" {
        Show-RunContext
        ($script:ui -join "`n") | Should -Match 'Report layout: Pentester'
    }

    It "assessment plan counts gated data-plane checks separately when disabled" {
        function global:Test-DpPlan { param([array]$Subscriptions) }
        Register-AuditCheck -CheckId 'ZZ-DP-PLAN' -Category 'Azure' -Service 'Storage' -Name 'dp plan' `
            -Function 'Test-DpPlan' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.storage/storageaccounts') -RequiresDataPlane $true
        Show-AssessmentPlan -Services @('All')
        $all = $script:ui -join "`n"
        $all | Should -Match 'Data-plane checks: disabled'
        $all | Should -Match '1 relevant check\(s\) gated'
        $all | Should -Match '-IncludeDataPlane'
    }

    It "assessment plan shows enabled mode and counts the check as relevant" {
        $script:State.Config.IncludeDataPlane = $true
        function global:Test-DpPlan2 { param([array]$Subscriptions) }
        Register-AuditCheck -CheckId 'ZZ-DP-PLAN2' -Category 'Azure' -Service 'Storage' -Name 'dp plan2' `
            -Function 'Test-DpPlan2' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.storage/storageaccounts') -RequiresDataPlane $true
        Show-AssessmentPlan -Services @('All')
        $all = $script:ui -join "`n"
        $all | Should -Match 'Data-plane checks: enabled'
        $all | Should -Match '1 relevant to this environment'
    }
}

Describe "Exports show the data-plane mode" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
    }

    It "JSON metadata carries DataPlaneIncluded=false by default" {
        $base = Join-Path $TestDrive 'dp-off'
        Export-ResultsJson -Results @() -BaseName $base | Out-Null
        (Get-Content "$base.json" -Raw) | Should -Match '"DataPlaneIncluded":\s*false'
    }

    It "JSON metadata carries DataPlaneIncluded=true when enabled" {
        $script:State.Config.IncludeDataPlane = $true
        $base = Join-Path $TestDrive 'dp-on'
        Export-ResultsJson -Results @() -BaseName $base | Out-Null
        (Get-Content "$base.json" -Raw) | Should -Match '"DataPlaneIncluded":\s*true'
    }

    It "skipped data-plane checks appear in ExecutedChecks with DataPlaneRequired" {
        $script:State.ExecutedChecks.Add([PSCustomObject]@{
            CheckId = 'STORAGE-004'; Name = 'Anonymous Blob Access'; Status = 'Skipped'
            Service = 'Storage'; Category = 'Azure'; SummaryText = $null
            Detail = 'Data-plane checks disabled'; ErrorClass = $null; Coverage = $null
            DataPlaneRequired = $true
        })
        $base = Join-Path $TestDrive 'dp-skip'
        Export-ResultsJson -Results @() -BaseName $base | Out-Null
        $raw = Get-Content "$base.json" -Raw
        $raw | Should -Match '"Status":\s*"Skipped"'
        $raw | Should -Match '"DataPlaneRequired":\s*true'
        $raw | Should -Match 'Data-plane checks disabled'
    }

    It "HTML declares the data-plane mode in the report header and coverage section" {
        $html = Get-Content (Join-Path $projectRoot 'Shared\Export\Html.ps1') -Raw
        $html | Should -Match 'Data-plane checks: \$dpMode'
        $html | Should -Match 'Data-plane checks: disabled'
        $html | Should -Match 'Data-plane checks: enabled'
    }
}

Describe "Safety grep - no key/secret/content retrieval in runtime code" {

    BeforeAll {
        $script:runtimeFiles = @(
            Get-ChildItem -Path (Join-Path $projectRoot 'Products') -Filter *.ps1 -File -Recurse
            Get-ChildItem -Path (Join-Path $projectRoot 'Shared')   -Filter *.ps1 -File -Recurse
            Get-Item (Join-Path $projectRoot 'Products\AzureMap\azuremap.ps1')
        )
        # Strips full-line and trailing comments so policy statements in
        # comments (e.g. "no listKeys") never trip the guard.
        function script:Get-CodeLines {
            param([string]$Path)
            foreach ($line in (Get-Content $Path)) {
                $t = $line.TrimStart()
                if ($t.StartsWith('#')) { continue }
                $line
            }
        }
    }

    It "never calls Get-AzStorageAccountKey" {
        foreach ($f in $script:runtimeFiles) {
            (Get-CodeLines -Path $f.FullName) | Should -Not -Match 'Get-AzStorageAccountKey'
        }
    }

    It "never invokes listKeys / listSecrets actions" {
        foreach ($f in $script:runtimeFiles) {
            $codeLines = @(Get-CodeLines -Path $f.FullName)
            # Phase B2 distinction: static single-quoted permission/action strings
            # used for read-only capability modeling (e.g. the key-list action name
            # in a role-definition Actions comparison, or the RBAC reference in
            # StorageKey.ps1) are SAFE. Anything outside a quoted literal - path
            # construction, SDK/REST invocation - remains forbidden.
            $stripped = ($codeLines | ForEach-Object { $_ -replace "'[^']*'", "''" }) -join "`n"
            $stripped | Should -Not -Match 'listKeys'
            $stripped | Should -Not -Match 'listSecrets'
            # Even inside quotes, an invocation cmdlet on the same line is forbidden.
            foreach ($line in $codeLines) {
                if ("$line" -match 'listKeys|listSecrets') {
                    $line | Should -Not -Match 'Invoke-AzRestMethod|Invoke-RestMethod|Invoke-WebRequest|Invoke-AzureCommand'
                }
            }
        }
    }

    It "never reads .SecretValue" {
        foreach ($f in $script:runtimeFiles) {
            (Get-CodeLines -Path $f.FullName) | Should -Not -Match '\.SecretValue'
        }
    }

    It "never downloads blob or file content" {
        foreach ($f in $script:runtimeFiles) {
            (Get-CodeLines -Path $f.FullName) | Should -Not -Match 'Get-AzStorageBlobContent|Get-AzStorageFileContent|Invoke-AzStorageBlobDownload'
        }
    }

    It "never builds a key/SAS-backed storage context" {
        foreach ($f in $script:runtimeFiles) {
            (Get-CodeLines -Path $f.FullName) | Should -Not -Match 'New-AzStorageContext'
        }
    }

    It "no interactive prompts anywhere in runtime code" {
        foreach ($f in $script:runtimeFiles) {
            (Get-CodeLines -Path $f.FullName) | Should -Not -Match '\bRead-Host\b|PromptForCredential'
        }
    }
}

Describe "Permission-denied data-plane degradation" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $false
        $script:State.Config.IncludeDataPlane = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        $script:State.Footprint = [PSCustomObject]@{
            TypeCounts = @{ 'microsoft.keyvault/vaults' = 3 }
            Source = 'ResourceGraph'; CoverageStatus = 'Complete'; Confidence = 'High'
        }
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
    }

    It "nothing evaluated (all access denied) resolves to Could not check, not Partially checked" {
        # Mirrors the KEYVAULT-003 coverage shape when every vault read is denied:
        # a single NOTEVALUATED record that still carries PartialEvaluation=$true.
        function global:Test-DpDenied { param([array]$Subscriptions)
            Write-Finding -Severity 'INFO' -Status 'NOTEVALUATED' -Count 0 -Service 'KeyVault' -CheckId 'ZZ-DP-DENIED' `
                -Message 'Could not evaluate Key Vault secret metadata; data-plane access denied or collection failed.' `
                -DiscoveredResourceCount 3 -EvaluatedResourceCount 0 -FailedCollectionCount 3 `
                -CollectionStatus 'Failed' -PartialEvaluation $true -DataPlaneRequired $true
        }
        Register-AuditCheck -CheckId 'ZZ-DP-DENIED' -Category 'Azure' -Service 'KeyVault' -Name 'secret expiry' `
            -Function 'Test-DpDenied' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.keyvault/vaults') -RequiresDataPlane $true

        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-DP-DENIED' })[0]
        $rec.Status | Should -Be 'NotEvaluated'
        # The full reason is preserved on the record (exports/HTML); the CLI row
        # truncates the summary to its column width.
        $rec.SummaryText | Should -Match 'data-plane access denied'
        $all = $script:ui -join "`n"
        $all | Should -Match 'Could not check'
        $all | Should -Match 'Could not evaluate Key Vault secret metad'
        $all | Should -Not -Match 'Partially checked'
    }

    It "some evaluated + some denied resolves to Partially checked" {
        function global:Test-DpSome { param([array]$Subscriptions)
            Write-Finding -Severity 'INFO' -Status 'PASS' -Count 0 -Service 'KeyVault' -CheckId 'ZZ-DP-SOME' `
                -Message 'evaluated vaults; 0 issues' `
                -DiscoveredResourceCount 3 -EvaluatedResourceCount 1 -FailedCollectionCount 2 `
                -CollectionStatus 'Partial' -PartialEvaluation $true -DataPlaneRequired $true
        }
        Register-AuditCheck -CheckId 'ZZ-DP-SOME' -Category 'Azure' -Service 'KeyVault' -Name 'secret expiry partial' `
            -Function 'Test-DpSome' -Phase 'PerSubscription' `
            -RequiredResourceTypes @('microsoft.keyvault/vaults') -RequiresDataPlane $true

        Invoke-AuditChecks -Subscriptions @(script:New-FxSub) -Exclusions @{} -Services @('All')
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-DP-SOME' })[0]
        $rec.Status | Should -Be 'Partial'
        ($script:ui -join "`n") | Should -Match 'Partially checked'
    }
}

Describe "Unattended-run hardening (no prompts, no module warning leaks)" {

    BeforeAll {
        $script:entrypoint = Get-Content (Join-Path $projectRoot 'Products\AzureMap\azuremap.ps1') -Raw
    }

    It "Invoke-WebRequest/Invoke-RestMethod basic parsing is forced at GLOBAL scope" {
        # Module-scope calls (Az internals, background runspaces) do not inherit
        # script-scoped defaults; the anti-prompt hardening must be global.
        $script:entrypoint | Should -Match '\$global:PSDefaultParameterValues\[''Invoke-WebRequest:UseBasicParsing''\]\s*=\s*\$true'
        $script:entrypoint | Should -Match '\$global:PSDefaultParameterValues\[''Invoke-RestMethod:UseBasicParsing''\]\s*=\s*\$true'
    }

    It "the Warning stream is silenced at GLOBAL scope (module autoload warnings)" {
        $script:entrypoint | Should -Match '\$global:WarningPreference\s*=\s*''SilentlyContinue'''
    }

    It "global preferences are restored in the finally block" {
        $script:entrypoint | Should -Match '\$global:WarningPreference\s*=\s*\$script:PrevWarningPreference'
        $script:entrypoint | Should -Match '\$global:ProgressPreference\s*=\s*\$script:PrevProgressPreference'
    }

    It "Write-Finding never prints blocks for VerboseOutput alone (only -ShowFindings/-ShowRemediation)" {
        $registry = Get-Content (Join-Path $projectRoot 'Shared\Core\CheckRegistry.ps1') -Raw
        # The block gate must not contain VerboseOutput anymore.
        $registry | Should -Match 'if \(-not \(\$script:State\.Config\.ShowFindings -or \$script:State\.Config\.ShowRemediation\)\) \{ return \}'
        $registry | Should -Not -Match 'Config\.VerboseOutput -or \$script:State\.Config\.ShowFindings'
    }
}
