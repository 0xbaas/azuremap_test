#==============================================================================
# AzureMap v2 - Tests/Unit/Phase3.RunStatus.Tests.ps1
# Phase 3 - mocked/local only. No Azure, no Graph, no authentication.
#
# Covers run-status diagnostics math and the clean console renderer.
# No real identifiers are used - all values are synthetic placeholders.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\RunStatus.ps1"
    . "$projectRoot\Core\Console.ps1"

    $script:State = Initialize-AuditState

    function New-Exec {
        param([string]$Status, [string]$CheckId = "CHK-00", [string]$ErrorClass = $null)
        [PSCustomObject]@{ CheckId = $CheckId; Name = "check"; Category = "Azure"; Service = "Storage";
                           Phase = "PerSubscription"; Status = $Status; StartedAt = (Get-Date);
                           CompletedAt = (Get-Date); ErrorClass = $ErrorClass; Detail = $null }
    }

    function New-Finding {
        param($Count, [string]$Severity = "HIGH", [string]$Status = "FAIL", $Evidence = $null, [switch]$NoCount)
        $h = [ordered]@{ Severity = $Severity; Service = "Identity"; Finding = "synthetic finding title"; Status = $Status; Evidence = $Evidence }
        if (-not $NoCount) { $h['Count'] = $Count }
        [PSCustomObject]$h
    }

    function Capture-Console {
        param([string[]]$ExportedFiles = @())
        & { Show-AuditConsole -ExportedFiles $ExportedFiles } *>&1 | Out-String
    }
}

Describe "Get-RunDiagnostics - summary math" {

    BeforeEach {
        $script:State.ExecutedChecks.Clear()
        $script:State.Results.Clear()
    }

    It "3 attempted checks (Pass/Error/NotEvaluated) counted correctly" {
        $script:State.ExecutedChecks.Add((New-Exec -Status 'Pass'         -CheckId 'A-1'))
        $script:State.ExecutedChecks.Add((New-Exec -Status 'Error'        -CheckId 'A-2' -ErrorClass 'Auth'))
        $script:State.ExecutedChecks.Add((New-Exec -Status 'NotEvaluated' -CheckId 'A-3'))

        $d = Get-RunDiagnostics
        $d.ChecksAttempted | Should -Be 3
        $d.Passed          | Should -Be 1
        $d.Errors          | Should -Be 1
        $d.NotEvaluated    | Should -Be 1
        $d.Failed          | Should -Be 0
    }

    It "one finding group with Count=227 -> FindingGroups 1, AffectedResources 227" {
        $script:State.Results.Add((New-Finding -Count 227))
        $d = Get-RunDiagnostics
        $d.FindingGroups     | Should -Be 1
        $d.AffectedResources | Should -Be 227
    }

    It "many finding groups sum to affected resources" {
        $script:State.Results.Add((New-Finding -Count 5))
        $script:State.Results.Add((New-Finding -Count 200))
        $script:State.Results.Add((New-Finding -Count 22))
        $d = Get-RunDiagnostics
        $d.FindingGroups     | Should -Be 3
        $d.AffectedResources | Should -Be 227
    }

    It "no findings and no checks -> all zero, no crash" {
        $d = Get-RunDiagnostics
        $d.ChecksAttempted   | Should -Be 0
        $d.FindingGroups     | Should -Be 0
        $d.AffectedResources | Should -Be 0
    }

    It "all-error run does not crash and reports errors" {
        1..3 | ForEach-Object { $script:State.ExecutedChecks.Add((New-Exec -Status 'Error' -CheckId "E-$_")) }
        $d = Get-RunDiagnostics
        $d.Errors        | Should -Be 3
        $d.Failed        | Should -Be 0
        $d.FindingGroups | Should -Be 0
    }

    It "Count = 0 and missing Count are excluded from finding groups" {
        $script:State.Results.Add((New-Finding -Count 0))
        $script:State.Results.Add((New-Finding -NoCount))
        $d = Get-RunDiagnostics
        $d.FindingGroups     | Should -Be 0
        $d.AffectedResources | Should -Be 0
    }

    It "NotEvaluated findings are not counted as finding groups" {
        $script:State.Results.Add((New-Finding -Count 0 -Severity 'INFO' -Status 'NotEvaluated'))
        $d = Get-RunDiagnostics
        $d.FindingGroups | Should -Be 0
    }
}

Describe "Show-AuditConsole - clean output" {

    BeforeEach {
        $script:State.ExecutedChecks.Clear()
        $script:State.Results.Clear()
        $script:State.Config.Quiet         = $false
        $script:State.Config.VerboseOutput = $false
    }

    It "-Quiet suppresses all output" {
        $script:State.Config.Quiet = $true
        $script:State.Results.Add((New-Finding -Count 227))
        $out = Capture-Console
        $out.Trim() | Should -BeNullOrEmpty
    }

    It "Count=227 is 'Affected resources  227', never '227 findings'" {
        $script:State.Results.Add((New-Finding -Count 227))
        $script:State.ExecutedChecks.Add((New-Exec -Status 'Fail'))
        $out = Capture-Console
        $out | Should -Match 'Affected resources\s+227'
        $out | Should -Match 'Finding groups\s+1'
        $out | Should -Not -Match '227 findings'
    }

    It "does not print raw hashtable evidence or object type names" {
        $script:State.Results.Add((New-Finding -Count 3 -Evidence @{ Secret = 'RAWHASHSECRET' }))
        $out = Capture-Console
        $out | Should -Not -Match 'RAWHASHSECRET'
        $out | Should -Not -Match 'System.Collections'
    }

    It "no-finding run renders cleanly with a Top findings (none) section" {
        $out = Capture-Console
        $out | Should -Match 'Top findings'
        $out | Should -Match '\(none\)'
    }

    It "all-error run renders without crashing and shows error count" {
        $script:State.ExecutedChecks.Add((New-Exec -Status 'Error' -CheckId 'E-1' -ErrorClass 'Auth'))
        $script:State.ExecutedChecks.Add((New-Exec -Status 'Error' -CheckId 'E-2' -ErrorClass 'Throttle'))
        $out = Capture-Console
        $out | Should -Match 'Tool errors\s+2'
    }

    It "-VerboseOutput still does not leak raw evidence/secrets" {
        $script:State.Config.VerboseOutput = $true
        $script:State.Results.Add((New-Finding -Count 3 -Evidence @{ Secret = 'RAWHASHSECRET' }))
        $out = Capture-Console
        $out | Should -Not -Match 'RAWHASHSECRET'
    }
}
