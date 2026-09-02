#==============================================================================
# AzureMap v2 - Tests/EntraMap/Phase7.GraphBatch.Tests.ps1
# Phase 7 - mocked/local only. No Azure, no Graph, no authentication.
#
# Verifies Invoke-GraphBatch returns a shaped { Success; Status; Data; Error }
# result per request id, and that failed subresponses are distinguishable from
# successful-but-empty data. No real Graph calls are made (fully mocked).
#==============================================================================

BeforeAll {
    # Parked under Future/EntraMap/Tests: repo root is three levels up.
    $projectRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Future\EntraMap\Core\Graph.ps1"

    $script:State = Initialize-EntraAuditState
    $script:State.Config.Quiet = $true
}

Describe "Invoke-GraphBatch - shaped results" {

    BeforeEach {
        Mock Get-GraphToken { "placeholder-token" }

        # Simulate the /$batch envelope response: mixed 200 / 403 / 404 / 200-empty.
        Mock Invoke-AzureCommand {
            [PSCustomObject]@{
                responses = @(
                    [PSCustomObject]@{ id = '0'; status = 200; body = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'obj-a' }) } }
                    [PSCustomObject]@{ id = '1'; status = 403; body = [PSCustomObject]@{ error = [PSCustomObject]@{ code = 'Authorization_RequestDenied' } } }
                    [PSCustomObject]@{ id = '2'; status = 404; body = $null }
                    [PSCustomObject]@{ id = '3'; status = 200; body = [PSCustomObject]@{ value = @() } }
                )
            }
        }

        $script:Requests = @(
            @{ id = '0'; url = '/directoryObjects/x' }
            @{ id = '1'; url = '/directoryObjects/y' }
            @{ id = '2'; url = '/directoryObjects/z' }
            @{ id = '3'; url = '/directoryObjects/w' }
        )
    }

    It "200 -> Success=true with populated Data" {
        $r = Invoke-GraphBatch -Requests $script:Requests
        $r['0'].Success        | Should -BeTrue
        $r['0'].Status         | Should -Be 200
        @($r['0'].Data.value).Count | Should -Be 1
    }

    It "403 -> Success=false, Status=403, Error populated, Data null" {
        $r = Invoke-GraphBatch -Requests $script:Requests
        $r['1'].Success | Should -BeFalse
        $r['1'].Status  | Should -Be 403
        $r['1'].Data    | Should -BeNullOrEmpty
        $r['1'].Error   | Should -Not -BeNullOrEmpty
    }

    It "404 -> Success=false, Status=404" {
        $r = Invoke-GraphBatch -Requests $script:Requests
        $r['2'].Success | Should -BeFalse
        $r['2'].Status  | Should -Be 404
    }

    It "a failed subresponse is distinguishable from successful-but-empty data" {
        $r = Invoke-GraphBatch -Requests $script:Requests
        # id 3 is a legitimate empty success; id 1 is a failure.
        $r['3'].Success             | Should -BeTrue
        @($r['3'].Data.value).Count | Should -Be 0
        $r['1'].Success             | Should -BeFalse
        # A consumer checking .Success must not treat id 1 as clean empty data.
        ($r['3'].Success -and -not $r['1'].Success) | Should -BeTrue
    }
}
