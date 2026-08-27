#==============================================================================
# AzureMap v2 - Tests/Shared/Phase2.Preflight.Tests.ps1
# Phase 2 - mocked/local only. No Azure, no Graph, no authentication.
#
# Covers:
#   * ARM present + Graph succeeds -> Entra enabled
#   * Graph auth fails -> clean guidance (AuthScope), ShouldStop
#   * -ContinueWithoutEntra -> Azure-only continues (no stop)
#   * -SkipEntra -> Graph token never requested
#   * ARM missing -> ShouldStop with Connect-AzAccount guidance
#   * No token is printed or logged
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Preflight.ps1"

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet = $true

    # Stubs so Get-Command / Mock can attach (no real Azure/Graph).
    function Get-AzContext { param([switch]$ErrorAction) $null }
    function Get-GraphToken { param([switch]$ForceRefresh) "stub" }

    $script:FakeContext = [PSCustomObject]@{
        Account = [PSCustomObject]@{ Id = "actor@example.test" }
        Tenant  = [PSCustomObject]@{ Id = "tenant-placeholder" }
    }
}

Describe "Test-AuthenticationPreflight" {

    BeforeEach {
        $script:State.Auth = $null
        $script:State.LogBuffer.Clear()
    }

    It "ARM + Graph success -> Entra enabled, no stop" {
        Mock Get-AzContext  { $script:FakeContext }
        Mock Get-GraphToken { "valid-token" }

        $r = Test-AuthenticationPreflight

        $r.ArmAvailable       | Should -BeTrue
        $r.EntraRequested     | Should -BeTrue
        $r.GraphTokenAcquired | Should -BeTrue
        $r.EntraInScope       | Should -BeTrue
        $r.ShouldStop         | Should -BeFalse
    }

    It "Graph failure without -ContinueWithoutEntra -> clean guidance and stop" {
        Mock Get-AzContext  { $script:FakeContext }
        Mock Get-GraphToken { throw "AADSTS65001: interaction_required - use -AuthScope" }

        $r = Test-AuthenticationPreflight

        $r.GraphTokenAcquired | Should -BeFalse
        $r.EntraInScope       | Should -BeFalse
        $r.ShouldStop         | Should -BeTrue
        $r.Guidance           | Should -BeLike '*Connect-AzAccount -AuthScope*'
        $r.Guidance           | Should -BeLike '*https://graph.microsoft.com*'
    }

    It "Graph failure with -ContinueWithoutEntra -> Azure-only continues (no stop)" {
        Mock Get-AzContext  { $script:FakeContext }
        Mock Get-GraphToken { throw "interaction_required" }

        $r = Test-AuthenticationPreflight -ContinueWithoutEntra

        $r.EntraInScope | Should -BeFalse
        $r.ShouldStop   | Should -BeFalse
    }

    It "-SkipEntra -> Graph token never requested" {
        Mock Get-AzContext  { $script:FakeContext }
        Mock Get-GraphToken { "should-not-be-called" }

        $r = Test-AuthenticationPreflight -SkipEntra

        Should -Not -Invoke Get-GraphToken
        $r.EntraRequested | Should -BeFalse
        $r.EntraInScope   | Should -BeFalse
        $r.ShouldStop     | Should -BeFalse
    }

    It "ARM missing -> stop with Connect-AzAccount guidance, Graph not attempted" {
        Mock Get-AzContext  { $null }
        Mock Get-GraphToken { "should-not-be-called" }

        $r = Test-AuthenticationPreflight

        $r.ArmAvailable | Should -BeFalse
        $r.ShouldStop   | Should -BeTrue
        $r.Guidance     | Should -BeLike '*Connect-AzAccount*'
        Should -Not -Invoke Get-GraphToken
    }

    It "never prints or logs the token value" {
        Mock Get-AzContext  { $script:FakeContext }
        Mock Get-GraphToken { "SUPER-SECRET-TOKEN-VALUE" }

        $r = Test-AuthenticationPreflight

        $r.GraphTokenAcquired | Should -BeTrue
        # The token value must not appear anywhere in the result object...
        ($r | ConvertTo-Json -Depth 5) | Should -Not -BeLike '*SUPER-SECRET-TOKEN-VALUE*'
        # ...nor in the log buffer.
        ($script:State.LogBuffer -join "`n") | Should -Not -BeLike '*SUPER-SECRET-TOKEN-VALUE*'
    }
}
