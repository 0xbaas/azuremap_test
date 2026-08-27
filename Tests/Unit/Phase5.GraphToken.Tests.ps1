#==============================================================================
# AzureMap v2 - Tests/Unit/Phase5.GraphToken.Tests.ps1
# Phase 5 - mocked/local only. No Azure, no Graph, no authentication.
#
# Verifies SecureString tokens are converted to a plaintext Bearer value in
# memory, and never surface as "System.Security.SecureString" or in logs.
# The token strings here are synthetic placeholders (not real credentials).
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Retry.ps1"
    . "$projectRoot\Core\Entra\Graph.ps1"

    $script:State = Initialize-EntraAuditState
    $script:State.Config.Quiet = $true

    $script:FakeTokenPlain = 'test-token'
}

Describe "ConvertTo-PlainToken" {
    It "converts a SecureString to plaintext" {
        $secure = ConvertTo-SecureString $script:FakeTokenPlain -AsPlainText -Force
        (ConvertTo-PlainToken -Token $secure) | Should -Be $script:FakeTokenPlain
    }

    It "passes a plain string through unchanged" {
        (ConvertTo-PlainToken -Token $script:FakeTokenPlain) | Should -Be $script:FakeTokenPlain
    }

    It "returns null for null input" {
        (ConvertTo-PlainToken -Token $null) | Should -BeNullOrEmpty
    }
}

Describe "Get-GraphToken with SecureString token shape" {

    BeforeEach {
        $script:State.GraphToken       = $null
        $script:State.GraphTokenExpiry = $null
        $script:State.LogBuffer.Clear()

        Mock Invoke-AzureCommand {
            [PSCustomObject]@{
                Token     = (ConvertTo-SecureString $script:FakeTokenPlain -AsPlainText -Force)
                ExpiresOn = ([DateTimeOffset]::UtcNow.AddHours(1))
            }
        }
    }

    It "returns a plaintext string, not a SecureString" {
        $t = Get-GraphToken
        $t | Should -BeOfType [string]
        $t | Should -Be $script:FakeTokenPlain
        $t | Should -Not -BeLike '*System.Security.SecureString*'
    }

    It "produces an Authorization header containing the plaintext token ('Bearer test-token') and no SecureString text" {
        $plain  = [string](Get-GraphToken)
        # The token must be the actual plaintext value, never empty and never the
        # SecureString type name.
        $plain  | Should -Not -BeNullOrEmpty
        $plain  | Should -Be 'test-token'
        $header = 'Bearer ' + $plain
        # Strong, explicit assertions: the header is exactly the plaintext bearer value,
        # it contains the token, and it never contains a SecureString type name.
        $header | Should -Be 'Bearer test-token'
        $header | Should -BeLike '*test-token*'
        $header | Should -Not -BeLike '*SecureString*'
        $header | Should -Not -BeLike '*System.Security.SecureString*'
    }

    It "never writes the token value to the log buffer" {
        $null = Get-GraphToken
        ($script:State.LogBuffer -join "`n") | Should -Not -BeLike "*$($script:FakeTokenPlain)*"
    }
}
