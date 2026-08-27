#==============================================================================
# AzureMap v2 - Tests/Unit/Phase6.ErrorClass.Tests.ps1
# Phase 6 - mocked/local only. No Azure, no Graph, no authentication.
#
# Verifies defensive error classification and that Forbidden (403) never
# triggers an automatic Connect-AzAccount in the retry wrapper.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Retry.ps1"

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet = $true

    function New-Err {
        param([string]$Message, [int]$StatusCode = 0, [switch]$OnException)
        $ex = [System.Exception]::new($Message)
        if ($StatusCode -gt 0) {
            if ($OnException) {
                $ex | Add-Member -NotePropertyName StatusCode -NotePropertyValue $StatusCode -Force
            } else {
                $resp = [PSCustomObject]@{ StatusCode = $StatusCode; Headers = @{} }
                $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp -Force
            }
        }
        [System.Management.Automation.ErrorRecord]::new(
            $ex, "Mock", [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
    }

    # Stub so the retry wrapper's reconnect path can be mocked/observed.
    function Connect-AzAccount { param([Parameter(ValueFromRemainingArguments)]$Rest) }
}

Describe "Get-ErrorClass - defensive classification" {

    It "does not assume Exception.Response exists (message-only exception)" {
        $err = New-Err -Message "Something completely unexpected"
        { Get-ErrorClass -ErrorRecord $err } | Should -Not -Throw
        (Get-ErrorClass -ErrorRecord $err).Class | Should -Be "Unknown"
    }

    It "Response.StatusCode 401 -> Authentication" {
        (Get-ErrorClass -ErrorRecord (New-Err -Message "denied" -StatusCode 401)).Class | Should -Be "Authentication"
    }

    It "Response.StatusCode 403 -> Forbidden" {
        (Get-ErrorClass -ErrorRecord (New-Err -Message "denied" -StatusCode 403)).Class | Should -Be "Forbidden"
    }

    It "Exception.StatusCode (no Response) 429 -> Throttling" {
        (Get-ErrorClass -ErrorRecord (New-Err -Message "slow down" -StatusCode 429 -OnException)).Class | Should -Be "Throttling"
    }

    It "plain message AuthorizationFailed -> Forbidden" {
        (Get-ErrorClass -ErrorRecord (New-Err -Message "AuthorizationFailed: insufficient privileges")).Class | Should -Be "Forbidden"
    }

    It "plain message TooManyRequests -> Throttling" {
        (Get-ErrorClass -ErrorRecord (New-Err -Message "TooManyRequests, retry later")).Class | Should -Be "Throttling"
    }

    It "404 -> NotFound" {
        (Get-ErrorClass -ErrorRecord (New-Err -Message "Not Found" -StatusCode 404)).Class | Should -Be "NotFound"
    }

    It "5xx -> Transient" {
        (Get-ErrorClass -ErrorRecord (New-Err -Message "BadGateway" -StatusCode 502)).Class | Should -Be "Transient"
    }
}

Describe "Retry wrapper - Forbidden does not reconnect" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        Mock Connect-AzAccount { }
    }

    It "403 Forbidden throws and never calls Connect-AzAccount" {
        $threw = $false
        try {
            Invoke-AzureCommand -CommandName "probe" -SkipContextCheck -Command {
                throw (New-Object System.Exception "403 Forbidden: AuthorizationFailed")
            }
        } catch {
            $threw = $true
        }
        $threw | Should -BeTrue
        Should -Not -Invoke Connect-AzAccount
    }

    It "401 Authentication does not auto-login and does not retry in a loop" {
        # Use a generic System.Exception (no Azure-specific exception types) and
        # count command invocations to prove there is no retry loop. We do not
        # assert on the re-thrown message, because the wrapper's typed catch clause
        # for an Az-specific exception type is not resolvable in environments where
        # the Az modules are not loaded (that type only exists at production runtime).
        $script:Invoke401Count = 0
        $threw = $false
        try {
            Invoke-AzureCommand -CommandName "probe401" -Critical -SkipContextCheck -Command {
                $script:Invoke401Count++
                throw (New-Object System.Exception "401 Unauthorized: token expired")
            }
        } catch {
            $threw = $true
        }

        $threw                  | Should -BeTrue
        Should -Not -Invoke Connect-AzAccount
        $script:Invoke401Count  | Should -Be 1   # invoked once => no retry loop
    }

    It "a synthetic 401 error is classified as Authentication (classification preserved)" {
        $err = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("401 Unauthorized: token expired"),
            "x", [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
        (Get-ErrorClass -ErrorRecord $err).Class | Should -Be "Authentication"
    }

    It "no automatic Connect-AzAccount for any classification (401 + 403)" {
        foreach ($m in @("401 Unauthorized", "403 AuthorizationFailed")) {
            try {
                Invoke-AzureCommand -CommandName "probe" -SkipContextCheck -Command {
                    throw (New-Object System.Exception $m)
                }
            } catch { }
        }
        Should -Not -Invoke Connect-AzAccount
    }
}
