#==============================================================================
# AzureMap v2 - Tests/Shared/Retry.Tests.ps1
# Pester v5 tests for Get-ErrorClass, Test-CircuitBreaker, Update-CircuitBreaker.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    # Test the REAL production functions (Get-ErrorClass, Test-CircuitBreaker,
    # Update-CircuitBreaker). Dot-sourcing Core/Retry.ps1 means the inline
    # fallbacks below are inert (their Get-Command guards see the real commands),
    # so error-class names always match the single production taxonomy.
    . "$projectRoot\Shared\Core\Retry.ps1"

    $script:State = Initialize-AuditState

    # Inline fallbacks retained only for isolation if Core/Retry.ps1 is absent.
    # (Get-ErrorClass now comes from Core/Retry.ps1 - no stale copy here.)

    if (-not (Get-Command -Name "Test-CircuitBreaker" -ErrorAction SilentlyContinue)) {
        function Test-CircuitBreaker {
            $cb = $script:State.CircuitBreaker

            if ($cb.State -eq "Open") {
                $timeSinceOpen = (Get-Date) - $cb.LastFailureTime
                if ($timeSinceOpen.TotalSeconds -ge $cb.OpenDurationSeconds) {
                    $cb.State = "HalfOpen"
                    $cb.HalfOpenProbeInFlight = $false
                    return $true
                } else {
                    return $false
                }
            }

            if ($cb.State -eq "HalfOpen") {
                if ($cb.HalfOpenProbeInFlight) {
                    return $false
                }
                $cb.HalfOpenProbeInFlight = $true
            }

            return $true
        }
    }

    if (-not (Get-Command -Name "Update-CircuitBreaker" -ErrorAction SilentlyContinue)) {
        function Update-CircuitBreaker {
            param([bool]$Success)

            $cb = $script:State.CircuitBreaker

            if ($cb.State -eq "HalfOpen") {
                $cb.HalfOpenProbeInFlight = $false
            }

            if ($Success) {
                if ($cb.State -eq "HalfOpen") {
                    $cb.State        = "Closed"
                    $cb.FailureCount = 0
                } else {
                    $cb.FailureCount = 0
                }
            } else {
                $cb.FailureCount++
                $cb.LastFailureTime = Get-Date

                if ($cb.State -eq "HalfOpen") {
                    $cb.State = "Open"
                } elseif ($cb.FailureCount -ge $cb.FailureThreshold) {
                    $cb.State = "Open"
                }
            }
        }
    }

    # Helper to create mock ErrorRecord objects
    function New-MockErrorRecord {
        param(
            [string]$Message,
            [int]$StatusCode = 0
        )
        $exception = [System.Exception]::new($Message)

        if ($StatusCode -gt 0) {
            $response = [PSCustomObject]@{
                StatusCode = $StatusCode
                Headers    = @{}
            }
            $exception | Add-Member -NotePropertyName "Response" -NotePropertyValue $response -Force
        }

        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            "MockError",
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $null
        )
        return $errorRecord
    }
}

Describe "Get-ErrorClass" {

    It "classifies 401 as Authentication" {
        $err = New-MockErrorRecord -Message "Unauthorized request" -StatusCode 401
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "Authentication"
    }

    It "classifies 429 as Throttling" {
        $err = New-MockErrorRecord -Message "Too many requests" -StatusCode 429
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "Throttling"
    }

    It "classifies 500 as Transient" {
        $err = New-MockErrorRecord -Message "Internal server error" -StatusCode 500
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "Transient"
    }

    It "classifies 503 as Transient" {
        $err = New-MockErrorRecord -Message "ServiceUnavailable" -StatusCode 503
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "Transient"
    }

    It "classifies message-based AuthorizationFailed as Forbidden" {
        $err = New-MockErrorRecord -Message "AuthorizationFailed for resource"
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "Forbidden"
    }

    It "classifies message-based Throttling error without status code" {
        $err = New-MockErrorRecord -Message "TooManyRequests - please slow down"
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "Throttling"
    }

    It "classifies 404 as NotFound" {
        $err = New-MockErrorRecord -Message "Not Found" -StatusCode 404
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "NotFound"
    }

    It "classifies unknown error as Unknown" {
        $err = New-MockErrorRecord -Message "Something completely unexpected"
        $result = Get-ErrorClass -ErrorRecord $err

        $result.Class | Should -Be "Unknown"
    }
}

Describe "Test-CircuitBreaker" {

    BeforeEach {
        $script:State.CircuitBreaker.State                 = "Closed"
        $script:State.CircuitBreaker.FailureCount          = 0
        $script:State.CircuitBreaker.LastFailureTime       = $null
        $script:State.CircuitBreaker.HalfOpenProbeInFlight = $false
    }

    It "allows requests when Closed" {
        Test-CircuitBreaker | Should -BeTrue
    }

    It "blocks requests when Open and within cooldown" {
        $script:State.CircuitBreaker.State           = "Open"
        $script:State.CircuitBreaker.LastFailureTime = Get-Date
        # OpenDurationSeconds defaults to 60, so it's well within cooldown

        Test-CircuitBreaker | Should -BeFalse
    }

    It "transitions from Open to HalfOpen after cooldown expires" {
        $script:State.CircuitBreaker.State           = "Open"
        $script:State.CircuitBreaker.LastFailureTime = (Get-Date).AddSeconds(-120)

        Test-CircuitBreaker | Should -BeTrue
        $script:State.CircuitBreaker.State | Should -Be "HalfOpen"
    }

    It "allows first probe in HalfOpen state" {
        $script:State.CircuitBreaker.State                 = "HalfOpen"
        $script:State.CircuitBreaker.HalfOpenProbeInFlight = $false

        Test-CircuitBreaker | Should -BeTrue
        $script:State.CircuitBreaker.HalfOpenProbeInFlight | Should -BeTrue
    }

    It "blocks second probe in HalfOpen when one is in-flight" {
        $script:State.CircuitBreaker.State                 = "HalfOpen"
        $script:State.CircuitBreaker.HalfOpenProbeInFlight = $true

        Test-CircuitBreaker | Should -BeFalse
    }
}

Describe "Update-CircuitBreaker" {

    BeforeEach {
        $script:State.CircuitBreaker.State                 = "Closed"
        $script:State.CircuitBreaker.FailureCount          = 0
        $script:State.CircuitBreaker.LastFailureTime       = $null
        $script:State.CircuitBreaker.HalfOpenProbeInFlight = $false
        $script:State.CircuitBreaker.FailureThreshold      = 5
    }

    It "resets failure count on success" {
        $script:State.CircuitBreaker.FailureCount = 3
        Update-CircuitBreaker -Success $true

        $script:State.CircuitBreaker.FailureCount | Should -Be 0
        $script:State.CircuitBreaker.State        | Should -Be "Closed"
    }

    It "increments failure count on failure" {
        Update-CircuitBreaker -Success $false

        $script:State.CircuitBreaker.FailureCount | Should -Be 1
    }

    It "opens circuit after reaching failure threshold" {
        $script:State.CircuitBreaker.FailureCount = 4

        Update-CircuitBreaker -Success $false

        $script:State.CircuitBreaker.FailureCount | Should -Be 5
        $script:State.CircuitBreaker.State        | Should -Be "Open"
    }

    It "closes circuit on successful HalfOpen probe" {
        $script:State.CircuitBreaker.State = "HalfOpen"

        Update-CircuitBreaker -Success $true

        $script:State.CircuitBreaker.State        | Should -Be "Closed"
        $script:State.CircuitBreaker.FailureCount | Should -Be 0
    }

    It "reopens circuit on failed HalfOpen probe" {
        $script:State.CircuitBreaker.State = "HalfOpen"

        Update-CircuitBreaker -Success $false

        $script:State.CircuitBreaker.State | Should -Be "Open"
    }
}
