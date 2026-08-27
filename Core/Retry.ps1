#==============================================================================
# AzureMap v2 - Core/Retry.ps1
# Error classification, circuit breaker, and Azure command retry wrapper.
# All functions reference $script:State.
#==============================================================================

function Get-ErrorClass {
    <#
    .SYNOPSIS
        Classifies an error record into Authentication, Forbidden, Throttling,
        NotFound, Transient, or Unknown.
    .DESCRIPTION
        Defensive: does NOT assume Exception.Response exists. Reads a status code
        from Exception.Response.StatusCode when present, otherwise Exception.StatusCode,
        otherwise falls back to matching the message text. Never calls Connect-AzAccount.
    .OUTPUTS
        [hashtable] @{ Class = <string>; RetryAfter = <int|null> }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception    = $ErrorRecord.Exception
    $errorMessage = if ($exception) { [string]$exception.Message } else { '' }
    $statusCode   = $null
    $retryAfter   = $null

    # Safely probe for a Response property (many exceptions do not have one).
    $response = $null
    if ($exception -and ($exception.PSObject.Properties.Name -contains 'Response') -and $exception.Response) {
        $response = $exception.Response
    }

    if ($response) {
        if (($response.PSObject.Properties.Name -contains 'StatusCode') -and ($null -ne $response.StatusCode)) {
            try { $statusCode = [int]$response.StatusCode } catch { }
        }
        if (($response.PSObject.Properties.Name -contains 'Headers') -and $response.Headers) {
            try {
                $ra = $response.Headers['Retry-After']
                if ($ra) { $retryAfter = [int]$ra }
            } catch { }
        }
    }

    # Some Azure exceptions expose StatusCode directly on the exception.
    if (($null -eq $statusCode) -and $exception -and
        ($exception.PSObject.Properties.Name -contains 'StatusCode') -and ($null -ne $exception.StatusCode)) {
        try { $statusCode = [int]$exception.StatusCode } catch { }
    }

    # Classify (status code first, then message text). Order matters:
    # 401 before 403 so "Unauthorized" is not mistaken for "AuthorizationFailed".
    # The Authentication set also covers interactive/MFA/Conditional-Access re-auth
    # failures (e.g. Get-AzAccessToken for Graph). These must be Authentication so the
    # retry wrapper surfaces guidance and does NOT retry (no 2s/4s loop). The tokens
    # below are deliberately distinct from 403 "AuthorizationFailed".
    if ($statusCode -eq 401 -or $errorMessage -match '(?i)(\b401\b|Unauthorized|expired token|token expired|invalid token|InvalidAuthenticationToken|interaction_required|user interaction is required|Authentication failed|AADSTS\d+|rerun Connect-AzAccount|AuthScope|multi-?factor|Conditional Access|DeviceCodeFlow|acquire a token)') {
        return @{ Class = "Authentication"; RetryAfter = $null }
    }

    if ($statusCode -eq 403 -or $errorMessage -match '(?i)(\b403\b|AuthorizationFailed|Forbidden|insufficient privileges|InsufficientPrivileges|Authorization_RequestDenied)') {
        return @{ Class = "Forbidden"; RetryAfter = $null }
    }

    if ($statusCode -eq 429 -or $errorMessage -match '(?i)(\b429\b|TooManyRequests|Throttl)') {
        return @{ Class = "Throttling"; RetryAfter = $retryAfter }
    }

    if ($statusCode -eq 404 -or $errorMessage -match '(?i)(\b404\b|NotFound|ResourceNotFound)') {
        return @{ Class = "NotFound"; RetryAfter = $null }
    }

    if (($statusCode -ge 500 -and $statusCode -lt 600) -or
        $errorMessage -match '(?i)(\b5\d{2}\b|InternalServerError|ServiceUnavailable|BadGateway|GatewayTimeout|TemporarilyUnavailable|Timeout|OperationTimedOut)') {
        return @{ Class = "Transient"; RetryAfter = $null }
    }

    return @{ Class = "Unknown"; RetryAfter = $null }
}

function Test-CircuitBreaker {
    <#
    .SYNOPSIS
        Three-state circuit breaker gate (Closed / Open / HalfOpen).
    .DESCRIPTION
        Returns $true if the call should be allowed, $false if rejected.
        Transitions Open -> HalfOpen after OpenDurationSeconds elapses.
        Only one HalfOpen probe is allowed in flight at a time.
    #>
    [CmdletBinding()]
    param()

    $cb = $script:State.CircuitBreaker

    if ($cb.State -eq "Open") {
        $timeSinceOpen = (Get-Date) - $cb.LastFailureTime
        if ($timeSinceOpen.TotalSeconds -ge $cb.OpenDurationSeconds) {
            $cb.State = "HalfOpen"
            $cb.HalfOpenProbeInFlight = $false
            Write-AuditLog -Message "Circuit breaker: Moving to HalfOpen state (testing recovery)" -Level INFO
            return $true
        }
        else {
            return $false
        }
    }

    if ($cb.State -eq "HalfOpen") {
        if ($cb.HalfOpenProbeInFlight) {
            return $false
        }
        $cb.HalfOpenProbeInFlight = $true
    }

    return $true   # Closed or HalfOpen (probe slot available)
}

function Update-CircuitBreaker {
    <#
    .SYNOPSIS
        Updates circuit breaker state on success or failure.
    .DESCRIPTION
        On success: HalfOpen -> Closed (reset), or reset failure count.
        On failure: increment count, HalfOpen -> Open, or Closed -> Open
        when threshold is reached.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool]$Success
    )

    $cb = $script:State.CircuitBreaker

    if ($cb.State -eq "HalfOpen") {
        $cb.HalfOpenProbeInFlight = $false
    }

    if ($Success) {
        if ($cb.State -eq "HalfOpen") {
            $cb.State        = "Closed"
            $cb.FailureCount = 0
            Write-AuditLog -Message "Circuit breaker: Recovery successful, closing circuit" -Level INFO
        }
        else {
            $cb.FailureCount = 0
        }
    }
    else {
        $cb.FailureCount++
        $cb.LastFailureTime = Get-Date

        if ($cb.State -eq "HalfOpen") {
            $cb.State = "Open"
            Write-AuditLog -Message "Circuit breaker: HalfOpen probe failed, reopening circuit" -Level ERROR
        }
        elseif ($cb.FailureCount -ge $cb.FailureThreshold) {
            $cb.State = "Open"
            Write-AuditLog -Message "Circuit breaker: OPENED after $($cb.FailureCount) failures. Will retry after $($cb.OpenDurationSeconds) seconds." -Level ERROR -ForceConsole
        }
    }
}

function Invoke-AzureCommand {
    <#
    .SYNOPSIS
        Retry wrapper with circuit breaker, throttle backoff, and auth recovery.
    .DESCRIPTION
        Executes a scriptblock with automatic retries based on error classification:
          - Authentication: NO auto-login; surfaces clean guidance and the original error
          - Forbidden: never retried, never reconnects
          - Throttling: exponential backoff with Retry-After respect
          - Transient: linear backoff, feeds circuit breaker
          - NotFound / Unknown: retry only if -Critical
        Checks circuit breaker before each attempt. Never calls Connect-AzAccount.
    .PARAMETER Command
        The scriptblock to execute.
    .PARAMETER CommandName
        Friendly name for logging.
    .PARAMETER MaxRetries
        Override for $script:State.Config.MaxRetryAttempts.
    .PARAMETER Critical
        If set, client errors (4xx) will also be retried.
    .PARAMETER SkipContextCheck
        Skip the Get-AzContext validation before execution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$Command,

        [string]$CommandName = "AzureCommand",

        [int]$MaxRetries = $script:State.Config.MaxRetryAttempts,

        [switch]$Critical,
        [switch]$SkipContextCheck
    )

    if (-not (Test-CircuitBreaker)) {
        throw "Circuit breaker is OPEN - Azure service appears unavailable. Last failure: $($script:State.CircuitBreaker.LastFailureTime)"
    }

    $retryCount = 0
    $lastError  = $null

    while ($retryCount -le $MaxRetries) {
        try {
            if (-not $SkipContextCheck) {
                $context = Get-AzContext -ErrorAction SilentlyContinue
                if (-not $context) {
                    # Do NOT auto-login. Sign-in is validated by the authentication
                    # preflight before checks run; surface a clean actionable error.
                    throw "No Azure Resource Manager context for $CommandName. Run 'Connect-AzAccount' and re-run AzureMap."
                }
            }

            $result = & $Command
            Update-CircuitBreaker -Success $true
            return $result
        }
        catch [Microsoft.Azure.Commands.Common.Authentication.AadAuthenticationCanceledException] {
            $lastError = $_
            Write-AuditLog -Message "Authentication canceled for $CommandName" -Level ERROR
            throw "Authentication failed: $($_.Exception.Message)"
        }
        catch {
            $lastError  = $_
            $errorClass = Get-ErrorClass -ErrorRecord $_

            # Authentication errors (401 / expired token): NEVER auto-login and NEVER
            # loop. Surface clean guidance and let the original error propagate so the
            # orchestrator records it as an Error. Forbidden (403 / AuthorizationFailed)
            # likewise never reconnects - it simply falls through to the throw below.
            if ($errorClass.Class -eq "Authentication") {
                Write-AuditLog -Message "Authentication failed for $CommandName. Run 'Connect-AzAccount' (and 'Connect-AzAccount -AuthScope `"https://graph.microsoft.com`"' for Entra checks), then re-run AzureMap." -Level ERROR
                throw $_
            }

            if ($retryCount -lt $MaxRetries) {
                # Throttling - exponential backoff with Retry-After
                if ($errorClass.Class -eq "Throttling") {
                    $delay = $script:State.Config.RetryDelaySeconds * [Math]::Pow(2, $retryCount) + (Get-Random -Minimum 0 -Maximum 1000) / 1000

                    if ($errorClass.RetryAfter -and $errorClass.RetryAfter -gt 0) {
                        $delay = [Math]::Min($errorClass.RetryAfter, $script:State.Config.MaxRetryDelaySeconds)
                        Write-AuditLog -Message "Throttled on $CommandName, respecting Retry-After: $delay seconds" -Level WARN
                    }
                    else {
                        Write-AuditLog -Message "Throttled on $CommandName, retrying in $delay seconds (attempt $($retryCount+1)/$($MaxRetries+1))" -Level WARN
                    }

                    Start-Sleep -Seconds $delay
                    $retryCount++
                    continue
                }

                # Transient service errors (5xx / timeouts) - linear backoff
                if ($errorClass.Class -eq "Transient") {
                    $delay = $script:State.Config.RetryDelaySeconds * ($retryCount + 1)
                    Write-AuditLog -Message "Transient error on $CommandName, retrying in $delay seconds" -Level WARN
                    Start-Sleep -Seconds $delay
                    $retryCount++
                    continue
                }

                # Other retryable-if-Critical cases (NotFound / Unknown). Forbidden is
                # never retried here (a permission error will not resolve by retrying).
                if ($Critical -and ($errorClass.Class -eq "NotFound" -or $errorClass.Class -eq "Unknown")) {
                    $delay = $script:State.Config.RetryDelaySeconds * ($retryCount + 1)
                    Write-AuditLog -Message "$($errorClass.Class) error on $CommandName`: $($_.Exception.Message), retrying in $delay seconds" -Level WARN
                    Start-Sleep -Seconds $delay
                    $retryCount++
                    continue
                }
            }

            # Non-retryable or exhausted
            if ($errorClass.Class -eq "Transient") {
                Update-CircuitBreaker -Success $false
            }
            throw $_
        }
    }

    # Max retries exceeded
    Update-CircuitBreaker -Success $false
    throw "Max retries ($MaxRetries) exceeded for $CommandName. Last error: $($lastError.Exception.Message)"
}
