#==============================================================================
# AzureMap v2 - Core/Graph.ps1
# Microsoft Graph REST API engine: token management, single/batch requests,
# auto-pagination, JWT scope validation.
# All functions reference $script:State. Strictly read-only.
#
# READ-ONLY ENFORCEMENT:
#   - Invoke-GraphCommand defaults to GET. Non-GET requires -AllowNonGet flag
#     and emits a WARN-level log.
#   - Invoke-GraphBatch forces every inner request to GET. No exceptions.
#   - The only POST is the outer /$batch envelope itself (required by the
#     Graph batch protocol).
#==============================================================================

function ConvertTo-PlainToken {
    <#
    .SYNOPSIS
        Converts an access token value to a plaintext string in memory.
    .DESCRIPTION
        Current Az.Accounts returns Get-AzAccessToken.Token as a [SecureString].
        Building "Bearer $token" from a SecureString yields the literal
        "System.Security.SecureString", which breaks Graph calls. This converts a
        SecureString to plaintext (in memory only) and wipes the interop buffer.
        A plain string is returned unchanged. The result is NEVER logged, printed,
        or written to exports.
    .OUTPUTS
        [string] plaintext token, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Token
    )

    if ($null -eq $Token) { return $null }

    if ($Token -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    return [string]$Token
}

function Get-GraphToken {
    <#
    .SYNOPSIS
        Acquires (or returns cached) Bearer token for Microsoft Graph.
    .DESCRIPTION
        Uses Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com".
        Handles both legacy (string) and current (SecureString) token shapes,
        converting to plaintext in memory only. Caches the plaintext token in
        $script:State.GraphToken with an expiry timestamp. Refreshes automatically
        when < 5 minutes remain. The token value is never logged or printed.
    .OUTPUTS
        [string] The access token string.
    #>
    [CmdletBinding()]
    param(
        [switch]$ForceRefresh
    )

    $now = Get-Date

    if (-not $ForceRefresh `
        -and $script:State.GraphToken `
        -and $script:State.GraphTokenExpiry `
        -and $script:State.GraphTokenExpiry -gt $now.AddMinutes(5)) {
        return $script:State.GraphToken
    }

    Write-AuditLog -Message "Acquiring Microsoft Graph access token..." -Level INFO

    $tokenResponse = Invoke-AzureCommand -Command {
        Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    } -CommandName "Get-GraphToken" -SkipContextCheck -Critical

    # Token may be a [SecureString] (current Az.Accounts) or a [string] (legacy).
    # Normalize to plaintext in memory; never log or print the value.
    $script:State.GraphToken       = ConvertTo-PlainToken -Token $tokenResponse.Token
    $script:State.GraphTokenExpiry = $tokenResponse.ExpiresOn.UtcDateTime

    Write-AuditLog -Message "Graph token acquired, expires $($script:State.GraphTokenExpiry) UTC" -Level INFO

    return $script:State.GraphToken
}

function Test-GraphTokenScopes {
    <#
    .SYNOPSIS
        Decodes the cached JWT and validates required permissions.
    .DESCRIPTION
        Base64-decodes the token payload, extracts 'roles' (application) or
        'scp' (delegated) claims, and checks against RequiredScopes.
    .PARAMETER RequiredScopes
        Array of permission strings to validate (e.g. "Directory.Read.All").
    .OUTPUTS
        [PSCustomObject] with GrantedScopes, MissingScopes, IsValid properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$RequiredScopes
    )

    $token = Get-GraphToken
    if (-not $token) {
        return [PSCustomObject]@{
            GrantedScopes = @()
            MissingScopes = $RequiredScopes
            IsValid       = $false
        }
    }

    try {
        $parts   = $token.Split('.')
        $payload = $parts[1]

        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '='  }
        }
        $payload = $payload.Replace('-', '+').Replace('_', '/')

        $decoded = [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String($payload)
        )
        $claims = $decoded | ConvertFrom-Json -ErrorAction Stop

        $grantedScopes = @()
        if ($claims.roles) {
            $grantedScopes += @($claims.roles)
        }
        if ($claims.scp) {
            $grantedScopes += @($claims.scp -split ' ')
        }

        $missing = @($RequiredScopes | Where-Object { $_ -notin $grantedScopes })

        if ($missing.Count -gt 0) {
            Write-AuditLog -Message "Graph token missing scopes: $($missing -join ', ')" -Level WARN
        }

        return [PSCustomObject]@{
            GrantedScopes = $grantedScopes
            MissingScopes = $missing
            IsValid       = ($missing.Count -eq 0)
        }
    }
    catch {
        Write-AuditLog -Message "Failed to decode Graph JWT: $_" -Level WARN
        return [PSCustomObject]@{
            GrantedScopes = @()
            MissingScopes = $RequiredScopes
            IsValid       = $false
        }
    }
}

function Invoke-GraphCommand {
    <#
    .SYNOPSIS
        Executes a single Graph REST API request with auto-pagination.
    .DESCRIPTION
        Default method is GET. Any non-GET method is BLOCKED unless the caller
        passes -AllowNonGet, in which case a WARN is logged.  The only
        legitimate non-GET in AzureMap is the internal /$batch POST (which is
        handled by Invoke-GraphBatch, not this function).
    .PARAMETER Uri
        Graph API path (e.g. "/users"). Scheme/host prefixed automatically.
    .PARAMETER Method
        HTTP method. Defaults to GET. Non-GET requires -AllowNonGet.
    .PARAMETER Body
        Request body hashtable (converted to JSON for POST).
    .PARAMETER ApiVersion
        "v1.0" (default) or "beta".
    .PARAMETER AllPages
        Follow @odata.nextLink to retrieve all pages.
    .PARAMETER AllowNonGet
        Explicit opt-in to use a method other than GET. Logs a WARN.
    .OUTPUTS
        Array of result objects (the 'value' arrays concatenated across pages).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$Method = "GET",

        [hashtable]$Body,

        [ValidateSet("v1.0","beta")]
        [string]$ApiVersion = "v1.0",

        [switch]$AllPages,

        [switch]$AllowNonGet,

        [string]$CommandName
    )

    # --- Read-only enforcement ---
    if ($Method -ne "GET") {
        if (-not $AllowNonGet) {
            Write-AuditLog -Message "BLOCKED: Invoke-GraphCommand called with Method=$Method on $Uri without -AllowNonGet. Forcing GET." -Level ERROR
            $Method = "GET"
        }
        else {
            Write-AuditLog -Message "Non-GET Graph call permitted via -AllowNonGet: $Method $Uri" -Level WARN
        }
    }

    $token   = Get-GraphToken
    $baseUrl = "https://graph.microsoft.com/$ApiVersion"
    $fullUrl = if ($Uri.StartsWith("http")) { $Uri } else { "$baseUrl$Uri" }

    $headers = @{
        "Authorization"    = "Bearer $token"
        "ConsistencyLevel" = "eventual"
        "User-Agent"       = "AzureMap/2.0"
        "Accept"           = "application/json"
        "Content-Type"     = "application/json"
    }

    $allResults = [System.Collections.Generic.List[object]]::new()
    $nextLink   = $fullUrl

    do {
        $currentUrl = $nextLink
        $nextLink   = $null

        $response = Invoke-AzureCommand -Command {
            $params = @{
                Uri     = $currentUrl
                Method  = $Method
                Headers = $headers
                # Explicit (not just the session pin): PS 5.1 prompts with an
                # interactive "Script Execution Risk" dialog without this.
                UseBasicParsing = $true
            }
            if ($Body -and $Method -ne "GET") {
                $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
            }
            $raw = Invoke-RestMethod @params -ErrorAction Stop
            $raw
        } -CommandName ($(if ($CommandName) { $CommandName } else { "Graph:$Method $Uri" })) -SkipContextCheck

        if ($response.value) {
            foreach ($item in $response.value) {
                $allResults.Add($item)
            }
        }
        elseif ($null -ne $response -and -not $response.PSObject.Properties['value']) {
            $allResults.Add($response)
        }

        if ($AllPages -and $response.'@odata.nextLink') {
            $nextLink = $response.'@odata.nextLink'
        }

    } while ($nextLink)

    return $allResults.ToArray()
}

function Invoke-GraphBatch {
    <#
    .SYNOPSIS
        Sends read-only batch requests to the Graph /$batch endpoint.
    .DESCRIPTION
        Accepts an array of request descriptors @{id; method; url}.
        EVERY inner request is forced to GET regardless of what the caller
        passes -- this is the read-only safety guarantee.
        Chunks into groups of 20 (Graph batch limit).
        The outer POST to /$batch is the Graph batch protocol and does not
        modify any resources.
    .PARAMETER Requests
        Array of hashtables, each with: id (string), url (string).
        The 'method' key is ignored and overridden to GET.
    .PARAMETER ApiVersion
        "v1.0" (default) or "beta".
    .PARAMETER CommandName
        Label used in retry/log output.
    .OUTPUTS
        [hashtable] Keyed by request id, values are the response body objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Requests,

        [ValidateSet("v1.0","beta")]
        [string]$ApiVersion = "v1.0",

        [string]$CommandName = "GraphBatch"
    )

    $token    = Get-GraphToken
    $batchUrl = "https://graph.microsoft.com/$ApiVersion/`$batch"
    $headers  = @{
        "Authorization"    = "Bearer $token"
        "ConsistencyLevel" = "eventual"
        "User-Agent"       = "AzureMap/2.0"
        "Accept"           = "application/json"
        "Content-Type"     = "application/json"
    }

    $chunkSize = 20
    $results   = @{}

    for ($i = 0; $i -lt $Requests.Count; $i += $chunkSize) {
        $end   = [Math]::Min($i + $chunkSize - 1, $Requests.Count - 1)
        $chunk = $Requests[$i..$end]

        # Build batch body -- ALL inner requests are forced to GET.
        $batchBody = @{
            requests = @($chunk | ForEach-Object {
                @{
                    id     = [string]$_.id
                    method = "GET"
                    url    = [string]$_.url
                }
            })
        }

        $bodyJson = $batchBody | ConvertTo-Json -Depth 10 -Compress

        $response = Invoke-AzureCommand -Command {
            Invoke-RestMethod -Uri $batchUrl -Method POST -Headers $headers `
                -Body $bodyJson -UseBasicParsing -ErrorAction Stop
        } -CommandName "$CommandName ($($chunk.Count) reqs)" -SkipContextCheck

        if ($response.responses) {
            foreach ($resp in $response.responses) {
                $status = 0
                if (($resp.PSObject.Properties.Name -contains 'status') -and ($null -ne $resp.status)) {
                    try { $status = [int]$resp.status } catch { $status = 0 }
                }

                $body = $null
                if ($resp.PSObject.Properties.Name -contains 'body') { $body = $resp.body }

                $isSuccess = ($status -ge 200 -and $status -lt 300)

                # Shaped result so consumers can distinguish a failed subresponse
                # (Success=$false, Data=$null, Error populated) from a successful
                # response that legitimately has empty data (Success=$true).
                $results[[string]$resp.id] = [PSCustomObject]@{
                    Success = $isSuccess
                    Status  = $status
                    Data    = if ($isSuccess) { $body } else { $null }
                    Error   = if ($isSuccess) { $null } else { $body }
                }
            }
        }
    }

    return $results
}
