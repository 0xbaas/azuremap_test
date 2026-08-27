#==============================================================================
# AzureMap v2 - Core/ResourceGraph.ps1
# Cross-subscription KQL query engine via Azure Resource Graph.
# Falls back to Search-AzGraph if Az.ResourceGraph is available.
# All functions reference $script:State. Strictly read-only.
#==============================================================================

function Invoke-ResourceGraphQuery {
    <#
    .SYNOPSIS
        Executes a KQL query across subscriptions via Azure Resource Graph.
    .DESCRIPTION
        Primary path: Invoke-AzRestMethod POST to the Resource Graph REST API
        with $skipToken pagination.
        Fallback: If Az.ResourceGraph module is loaded, uses Search-AzGraph.
        All calls are wrapped in Invoke-AzureCommand for retry/CB support.
    .PARAMETER Query
        The KQL query string.
    .PARAMETER SubscriptionIds
        Array of subscription IDs to scope the query. If omitted the current
        context subscription is used.
    .PARAMETER First
        Maximum result count per page (default 1000, max 1000).
    .OUTPUTS
        Array of result objects across all pages.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [string[]]$SubscriptionIds,

        [int]$First = 1000
    )

    $allResults = [System.Collections.Generic.List[object]]::new()

    # --- Try Az.ResourceGraph module first if available ---
    $argModule = Get-Module -Name "Az.ResourceGraph" -ListAvailable -ErrorAction SilentlyContinue
    if ($argModule) {
        Write-AuditLog -Message "Using Search-AzGraph for Resource Graph query" -Level DEBUG
        try {
            $results = Invoke-AzureCommand -Command {
                $params = @{
                    Query = $Query
                    First = $First
                    ErrorAction = 'Stop'
                }
                if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
                    $params.Subscription = $SubscriptionIds
                }
                Search-AzGraph @params
            } -CommandName "Search-AzGraph" -SkipContextCheck

            if ($results) {
                foreach ($row in $results) {
                    $allResults.Add($row)
                }
            }
            return $allResults.ToArray()
        }
        catch {
            Write-AuditLog -Message "Search-AzGraph failed, falling back to REST API: $_" -Level WARN
        }
    }

    # --- REST API path ---
    $apiVersion = "2022-10-01"
    $restUri    = "/providers/Microsoft.ResourceGraph/resources?api-version=$apiVersion"
    $skipToken  = $null

    do {
        $body = @{
            query   = $Query
            options = @{
                "`$top" = $First
                resultFormat = "objectArray"
            }
        }

        if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
            $body.subscriptions = @($SubscriptionIds)
        }

        if ($skipToken) {
            $body.options.'$skipToken' = $skipToken
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress

        $response = Invoke-AzureCommand -Command {
            $restResult = Invoke-AzRestMethod -Path $restUri -Method POST -Payload $bodyJson -ErrorAction Stop
            if ($restResult.StatusCode -ge 400) {
                throw "Resource Graph API returned status $($restResult.StatusCode): $($restResult.Content)"
            }
            $restResult.Content | ConvertFrom-Json -ErrorAction Stop
        } -CommandName "ResourceGraph:REST" -SkipContextCheck

        $skipToken = $null

        if ($response.data) {
            foreach ($row in $response.data) {
                $allResults.Add($row)
            }
        }

        if ($response.'$skipToken') {
            $skipToken = $response.'$skipToken'
        }

    } while ($skipToken)

    Write-AuditLog -Message "Resource Graph query returned $($allResults.Count) results" -Level DEBUG

    return $allResults.ToArray()
}
