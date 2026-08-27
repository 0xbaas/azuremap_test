#==============================================================================
# AzureMap v2 - Core/Exclusions.ps1
# Load and evaluate exclusion rules (Resources, Findings, Subscriptions, Tags).
# All functions reference $script:State.
#==============================================================================

function Load-Exclusions {
    <#
    .SYNOPSIS
        Loads a JSON exclusion/baseline file with four dimensions.
    .DESCRIPTION
        Reads a JSON file and populates $script:State.Exclusions with:
          - Resources     : array of {ResourceId, NamePattern}
          - Findings      : array of {Pattern, Severity}
          - Subscriptions : array of subscription IDs
          - Tags          : array of {Key, Value} pairs
    .OUTPUTS
        [hashtable] The loaded exclusions (also stored in $script:State.Exclusions).
    #>
    [CmdletBinding()]
    param(
        [string]$ExclusionPath
    )

    $exclusions = @{
        Resources     = @()
        Findings      = @()
        Subscriptions = @()
        Tags          = @()
        FindingIds    = @()
        Principals    = @()
    }

    if (-not [string]::IsNullOrEmpty($ExclusionPath) -and (Test-Path $ExclusionPath)) {
        try {
            $exclusionData = Get-Content $ExclusionPath -Raw | ConvertFrom-Json -ErrorAction Stop

            if ($exclusionData.Resources) {
                $exclusions.Resources = @($exclusionData.Resources)
            }
            if ($exclusionData.Findings) {
                $exclusions.Findings = @($exclusionData.Findings)
            }
            if ($exclusionData.Subscriptions) {
                $exclusions.Subscriptions = @($exclusionData.Subscriptions)
            }
            if ($exclusionData.Tags) {
                $exclusions.Tags = @($exclusionData.Tags)
            }
            if ($exclusionData.FindingIds) {
                $exclusions.FindingIds = @($exclusionData.FindingIds)
            }
            if ($exclusionData.Principals) {
                $exclusions.Principals = @($exclusionData.Principals)
            }

            Write-AuditLog -Message "Loaded exclusions from $ExclusionPath" -Level INFO
        }
        catch {
            Write-AuditLog -Message "Failed to load exclusions from ${ExclusionPath}: $_" -Level WARN
        }
    }

    $script:State.Exclusions = $exclusions
    return $exclusions
}

function Test-Exclusion {
    <#
    .SYNOPSIS
        Checks whether a finding matches any exclusion rule.
    .DESCRIPTION
        Evaluates the finding against four exclusion dimensions:
          1. Subscription ID match
          2. Resource ID or name-pattern match
          3. Tag key/value match
          4. Finding pattern + severity match
    .OUTPUTS
        [bool] $true if the finding should be excluded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding,

        [Parameter(Mandatory)]
        [hashtable]$Exclusions
    )

    # This function reads many OPTIONAL keys on both $Finding and $Exclusions
    # (Resources, Tags, Findings, FindingIds, Principals, ResourceId, etc.). Under
    # Windows PowerShell 5.1 StrictMode, a missing key/property throws; relax to
    # soft member access for this function's scope so absent keys read as $null.
    Set-StrictMode -Off

    # 1. Subscription exclusion by ID
    if ($Finding.SubscriptionId -and $Exclusions.Subscriptions -contains $Finding.SubscriptionId) {
        return $true
    }

    # 2. Resource exclusion by ID or name pattern
    if ($Finding.ResourceId -or $Finding.ResourceName) {
        foreach ($exclusion in $Exclusions.Resources) {
            if ($exclusion.ResourceId -and $Finding.ResourceId -like $exclusion.ResourceId) {
                return $true
            }
            if ($exclusion.NamePattern -and $Finding.ResourceName -like $exclusion.NamePattern) {
                return $true
            }
        }
    }

    # 3. Tag exclusions with key/value matching
    $tagsCount = if ($Exclusions.Tags) { ($Exclusions.Tags | Measure-Object).Count } else { 0 }
    if ($Finding.Tags -and $Finding.Tags.Count -gt 0 -and $tagsCount -gt 0) {
        foreach ($tagExclusion in $Exclusions.Tags) {
            if ($tagExclusion.Key -and $Finding.Tags.ContainsKey($tagExclusion.Key)) {
                $tagValue = $Finding.Tags[$tagExclusion.Key]
                if (-not $tagExclusion.Value -or $tagValue -like $tagExclusion.Value) {
                    return $true
                }
            }
        }
    }

    # 4. Finding type exclusion (pattern + severity)
    foreach ($exclusion in $Exclusions.Findings) {
        if ($Finding.Finding -like $exclusion.Pattern -and
            $Finding.Severity -eq $exclusion.Severity) {
            return $true
        }
    }

    # 5. FindingId exclusion (baseline suppression)
    # Guard property existence: Windows PowerShell 5.1 StrictMode throws on a
    # missing property, and callers may pass a partial finding object.
    if (($Finding.PSObject.Properties.Name -contains 'FindingId') -and $Finding.FindingId -and $Exclusions.FindingIds) {
        if ($Exclusions.FindingIds -contains $Finding.FindingId.ToString()) {
            return $true
        }
    }

    # 6. Principal exclusion (for Entra checks — exclude known service accounts etc.)
    if ($Exclusions.Principals -and $Finding.Evidence) {
        foreach ($principalExclusion in $Exclusions.Principals) {
            foreach ($ev in $Finding.Evidence) {
                if ($ev.PSObject.Properties['PrincipalId'] -and
                    $ev.PrincipalId -eq $principalExclusion) {
                    return $true
                }
                if ($ev.PSObject.Properties['SPId'] -and
                    $ev.SPId -eq $principalExclusion) {
                    return $true
                }
            }
        }
    }

    return $false
}
