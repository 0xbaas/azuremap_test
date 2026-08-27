#==============================================================================
# AzureMap v2 - Checks/Entra/BreakGlass.ps1
# ENTRA-11  Break-glass / Global Administrator hygiene  (TenantWide, HIGH)
#
# READ-ONLY. Consumes already-collected $script:State.Entra data
# (RoleAssignments, RoleDefinitions, PrincipalCache). No live Graph calls.
# NotEvaluated when the required role-assignment slice was not collected.
#==============================================================================

# Well-known Global Administrator role template id.
$script:GlobalAdminTemplateId = "62e90394-69f5-4237-9190-012177145e10"

function Test-EntraBreakGlassHygiene {
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    $roleAssignments = $null
    if ($entra) { $roleAssignments = $entra.RoleAssignments }

    if ($null -eq $roleAssignments) {
        Write-Finding -CheckId "ENTRA-11" -Service "EntraBreakGlass" -Category "Entra" `
            -Severity "HIGH" -Status "NotEvaluated" -Count 0 `
            -Message "Global Administrator / break-glass hygiene could not be evaluated (role assignments were not collected)."
        return
    }

    $roleDefinitions = @($entra.RoleDefinitions)
    $principalCache  = $entra.PrincipalCache

    # Resolve the set of roleDefinition ids that map to Global Administrator.
    $gaDefIds = [System.Collections.Generic.HashSet[string]]::new()
    [void]$gaDefIds.Add($script:GlobalAdminTemplateId)
    foreach ($rd in $roleDefinitions) {
        if ("$($rd.displayName)" -eq "Global Administrator") { [void]$gaDefIds.Add("$($rd.id)") }
        if ("$($rd.templateId)" -eq $script:GlobalAdminTemplateId) { [void]$gaDefIds.Add("$($rd.id)") }
    }

    $gaPrincipals = @($roleAssignments |
        Where-Object { $gaDefIds.Contains("$($_.roleDefinitionId)") } |
        ForEach-Object { "$($_.principalId)" } |
        Sort-Object -Unique)

    $gaCount  = $gaPrincipals.Count
    $findings = [System.Collections.Generic.List[object]]::new()

    if ($gaCount -gt 5) {
        $findings.Add([PSCustomObject]@{ Risk = "More than five Global Administrators"; Count = $gaCount })
    }
    if ($gaCount -lt 2) {
        $findings.Add([PSCustomObject]@{ Risk = "Fewer than two Global Administrators (no resilient break-glass)"; Count = $gaCount })
    }

    # Break-glass naming heuristic via the principal cache (display name / UPN only).
    $cacheHasData = ($null -ne $principalCache -and @($principalCache.Keys).Count -gt 0)
    if (-not $cacheHasData) {
        $findings.Add([PSCustomObject]@{
            Risk       = "Break-glass account presence could not be assessed"
            Limitation = "Principal directory data was not collected; manual validation required."
        })
    }
    else {
        $breakGlassCount   = 0
        $breakGlassDisabled = 0
        foreach ($principalId in $gaPrincipals) {
            $entry = $principalCache[$principalId]
            if ($null -eq $entry) { continue }
            $name = "$($entry.displayName) $($entry.upn)"
            if ($name -match "break.?glass|emergency") {
                $breakGlassCount++
                if ($entry.PSObject.Properties.Name -contains 'accountEnabled' -and $entry.accountEnabled -eq $false) {
                    $breakGlassDisabled++
                }
                elseif (($entry -is [hashtable]) -and $entry.ContainsKey('accountEnabled') -and $entry['accountEnabled'] -eq $false) {
                    $breakGlassDisabled++
                }
            }
        }
        if ($breakGlassCount -eq 0) {
            $findings.Add([PSCustomObject]@{
                Risk       = "No obvious break-glass account found among Global Administrators"
                Limitation = "Naming heuristic only (break-glass/emergency); confirm manually if a differently-named emergency account exists."
            })
        }
        if ($breakGlassDisabled -gt 0) {
            $findings.Add([PSCustomObject]@{ Risk = "A break-glass Global Administrator account appears disabled"; Count = $breakGlassDisabled })
        }
    }

    $status = if ($findings.Count -gt 0) { "FAIL" } else { "PASS" }
    Write-Finding -CheckId "ENTRA-11" -Service "EntraBreakGlass" -Category "Entra" `
        -Severity "HIGH" -Status $status -Count $findings.Count -Data $findings.ToArray() `
        -Message "Break-glass and Global Administrator hygiene risks" `
        -Remediation "Maintain 2-5 Global Administrators, keep at least one enabled emergency/break-glass account excluded from MFA-blocking CA (but monitored), and review standing GA counts."
}

function Register-EntraBreakGlassChecks {
    [CmdletBinding()]
    param()
    @(
        @{
            CheckId         = "ENTRA-11"
            Category        = "Entra"
            Service         = "EntraBreakGlass"
            Name            = "Test-EntraBreakGlassHygiene"
            Function        = "Test-EntraBreakGlassHygiene"
            DefaultSeverity = "HIGH"
            RequiredModules = @()
            RequiredPerms   = @("RoleManagement.Read.Directory", "Directory.Read.All")
            Phase           = "TenantWide"
            Description     = "Break-glass / Global Administrator hygiene"
        }
    )
}
