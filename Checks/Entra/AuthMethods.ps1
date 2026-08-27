#==============================================================================
# AzureMap v2 - Checks/Entra/AuthMethods.ps1
# ENTRA-10  Weak authentication methods enabled  (TenantWide, HIGH)
#
# READ-ONLY. Microsoft Graph GET /policies/authenticationMethodsPolicy.
# NotEvaluated on Graph failure - never PASS on a collection failure.
#==============================================================================

function Get-AmProp {
    param([object]$Object, [string]$Name)
    if ($null -ne $Object -and ($Object.PSObject.Properties.Name -contains $Name)) {
        return $Object.$Name
    }
    return $null
}

function Test-EntraAuthenticationMethods {
    [CmdletBinding()]
    param()

    try {
        $result = @(Invoke-GraphCommand -Uri "/policies/authenticationMethodsPolicy" -CommandName "EntraAuthMethodsPolicy")
    }
    catch {
        Write-Finding -CheckId "ENTRA-10" -Service "EntraAuthMethods" -Category "Entra" `
            -Severity "HIGH" -Status "NotEvaluated" -Count 0 `
            -Message "Authentication methods policy could not be evaluated (Graph query failed or Policy.Read.All missing)."
        return
    }

    if ($result.Count -eq 0 -or $null -eq $result[0]) {
        Write-Finding -CheckId "ENTRA-10" -Service "EntraAuthMethods" -Category "Entra" `
            -Severity "HIGH" -Status "NotEvaluated" -Count 0 `
            -Message "Authentication methods policy returned no data; not evaluated."
        return
    }

    $policy  = $result[0]
    $configs = @(Get-AmProp $policy 'authenticationMethodConfigurations')
    $weakIds = @('sms', 'voice')

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($method in $configs) {
        $id    = "$(Get-AmProp $method 'id')"
        $state = "$(Get-AmProp $method 'state')"
        if (($weakIds -contains $id.ToLower()) -and ($state.ToLower() -eq 'enabled')) {
            $findings.Add([PSCustomObject]@{
                Method = $id
                State  = $state
                Risk   = "Phishable/weak authentication method enabled"
            })
        }
    }

    $status = if ($findings.Count -gt 0) { "FAIL" } else { "PASS" }
    Write-Finding -CheckId "ENTRA-10" -Service "EntraAuthMethods" -Category "Entra" `
        -Severity "HIGH" -Status $status -Count $findings.Count -Data $findings.ToArray() `
        -Message "Weak authentication methods enabled" `
        -Remediation "Disable SMS and Voice as authentication methods; prefer phishing-resistant methods (FIDO2/passkeys, Microsoft Authenticator with number matching)."
}

function Register-EntraAuthMethodsChecks {
    [CmdletBinding()]
    param()
    @(
        @{
            CheckId         = "ENTRA-10"
            Category        = "Entra"
            Service         = "EntraAuthMethods"
            Name            = "Test-EntraAuthenticationMethods"
            Function        = "Test-EntraAuthenticationMethods"
            DefaultSeverity = "HIGH"
            RequiredModules = @()
            RequiredPerms   = @("Policy.Read.All")
            Phase           = "TenantWide"
            Description     = "Weak authentication methods (SMS/Voice) enabled"
        }
    )
}
