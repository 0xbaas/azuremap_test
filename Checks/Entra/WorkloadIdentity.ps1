#==============================================================================
# AzureMap v2 - Checks/Entra/WorkloadIdentity.ps1
# ENTRA-12  Risky workload identity federation  (TenantWide, CRITICAL)
#
# READ-ONLY. Uses collected $script:State.Entra.Applications, then Microsoft
# Graph GET /applications/{id}/federatedIdentityCredentials per app.
# NotEvaluated when apps were not collected, or when FIC reads fail and no
# risky credential was found (partial evaluation) - never a false PASS.
#==============================================================================

function Test-EntraWorkloadIdentityFederatedCredentials {
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    $applications = $null
    if ($entra) { $applications = $entra.Applications }

    if ($null -eq $applications) {
        Write-Finding -CheckId "ENTRA-12" -Service "EntraWorkloadIdentity" -Category "Entra" `
            -Severity "CRITICAL" -Status "NotEvaluated" -Count 0 `
            -Message "Applications were not collected; workload identity federated credentials not evaluated."
        return
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $failures = 0

    foreach ($app in @($applications)) {
        try {
            $creds = @(Invoke-GraphCommand -Uri "/applications/$($app.id)/federatedIdentityCredentials" -CommandName "EntraFederatedCredentials")
        }
        catch {
            $failures++
            continue
        }

        foreach ($cred in $creds) {
            $issuer   = "$($cred.issuer)"
            $subject  = "$($cred.subject)"
            $auds     = @($cred.audiences)
            $reasons  = @()

            if ($issuer -match "token\.actions\.githubusercontent\.com") { $reasons += "GitHub Actions OIDC trust" }
            if ($subject -match "\*" -or $subject -match "refs/heads/main|refs/heads/master|refs/tags/|:ref:refs/heads/main") {
                $reasons += "Broad or production-linked subject"
            }
            if ($auds.Count -gt 0 -and ($auds -notcontains "api://AzureADTokenExchange")) {
                $reasons += "Unexpected token audience"
            }

            if ($reasons.Count -gt 0) {
                $findings.Add([PSCustomObject]@{
                    AppDisplayName = [string]$app.displayName
                    AppId          = [string]$app.appId
                    Issuer         = $issuer
                    Subject        = $subject
                    Risk           = ($reasons -join "; ")
                })
            }
        }
    }

    if ($failures -gt 0 -and $findings.Count -eq 0) {
        Write-Finding -CheckId "ENTRA-12" -Service "EntraWorkloadIdentity" -Category "Entra" `
            -Severity "HIGH" -Status "NotEvaluated" -Count 0 `
            -Message "Federated credentials only partially evaluated ($failures application read(s) failed); not reported as clean."
        return
    }

    $status = if ($findings.Count -gt 0) { "FAIL" } else { "PASS" }
    Write-Finding -CheckId "ENTRA-12" -Service "EntraWorkloadIdentity" -Category "Entra" `
        -Severity "CRITICAL" -Status $status -Count $findings.Count -Data $findings.ToArray() `
        -Message "Risky workload identity federation" `
        -Remediation "Scope federated identity credential subjects tightly (specific repo + environment/branch), avoid wildcard/main-branch trust, and verify audiences are api://AzureADTokenExchange. Review FICs on apps with privileged Graph permissions."
}

function Register-EntraWorkloadIdentityChecks {
    [CmdletBinding()]
    param()
    @(
        @{
            CheckId         = "ENTRA-12"
            Category        = "Entra"
            Service         = "EntraWorkloadIdentity"
            Name            = "Test-EntraWorkloadIdentityFederatedCredentials"
            Function        = "Test-EntraWorkloadIdentityFederatedCredentials"
            DefaultSeverity = "CRITICAL"
            RequiredModules = @()
            RequiredPerms   = @("Application.Read.All")
            Phase           = "TenantWide"
            Description     = "Risky workload identity federated credentials"
        }
    )
}
