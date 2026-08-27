#==============================================================================
# AzureMap v2 - Products/AzureMap/Checks/Governance.ps1
# AZURE-GOV-001  Defender for Cloud + policy coverage  (PerSubscription, HIGH)
#
# READ-ONLY. ARM REST GET (Microsoft.Security/pricings) + Get-AzPolicyAssignment.
# No writes, no Graph. NotEvaluated when the Defender pricings read fails -
# never a false PASS.
#==============================================================================

function Test-DefenderAndPolicyCoverage {
    [CmdletBinding()]
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    $importantPlans = @("VirtualMachines", "StorageAccounts", "SqlServers", "Containers", "KeyVaults", "AppServices")

    foreach ($sub in @($Subscriptions)) {
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) { continue }

        $pricingPath = "/subscriptions/$($sub.Id)/providers/Microsoft.Security/pricings?api-version=2024-01-01"
        $pricing = $null
        try {
            $pricing = Invoke-AzRestMethod -Method GET -Path $pricingPath -ErrorAction Stop
        }
        catch {
            $pricing = $null
        }

        if ($null -eq $pricing -or ($pricing.PSObject.Properties.Name -contains 'StatusCode' -and [int]$pricing.StatusCode -ge 400)) {
            Write-Finding -CheckId "AZURE-GOV-001" -Service "Governance" -Category "Azure" `
                -Severity "HIGH" -Status "NotEvaluated" -Count 0 -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                -Message "Defender for Cloud coverage could not be evaluated (Microsoft.Security/pricings read failed) for subscription '$($sub.Name)'."
            continue
        }

        $findings = [System.Collections.Generic.List[object]]::new()

        $plans = @()
        try { $plans = @((ConvertFrom-Json $pricing.Content).value) } catch { $plans = @() }

        foreach ($name in $importantPlans) {
            $plan = $plans | Where-Object { "$($_.name)" -eq $name } | Select-Object -First 1
            $tier = if ($plan) { "$($plan.properties.pricingTier)" } else { $null }
            if (-not $plan -or $tier -ne 'Standard') {
                $findings.Add([PSCustomObject]@{ Control = 'DefenderPlan'; Plan = $name; CurrentTier = $(if ($tier) { $tier } else { 'NotConfigured' }); Risk = 'Defender plan not enabled at Standard tier' })
            }
        }

        # Best-effort Azure Policy assignment presence (does not gate NotEvaluated).
        try {
            $assignments = @(Get-AzPolicyAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop)
            if ($assignments.Count -eq 0) {
                $findings.Add([PSCustomObject]@{ Control = 'PolicyAssignment'; Risk = 'No Azure Policy assignments found at subscription scope' })
            }
        }
        catch {
            $findings.Add([PSCustomObject]@{ Control = 'PolicyAssignment'; Note = 'PolicyNotEvaluated'; Detail = 'Policy assignment read failed; policy coverage not assessed.' })
        }

        # Determine status: real gaps (Defender/no-policy) => FAIL; only a
        # PolicyNotEvaluated note with otherwise-clean Defender => PASS on Defender.
        $realGaps = @($findings | Where-Object { -not ($_.PSObject.Properties.Name -contains 'Note') })

        if ($realGaps.Count -gt 0) {
            Write-Finding -CheckId "AZURE-GOV-001" -Service "Governance" -Category "Azure" `
                -Severity "MEDIUM" -Status "FAIL" -Count $realGaps.Count -Data $findings.ToArray() `
                -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                -Message "Defender for Cloud and policy coverage gaps" `
                -SeverityReason 'Detection/prevention coverage gap; context-dependent - raises risk of exposed workloads but is not a direct exploit path by itself.' `
                -Remediation "Enable Microsoft Defender for Cloud plans (Standard) for VMs, Storage, SQL, Containers, Key Vault, and App Service; assign security baseline / diagnostics Azure Policy initiatives."
        }
        else {
            Write-Finding -CheckId "AZURE-GOV-001" -Service "Governance" -Category "Azure" `
                -Severity "HIGH" -Status "PASS" -Count 0 -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                -Message "Defender for Cloud important plans enabled and policy assignments present"
        }
    }
}

function Register-AzureGovernanceChecks {
    [CmdletBinding()]
    param()
    Register-AuditCheck -CheckId "AZURE-GOV-001" `
        -Category "Azure" `
        -Service "Governance" `
        -Name "Defender for Cloud & Policy Coverage" `
        -Function "Test-DefenderAndPolicyCoverage" `
        -DefaultSeverity "MEDIUM" `
        -RequiredModules @("Az.Accounts", "Az.Resources") `
        -Phase "PerSubscription" `
        -Description "Microsoft Defender for Cloud plan tiers and Azure Policy assignment coverage." `
        -AlwaysRun $true
}
