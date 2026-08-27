# ============================================================================
# AzureMap - Logic Apps Security Checks
# ============================================================================
# Functions:
#   Test-LogicAppsManagedIdentity
#   Register-AzureLogicAppsChecks
# ============================================================================

function Test-LogicAppsManagedIdentity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "LOGIC APPS - MANAGED IDENTITY CONFIGURATION" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.LogicApp)) {
        Write-AuditLog -Message "Az.LogicApp module not installed. Skipping Logic App checks." -Level WARN
        return
    }
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        Write-Progress -Activity "Checking Logic Apps managed identity" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind LogicApps
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check Logic Apps in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }
        
        # Per-app Get-AzResource calls still need the session on this
        # subscription (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        try {
            foreach ($logicApp in $inv.Items) {
                if ($logicApp.State -ne "Enabled") { continue }
                
                try {
                    $resource = Invoke-AzureCommand -Command {
                        Get-AzResource -ResourceId $logicApp.ResourceId -ErrorAction Stop
                    } -CommandName "Get-LogicAppResource"
                    
                    $hasMI = $resource.Identity -and $resource.Identity.PrincipalId
                    if (-not $hasMI) {
                        $findings.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $logicApp.ResourceGroupName
                            LogicAppName = $logicApp.Name
                            State = $logicApp.State
                            ResourceId = $logicApp.ResourceId
                        })
                    }
                }
                catch {
                    Write-AuditLog -Message "Failed to check Logic App identity for $($logicApp.Name): $_" -Level WARN
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Logic Apps in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Enabled Logic Apps without managed identity" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "LogicApp" `
                      -Remediation "Enable managed identity on Logic Apps and use it for downstream access." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Register-AzureLogicAppsChecks {
    Register-AuditCheck -CheckId "LOGICAPPS-001" `
                        -Category "Azure" `
                        -Service "LogicApp" `
                        -Name "Logic Apps Managed Identity" `
                        -Function ${function:Test-LogicAppsManagedIdentity} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.LogicApp") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Logic/workflows')
}
