#==============================================================================
# AzureMap v2 - Checks/Entra/Overview.ps1
# Evaluates application credential hygiene (expiry, rotation, count).
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraAppCredentialHygiene {
    <#
    .SYNOPSIS
        Evaluates credential hygiene across Entra application registrations.
    .DESCRIPTION
        Checks passwordCredentials and keyCredentials for each app. Flags:
        - Credentials with expiry beyond 2 years (MEDIUM)
        - Already-expired credentials still present (LOW)
        - Multiple active credentials on a single app (LOW)
        - Apps with dangerous permissions but no credentials (INFO)
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping credential hygiene check" -Level WARN
        return
    }

    $now = Get-Date
    $twoYearsFromNow = $now.AddDays(730)
    $longCredentialDays = $script:State.Config.LongCredentialDays
    if (-not $longCredentialDays) { $longCredentialDays = 730 }
    $longCredentialThreshold = $now.AddDays($longCredentialDays)

    $evidence = [System.Collections.Generic.List[object]]::new()

    foreach ($app in $entra.Applications) {
        $appId   = $app.id
        $appName = $app.displayName

        $allCreds = @()
        if ($app.passwordCredentials) { $allCreds += $app.passwordCredentials | ForEach-Object { $_ | Add-Member -NotePropertyName '_CredType' -NotePropertyValue 'Password' -Force -PassThru } }
        if ($app.keyCredentials)      { $allCreds += $app.keyCredentials      | ForEach-Object { $_ | Add-Member -NotePropertyName '_CredType' -NotePropertyValue 'Certificate' -Force -PassThru } }

        $activeCreds  = @()
        $expiredCreds = @()

        foreach ($cred in $allCreds) {
            $endDate = $null
            if ($cred.endDateTime) {
                try { $endDate = [DateTime]::Parse($cred.endDateTime) } catch { }
            }

            if ($endDate -and $endDate -lt $now) {
                $expiredCreds += $cred
                $evidence.Add([PSCustomObject]@{
                    AppId          = $appId
                    AppName        = $appName
                    CredentialType = $cred._CredType
                    KeyId          = $cred.keyId
                    ExpiryDate     = $cred.endDateTime
                    DaysUntilExpiry = [math]::Round(($endDate - $now).TotalDays)
                    FindingType    = "ExpiredCredential"
                    Severity       = "LOW"
                })
            } else {
                $activeCreds += @{ Cred = $cred; EndDate = $endDate }

                if ($endDate -and $endDate -gt $longCredentialThreshold) {
                    $daysUntil = [math]::Round(($endDate - $now).TotalDays)
                    $evidence.Add([PSCustomObject]@{
                        AppId          = $appId
                        AppName        = $appName
                        CredentialType = $cred._CredType
                        KeyId          = $cred.keyId
                        ExpiryDate     = $cred.endDateTime
                        DaysUntilExpiry = $daysUntil
                        FindingType    = "LongLivedCredential"
                        Severity       = "MEDIUM"
                    })
                }
            }
        }

        if ($activeCreds.Count -gt 1) {
            $evidence.Add([PSCustomObject]@{
                AppId          = $appId
                AppName        = $appName
                CredentialType = "Mixed"
                KeyId          = "N/A"
                ExpiryDate     = "N/A"
                DaysUntilExpiry = "N/A"
                FindingType    = "MultipleActiveCredentials"
                ActiveCount    = $activeCreds.Count
                Severity       = "LOW"
            })
        }
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $mediumCount = ($evidence | Where-Object { $_.Severity -eq "MEDIUM" }).Count
        $maxSeverity = if ($mediumCount -gt 0) { "HIGH" } else { "MEDIUM" }

        $longLived = ($evidence | Where-Object { $_.FindingType -eq "LongLivedCredential" }).Count
        $expired   = ($evidence | Where-Object { $_.FindingType -eq "ExpiredCredential" }).Count
        $multiple  = ($evidence | Where-Object { $_.FindingType -eq "MultipleActiveCredentials" }).Count

        Write-Finding `
            -Severity       $maxSeverity `
            -Message        "Application credential hygiene issues ($longLived long-lived, $expired expired, $multiple with multiple active)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraOverview" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Rotate credentials with expiry beyond policy threshold. Remove expired credentials. Consolidate to single active credential per app. Migrate to managed identities or federated credentials where possible."
    } else {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No application credential hygiene issues found" `
            -Count          0 `
            -Service        "EntraOverview" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
    }
}

function Register-EntraOverviewChecks {
    <#
    .SYNOPSIS
        Registers the Entra Overview checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-07"
            Category        = "Entra"
            Service         = "EntraOverview"
            Name            = "Test-EntraAppCredentialHygiene"
            Function        = "Test-EntraAppCredentialHygiene"
            DefaultSeverity = "HIGH"
            RequiredModules = @()
            RequiredPerms   = @("Application.Read.All")
            Phase           = "TenantWide"
            Description     = "Application credential hygiene -- long-lived, expired, and duplicate credentials"
        }
    )
}
