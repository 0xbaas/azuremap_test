#==============================================================================
# AzureMap v2 - Core/Config.ps1
# Configuration loading, deep-merge, and Azure module dependency validation.
# All functions reference $script:State.
#==============================================================================

function Merge-Hashtable {
    <#
    .SYNOPSIS
        Recursively deep-merges two hashtables.
    .DESCRIPTION
        - Nested hashtables are merged recursively.
        - Arrays are replaced wholesale.
        - Scalar values are replaced.
        Keys in $Override that do not exist in $Base are added.
    .OUTPUTS
        [hashtable] The merged result (mutates and returns $Base).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Base,

        [Parameter(Mandatory)]
        [hashtable]$Override
    )

    foreach ($key in $Override.Keys) {
        if ($Base.ContainsKey($key)) {
            if ($Base[$key] -is [hashtable] -and $Override[$key] -is [hashtable]) {
                $Base[$key] = Merge-Hashtable -Base $Base[$key] -Override $Override[$key]
            }
            elseif ($Base[$key] -is [System.Array] -and $Override[$key] -is [System.Array]) {
                $Base[$key] = $Override[$key]
            }
            else {
                $Base[$key] = $Override[$key]
            }
        }
        else {
            $Base[$key] = $Override[$key]
        }
    }
    return $Base
}

function Load-Configuration {
    <#
    .SYNOPSIS
        Loads a JSON config file and deep-merges it into $script:State.Config.
    .DESCRIPTION
        If the file exists, its properties are converted to a hashtable and
        merged with Merge-Hashtable so that nested structures survive intact.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath
    )

    if (-not [string]::IsNullOrEmpty($ConfigPath) -and (Test-Path $ConfigPath)) {
        try {
            $userConfig = Get-Content $ConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop

            $userConfigHash = @{}
            foreach ($prop in $userConfig.PSObject.Properties) {
                $userConfigHash[$prop.Name] = $prop.Value
            }

            $script:State.Config = Merge-Hashtable -Base $script:State.Config -Override $userConfigHash

            Write-AuditLog -Message "Loaded configuration from $ConfigPath (deep merged)" -Level INFO
        }
        catch {
            Write-AuditLog -Message "Failed to load configuration from ${ConfigPath}: $_" -Level WARN
        }
    }
}

function Test-AzureModuleDependency {
    <#
    .SYNOPSIS
        Validates that required and optional Azure PowerShell modules are installed.
    .DESCRIPTION
        Iterates $script:State.RequiredModules and $script:State.OptionalModules.
        Missing required modules cause a $false return with install instructions.
        Outdated modules produce warnings but allow continuation.
    .OUTPUTS
        [bool] $true if all required modules are present.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipCheck
    )

    if ($SkipCheck -or $script:State.ModuleCheckComplete) {
        Write-AuditLog -Message "Skipping module dependency check" -Level INFO
        return $true
    }

    Write-AuditLog -Message "Validating Azure PowerShell module dependencies..." -Level INFO

    $missingModules  = [System.Collections.Generic.List[object]]::new()
    $outdatedModules = [System.Collections.Generic.List[object]]::new()

    # --- Required modules ---
    foreach ($moduleName in $script:State.RequiredModules.Keys) {
        $requiredVersion = $script:State.RequiredModules[$moduleName]

        try {
            $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue |
                      Sort-Object Version -Descending |
                      Select-Object -First 1

            if (-not $module) {
                $missingModules.Add([PSCustomObject]@{
                    Module           = $moduleName
                    RequiredVersion  = $requiredVersion
                    InstalledVersion = "Not installed"
                })
                continue
            }

            if ([System.Version]$module.Version -lt [System.Version]$requiredVersion) {
                $outdatedModules.Add([PSCustomObject]@{
                    Module           = $moduleName
                    RequiredVersion  = $requiredVersion
                    InstalledVersion = $module.Version
                })
            }
        }
        catch {
            Write-AuditLog -Message "Error checking module ${moduleName}: $_" -Level WARN
            $missingModules.Add([PSCustomObject]@{
                Module           = $moduleName
                RequiredVersion  = $requiredVersion
                InstalledVersion = "Check failed"
            })
        }
    }

    # --- Optional modules ---
    foreach ($moduleName in $script:State.OptionalModules.Keys) {
        $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue |
                  Sort-Object Version -Descending |
                  Select-Object -First 1

        if (-not $module) {
            Write-AuditLog -Message "Optional module $moduleName not installed (some checks will be skipped)" -Level WARN
        }
    }

    # --- Report ---
    if ($missingModules.Count -gt 0) {
        Write-AuditLog -Message "Missing required modules:" -Level ERROR -ForceConsole
        $missingModules | ForEach-Object {
            Write-AuditLog -Message "  - $($_.Module) v$($_.RequiredVersion) (Installed: $($_.InstalledVersion))" -Level ERROR -ForceConsole
        }

        Write-AuditLog -Message "`nInstall missing modules with:" -Level ERROR -ForceConsole
        $missingModules | ForEach-Object {
            Write-AuditLog -Message "  Install-Module -Name $($_.Module) -RequiredVersion $($_.RequiredVersion) -Force -AllowClobber" -Level ERROR -ForceConsole
        }

        return $false
    }

    if ($outdatedModules.Count -gt 0) {
        Write-AuditLog -Message "Outdated modules found:" -Level WARN
        $outdatedModules | ForEach-Object {
            Write-AuditLog -Message "  - $($_.Module) v$($_.InstalledVersion) (Required: v$($_.RequiredVersion))" -Level WARN
        }
        Write-AuditLog -Message "Continuing with outdated modules (some checks may fail)" -Level WARN
    }

    $script:State.ModuleCheckComplete = $true
    Write-AuditLog -Message "Module dependency validation passed" -Level INFO
    return $true
}
