#==============================================================================
# AzureMap v2 - Tests/Unit/CheckRegistry.Tests.ps1
# Pester v5 tests for Write-Finding and check registration.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    # Dot-source Core modules needed for Write-Finding
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"

    # Initialize state so $script:State is available
    $script:State = Initialize-AuditState

    # Minimal Write-Finding adapted from original (lives in CheckRegistry module)
    # Inlined here until Core/CheckRegistry.ps1 is created
    if (-not (Get-Command -Name "Write-Finding" -ErrorAction SilentlyContinue)) {
        function Write-Finding {
            param(
                [string]$Severity,
                [string]$Message,
                [int]$Count,
                [object]$Data,
                [string]$Service,
                [string]$Remediation,
                [hashtable]$Exclusions,
                [string]$SubscriptionId,
                [string]$SubscriptionName,
                [string]$ResourceId,
                [string]$ResourceName,
                [hashtable]$Tags,
                [guid]$FindingId = (New-Guid)
            )

            $severityLevel = $script:State.Config.SeverityLevel

            if ($severityLevel -eq "CriticalOnly" -and $Severity -ne "CRITICAL") {
                return
            }
            if ($severityLevel -eq "HighAndAbove" -and @("MEDIUM", "LOW", "INFO") -contains $Severity) {
                return
            }

            $evidenceData  = $null
            $evidenceCount = 0
            if ($Count -gt 0 -and $Data) {
                $normalizedData = @($Data)
                $evidenceCount  = $normalizedData.Count
                $maxEvidenceItems = 1000

                if ($evidenceCount -gt $maxEvidenceItems) {
                    $evidenceData = $normalizedData | Select-Object -First $maxEvidenceItems
                } else {
                    $evidenceData = $normalizedData
                }
            }

            $finding = [PSCustomObject]@{
                FindingId        = $FindingId
                Timestamp        = Get-Date
                Severity         = $Severity
                Finding          = $Message
                Count            = $Count
                EvidenceCount    = $evidenceCount
                Service          = $Service
                Status           = if ($Count -gt 0) { "FAIL" } else { "PASS" }
                SubscriptionId   = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceId       = $ResourceId
                ResourceName     = $ResourceName
                Tags             = $Tags
                Remediation      = $Remediation
                Evidence         = $evidenceData
            }

            if ($Exclusions -and (Test-Exclusion -Finding $finding -Exclusions $Exclusions)) {
                return
            }

            $script:State.Results.Add($finding)
        }
    }

    if (-not (Get-Command -Name "Register-AuditCheck" -ErrorAction SilentlyContinue)) {
        function Register-AuditCheck {
            param(
                [Parameter(Mandatory)][string]$CheckId,
                [Parameter(Mandatory)][string]$Category,
                [Parameter(Mandatory)][string]$Service,
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][string]$Function,
                [string]$DefaultSeverity = "MEDIUM",
                [string[]]$RequiredModules = @(),
                [string[]]$RequiredPerms = @(),
                [string]$Phase = "PerSubscription",
                [string]$Description = ""
            )

            $script:State.CheckRegistry.Add([PSCustomObject]@{
                CheckId         = $CheckId
                Category        = $Category
                Service         = $Service
                Name            = $Name
                Function        = $Function
                DefaultSeverity = $DefaultSeverity
                RequiredModules = $RequiredModules
                RequiredPerms   = $RequiredPerms
                Phase           = $Phase
                Description     = $Description
            })
        }
    }
}

function global:Test-StorageCheck { }
function global:Test-SqlCheck { }
function global:Test-EntraRoles { }
function global:Test-MockCheck { Set-Variable -Name MockCheckExecuted -Value $true -Scope Script }

Describe "Write-Finding" {
    BeforeEach {
        $script:State.Results.Clear()
        $script:State.Config.SeverityLevel = "All"
    }

    It "creates a valid finding object with all required fields" {
        Write-Finding -Severity "HIGH" -Message "Test finding" -Count 1 `
            -Data @("item1") -Service "Storage" -Remediation "Fix it" `
            -SubscriptionId "sub-123" -SubscriptionName "TestSub"

        $script:State.Results.Count | Should -Be 1
        $f = $script:State.Results[0]

        $f.FindingId        | Should -BeOfType [guid]
        $f.Timestamp        | Should -BeOfType [datetime]
        $f.Severity         | Should -Be "HIGH"
        $f.Finding          | Should -Be "Test finding"
        $f.Count            | Should -Be 1
        $f.Service          | Should -Be "Storage"
        $f.Status           | Should -Be "FAIL"
        $f.SubscriptionId   | Should -Be "sub-123"
        $f.SubscriptionName | Should -Be "TestSub"
        $f.Remediation      | Should -Be "Fix it"
    }

    It "sets Status to PASS when Count is 0" {
        Write-Finding -Severity "INFO" -Message "No issues" -Count 0 -Service "Network"

        $script:State.Results.Count | Should -Be 1
        $script:State.Results[0].Status | Should -Be "PASS"
    }

    It "applies CriticalOnly severity filter" {
        $script:State.Config.SeverityLevel = "CriticalOnly"

        Write-Finding -Severity "HIGH" -Message "Should be filtered" -Count 1 -Service "SQL"
        Write-Finding -Severity "CRITICAL" -Message "Should pass" -Count 1 -Service "SQL"

        $script:State.Results.Count | Should -Be 1
        $script:State.Results[0].Severity | Should -Be "CRITICAL"
    }

    It "applies HighAndAbove severity filter" {
        $script:State.Config.SeverityLevel = "HighAndAbove"

        Write-Finding -Severity "MEDIUM" -Message "Filtered" -Count 1 -Service "SQL"
        Write-Finding -Severity "LOW" -Message "Filtered" -Count 1 -Service "SQL"
        Write-Finding -Severity "INFO" -Message "Filtered" -Count 1 -Service "SQL"
        Write-Finding -Severity "HIGH" -Message "Kept" -Count 1 -Service "SQL"
        Write-Finding -Severity "CRITICAL" -Message "Kept" -Count 1 -Service "SQL"

        $script:State.Results.Count | Should -Be 2
    }

    It "caps evidence at 1000 items" {
        $bigData = 1..1500 | ForEach-Object { [PSCustomObject]@{ Id = $_ } }

        Write-Finding -Severity "HIGH" -Message "Big evidence" -Count 1500 `
            -Data $bigData -Service "Compute"

        $script:State.Results.Count | Should -Be 1
        $script:State.Results[0].Evidence.Count | Should -BeLessOrEqual 1000
    }

    It "finding schema has all required fields" {
        Write-Finding -Severity "MEDIUM" -Message "Schema test" -Count 0 -Service "KeyVault"

        $f = $script:State.Results[0]
        $requiredFields = @(
            "FindingId", "Timestamp", "Severity", "Finding", "Count",
            "EvidenceCount", "Service", "Status", "SubscriptionId",
            "SubscriptionName", "ResourceId", "ResourceName",
            "Tags", "Remediation", "Evidence"
        )
        foreach ($field in $requiredFields) {
            $f.PSObject.Properties.Name | Should -Contain $field
        }
    }
}

Describe "Register-AuditCheck" {

    BeforeEach {
        $script:State.CheckRegistry.Clear()
    }

    It "adds a check entry to the registry" {
        Register-AuditCheck -CheckId "TEST-01" -Category "Azure" `
            -Service "Storage" -Name "Test-StorageCheck" `
            -Function "Test-StorageCheck" -Description "Unit test check"

        $script:State.CheckRegistry.Count | Should -Be 1
        $entry = $script:State.CheckRegistry[0]
        $entry.CheckId  | Should -Be "TEST-01"
        $entry.Category | Should -Be "Azure"
        $entry.Service  | Should -Be "Storage"
        $entry.Function | Should -BeOfType [scriptblock]
    }

    It "allows multiple checks to be registered" {
        Register-AuditCheck -CheckId "A-01" -Category "Azure" -Service "SQL" `
            -Name "Test-SqlCheck" -Function "Test-SqlCheck"
        Register-AuditCheck -CheckId "E-01" -Category "Entra" -Service "EntraRoles" `
            -Name "Test-EntraRoles" -Function "Test-EntraRoles"

        $script:State.CheckRegistry.Count | Should -Be 2
    }
}

Describe "Invoke-AzureMapCheck" {
    BeforeEach {
        $script:State.CheckRegistry.Clear()
        Remove-Variable -Name MockCheckExecuted -Scope Script -ErrorAction SilentlyContinue
    }

    It "executes a registered check when requirements are met" {
        Register-AuditCheck -CheckId "M-01" -Category "Azure" -Service "Storage" `
            -Name "Test-MockCheck" -Function ${function:Test-MockCheck}

        $result = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions @() -Exclusions @{} -Services @("All")

        $result | Should -BeTrue
        Get-Variable -Name MockCheckExecuted -Scope Script -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It "skips a check when the service filter does not match" {
        Register-AuditCheck -CheckId "M-02" -Category "Azure" -Service "SQL" `
            -Name "Test-MockCheck" -Function ${function:Test-MockCheck}

        $result = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions @() -Exclusions @{} -Services @("Storage")

        $result | Should -BeTrue
        Get-Variable -Name MockCheckExecuted -Scope Script -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It "skips a check when a required module is missing" {
        Register-AuditCheck -CheckId "M-03" -Category "Azure" -Service "Storage" `
            -Name "Test-MockCheck" -Function ${function:Test-MockCheck} `
            -RequiredModules @("Az.DoesNotExist123")

        $result = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions @() -Exclusions @{} -Services @("All")

        $result | Should -BeTrue
        Get-Variable -Name MockCheckExecuted -Scope Script -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It "skips Entra checks when SkipEntra is specified" {
        Register-AuditCheck -CheckId "M-04" -Category "Entra" -Service "EntraRoles" `
            -Name "Test-MockCheck" -Function ${function:Test-MockCheck}

        $result = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions @() -Exclusions @{} -Services @("All") -SkipEntra

        $result | Should -BeTrue
        Get-Variable -Name MockCheckExecuted -Scope Script -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It "skips Azure checks when EntraOnly is specified" {
        Register-AuditCheck -CheckId "M-05" -Category "Azure" -Service "Storage" `
            -Name "Test-MockCheck" -Function ${function:Test-MockCheck}

        $result = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions @() -Exclusions @{} -Services @("All") -EntraOnly

        $result | Should -BeTrue
        Get-Variable -Name MockCheckExecuted -Scope Script -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
