#==============================================================================
# AzureMap v2 - Tests/Unit/Config.Tests.ps1
# Pester v5 tests for Merge-Hashtable, Load-Exclusions, Test-Exclusion.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Config.ps1"
    . "$projectRoot\Core\Exclusions.ps1"

    $script:State = Initialize-AuditState
}

Describe "Merge-Hashtable" {

    It "deep merges nested hashtables" {
        $base = @{
            Level1 = @{
                A = 1
                B = @{
                    Nested = "original"
                    Keep   = "kept"
                }
            }
        }
        $override = @{
            Level1 = @{
                B = @{
                    Nested = "overridden"
                }
            }
        }

        $result = Merge-Hashtable -Base $base -Override $override

        $result.Level1.A        | Should -Be 1
        $result.Level1.B.Nested | Should -Be "overridden"
        $result.Level1.B.Keep   | Should -Be "kept"
    }

    It "replaces arrays wholesale" {
        $base = @{
            Items = @(1, 2, 3)
        }
        $override = @{
            Items = @(10, 20)
        }

        $result = Merge-Hashtable -Base $base -Override $override

        $result.Items.Count | Should -Be 2
        $result.Items[0]    | Should -Be 10
        $result.Items[1]    | Should -Be 20
    }

    It "replaces scalar values" {
        $base = @{
            Name    = "original"
            Timeout = 30
        }
        $override = @{
            Timeout = 60
        }

        $result = Merge-Hashtable -Base $base -Override $override

        $result.Name    | Should -Be "original"
        $result.Timeout | Should -Be 60
    }

    It "adds new keys from override" {
        $base = @{ Existing = "yes" }
        $override = @{ NewKey = "added" }

        $result = Merge-Hashtable -Base $base -Override $override

        $result.Existing | Should -Be "yes"
        $result.NewKey   | Should -Be "added"
    }
}

Describe "Load-Exclusions" {

    It "returns empty structure for missing file" {
        $result = Load-Exclusions -ExclusionPath "C:\nonexistent\path\exclusions.json"

        $result.Resources     | Should -HaveCount 0
        $result.Findings      | Should -HaveCount 0
        $result.Subscriptions | Should -HaveCount 0
        $result.Tags          | Should -HaveCount 0
    }

    It "returns empty structure for null path" {
        $result = Load-Exclusions -ExclusionPath $null

        $result.Resources     | Should -HaveCount 0
        $result.Subscriptions | Should -HaveCount 0
    }

    It "returns empty structure for empty string path" {
        $result = Load-Exclusions -ExclusionPath ""

        $result.Findings | Should -HaveCount 0
        $result.Tags     | Should -HaveCount 0
    }
}

Describe "Test-Exclusion" {

    It "matches subscription ID" {
        $finding = [PSCustomObject]@{
            SubscriptionId   = "aaaa-bbbb-cccc"
            SubscriptionName = "TestSub"
            ResourceId       = $null
            ResourceName     = $null
            Tags             = $null
            Finding          = "Some finding"
            Severity         = "HIGH"
        }
        $exclusions = @{
            Resources     = @()
            Findings      = @()
            Subscriptions = @("aaaa-bbbb-cccc")
            Tags          = @()
        }

        Test-Exclusion -Finding $finding -Exclusions $exclusions | Should -BeTrue
    }

    It "does not match different subscription ID" {
        $finding = [PSCustomObject]@{
            SubscriptionId   = "xxxx-yyyy-zzzz"
            SubscriptionName = "OtherSub"
            ResourceId       = $null
            ResourceName     = $null
            Tags             = $null
            Finding          = "Some finding"
            Severity         = "HIGH"
        }
        $exclusions = @{
            Resources     = @()
            Findings      = @()
            Subscriptions = @("aaaa-bbbb-cccc")
            Tags          = @()
        }

        Test-Exclusion -Finding $finding -Exclusions $exclusions | Should -BeFalse
    }

    It "matches resource name pattern" {
        $finding = [PSCustomObject]@{
            SubscriptionId   = $null
            SubscriptionName = $null
            ResourceId       = $null
            ResourceName     = "test-storage-account"
            Tags             = $null
            Finding          = "Storage issue"
            Severity         = "MEDIUM"
        }
        $exclusions = @{
            Resources     = @([PSCustomObject]@{ ResourceId = $null; NamePattern = "test-*" })
            Findings      = @()
            Subscriptions = @()
            Tags          = @()
        }

        Test-Exclusion -Finding $finding -Exclusions $exclusions | Should -BeTrue
    }

    It "matches tag key/value" {
        $finding = [PSCustomObject]@{
            SubscriptionId   = $null
            SubscriptionName = $null
            ResourceId       = $null
            ResourceName     = $null
            Tags             = @{ Environment = "dev"; Team = "platform" }
            Finding          = "Tag finding"
            Severity         = "LOW"
        }
        $exclusions = @{
            Resources     = @()
            Findings      = @()
            Subscriptions = @()
            Tags          = @([PSCustomObject]@{ Key = "Environment"; Value = "dev" })
        }

        Test-Exclusion -Finding $finding -Exclusions $exclusions | Should -BeTrue
    }

    It "does not match when tag value differs" {
        $finding = [PSCustomObject]@{
            SubscriptionId   = $null
            SubscriptionName = $null
            ResourceId       = $null
            ResourceName     = $null
            Tags             = @{ Environment = "prod" }
            Finding          = "Tag finding"
            Severity         = "LOW"
        }
        $exclusions = @{
            Resources     = @()
            Findings      = @()
            Subscriptions = @()
            Tags          = @([PSCustomObject]@{ Key = "Environment"; Value = "dev" })
        }

        Test-Exclusion -Finding $finding -Exclusions $exclusions | Should -BeFalse
    }
}
