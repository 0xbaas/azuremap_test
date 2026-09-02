#==============================================================================
# AzureMap v2 - Tests/Shared/Phase32.CountLabelsCaveats.Tests.ps1
# Phase 32 / P2 report improvements - CountType display labels + static
# per-finding caveats. Mocked/local only. No Azure, no Graph, no
# authentication, no data-plane.
#
# Pins:
#   * Get-CountTypeLabel maps every CountType to its short display noun and
#     falls back to 'affected' for empty/unknown values.
#   * Get-FindingCaveats resolves the static display-layer caveat map,
#     including finding-category (message pattern) scoping within a check.
#   * Group-HtmlFindings carries CountType through aggregation.
#   * Classic layout: count labels in the findings-table link + component
#     group headers, caveats inside the finding-group block, and the
#     "NotEvaluated is not Pass." note in the attention section.
#   * Pentester layout: count labels in the affected column + finding detail
#     headers, caveats inside the fd- block, same NotEvaluated note.
# Existing Classic pins (Phase14/17/19/20/21/28/29) are untouched and must
# stay green.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"
    . "$projectRoot\Shared\Export\Html.ps1"
    . "$projectRoot\Shared\Export\HtmlPentester.ps1"
    . "$projectRoot\Shared\Export\Summary.ps1"

    # The HTML exporters probe Get-AzContext for account/tenant display.
    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }

    # Populates a small run whose findings exercise CountType labels and the
    # caveat map: STORAGE-002 (PNA + account-level caveats, UniqueResources),
    # IDENTITY-007 (RBAC caveat, RoleAssignments), plus one NotEvaluated check.
    function script:New-P32State {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-p32-test.log'

        Write-Finding -Severity 'CRITICAL' -Status 'FAIL' -CheckId 'STORAGE-002' -Service 'Storage' `
            -Message 'Storage accounts with public network exposure, blob public access, or unverified firewall' `
            -Count 2 -CountType 'UniqueResources' `
            -Data @([PSCustomObject]@{ StorageAccount = 'st1' }, [PSCustomObject]@{ StorageAccount = 'st2' })
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -CheckId 'IDENTITY-007' -Service 'Identity' `
            -Message 'Owner role assignments at subscription scope (assignments, not unique users)' `
            -Count 3 -CountType 'RoleAssignments' `
            -Data @([PSCustomObject]@{ Principal = 'user-a' })

        foreach ($c in @(
            [PSCustomObject]@{ CheckId = 'STORAGE-002';  Name = 'Public Network Access'; Status = 'Fail' },
            [PSCustomObject]@{ CheckId = 'IDENTITY-007'; Name = 'RBAC Privileged Assignment Decomposition'; Status = 'Fail' },
            [PSCustomObject]@{ CheckId = 'NETWORK-003';  Name = 'Public IP Inventory'; Status = 'NotEvaluated'; Detail = 'RBAC unreadable' }
        )) {
            $script:State.ExecutedChecks.Add([PSCustomObject]@{
                CheckId = $c.CheckId; Name = $c.Name; Category = 'Azure'; Service = 'Storage'
                Phase = 'PerSubscription'; Status = $c.Status; Detail = "$($c.Detail)"
                SummaryText = ''; Coverage = $null; DataPlaneRequired = $false
                StartedAt = Get-Date; CompletedAt = Get-Date
            })
        }

        # Minimal capability model so the shared capability section renders.
        $script:State.CapabilityModel = [PSCustomObject]@{
            Insights = @(); Nodes = @(); Edges = @()
            Summary  = [PSCustomObject]@{ NodeCount = 0; EdgeCount = 0; HighestSeverity = $null }
            Limits   = $null
        }
    }

    function script:Render-P32Classic {
        $out = Join-Path $TestDrive 'p32-classic.html'
        Export-ResultsHtml -Results @($script:State.Results) -OutputPath $out | Out-Null
        Get-Content $out -Raw
    }

    function script:Render-P32Pentester {
        $out = Join-Path $TestDrive 'p32-pentester.html'
        Export-ResultsHtmlPentester -Results @($script:State.Results) -OutputPath $out | Out-Null
        Get-Content $out -Raw
    }
}

Describe "Get-CountTypeLabel" {

    It "maps every CountType to its short display noun" {
        Get-CountTypeLabel -CountType 'UniqueResources'   | Should -Be 'resources'
        Get-CountTypeLabel -CountType 'Containers'        | Should -Be 'containers'
        Get-CountTypeLabel -CountType 'RoleAssignments'   | Should -Be 'assignments'
        Get-CountTypeLabel -CountType 'RiskSignals'       | Should -Be 'risk signals'
        Get-CountTypeLabel -CountType 'Observations'      | Should -Be 'observations'
        Get-CountTypeLabel -CountType 'NotEvaluatedItems' | Should -Be 'not-evaluated items'
    }

    It "falls back to 'affected' for empty or unknown values" {
        Get-CountTypeLabel -CountType ''         | Should -Be 'affected'
        Get-CountTypeLabel -CountType 'Whatever' | Should -Be 'affected'
    }
}

Describe "Get-FindingCaveats - static display-layer map" {

    It "returns nothing for checks without caveats" {
        @(Get-FindingCaveats -CheckId 'STORAGE-001' -Finding 'anything') | Should -BeNullOrEmpty
        @(Get-FindingCaveats -CheckId '' -Finding 'anything')            | Should -BeNullOrEmpty
    }

    It "STORAGE-002 gets both public-access caveats on every finding" {
        $c = @(Get-FindingCaveats -CheckId 'STORAGE-002' -Finding 'Storage accounts with public network exposure, blob public access, or unverified firewall')
        $c.Count | Should -Be 2
        $c -contains 'Public network access does not mean anonymous data access.' | Should -BeTrue
        $c -contains 'Account-level public blob access does not prove public containers.' | Should -BeTrue
    }

    It "STORAGE-004 caveat is scoped to the account-level control-plane signal" {
        @(Get-FindingCaveats -CheckId 'STORAGE-004' -Finding 'Storage accounts allowing blob public access at account level (control-plane signal; no public containers confirmed)') |
            Should -Be 'Account-level public blob access does not prove public containers.'
        @(Get-FindingCaveats -CheckId 'STORAGE-004' -Finding 'Storage accounts with CONFIRMED anonymous/public blob containers (data-plane verified)') |
            Should -BeNullOrEmpty
    }

    It "KEYVAULT-002 caveats are scoped per finding category" {
        @(Get-FindingCaveats -CheckId 'KEYVAULT-002' -Finding 'Key Vaults with public network access enabled or unspecified (defaults to enabled)') |
            Should -Be 'Public network access does not mean anonymous data access.'
        @(Get-FindingCaveats -CheckId 'KEYVAULT-002' -Finding 'Critical Key Vaults without private endpoints') |
            Should -Be 'Private IP/private endpoint does not prove full private-only access.'
        @(Get-FindingCaveats -CheckId 'KEYVAULT-002' -Finding 'Key Vaults without purge protection enabled') |
            Should -BeNullOrEmpty
    }

    It "NSG caveat applies to NETWORK-001 and to NSG findings of NETWORK-008 only" {
        @(Get-FindingCaveats -CheckId 'NETWORK-001' -Finding 'NSG rules allowing internet access to sensitive ports (SSH, RDP, SQL)') |
            Should -Be 'NSG rule does not prove reachability unless attached to a public path.'
        @(Get-FindingCaveats -CheckId 'NETWORK-008' -Finding 'NSG outbound rules allowing internet access (data exfiltration path)') |
            Should -Be 'NSG rule does not prove reachability unless attached to a public path.'
        @(Get-FindingCaveats -CheckId 'NETWORK-008' -Finding 'Route tables with default route (0.0.0.0/0) to Internet') |
            Should -BeNullOrEmpty
    }

    It "private-access caveat applies to NETWORK-002 and NETWORK-010" {
        @(Get-FindingCaveats -CheckId 'NETWORK-002' -Finding 'Private endpoints missing private DNS zone linkage (DNS leak risk)') |
            Should -Be 'Private IP/private endpoint does not prove full private-only access.'
        $c = @(Get-FindingCaveats -CheckId 'NETWORK-010' -Finding 'Sensitive PaaS resources with public network access and no linked private endpoint')
        $c -contains 'Public network access does not mean anonymous data access.' | Should -BeTrue
        $c -contains 'Private IP/private endpoint does not prove full private-only access.' | Should -BeTrue
    }

    It "RBAC assignment caveat applies to IDENTITY-003 and IDENTITY-007" {
        @(Get-FindingCaveats -CheckId 'IDENTITY-003' -Finding 'HIGH risk RBAC assignments at management group/subscription scope') |
            Should -Be 'RBAC assignment counts are not unique users.'
        @(Get-FindingCaveats -CheckId 'IDENTITY-007' -Finding 'Owner role assignments at subscription scope (assignments, not unique users)') |
            Should -Be 'RBAC assignment counts are not unique users.'
    }
}

Describe "Group-HtmlFindings carries CountType" {

    It "keeps the first non-empty CountType of the group" {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        Write-Finding -Severity 'HIGH' -Status 'FAIL' -CheckId 'IDENTITY-007' -Service 'Identity' `
            -Message 'Owner role assignments at subscription scope' -Count 2 -CountType 'RoleAssignments' `
            -SubscriptionId 'sub-a' -SubscriptionName 'sub-a'
        $rec = $script:State.Results[0]
        $plain = $rec.PSObject.Copy()
        $plain.CountType = ''
        $plain.SubscriptionId = 'sub-b'; $plain.SubscriptionName = 'sub-b'
        $g = @(Group-HtmlFindings -Findings @($plain, $rec))
        $g.Count | Should -Be 1
        $g[0].CountType | Should -Be 'RoleAssignments'
    }

    It "groups without CountType keep an empty label source (renderer falls back to 'affected')" {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        Write-Finding -Severity 'LOW' -Status 'FAIL' -CheckId 'X-1' -Service 'Storage' -Message 'legacy' -Count 1
        $rec = $script:State.Results[0]
        $rec.CountType = ''
        $g = @(Group-HtmlFindings -Findings @($rec))
        "$($g[0].CountType)" | Should -Be ''
        Get-CountTypeLabel -CountType "$($g[0].CountType)" | Should -Be 'affected'
    }
}

Describe "Classic layout - count labels and caveats" {

    BeforeEach { New-P32State }

    It "count labels replace the generic 'affected' in link and group headers" {
        $html = Render-P32Classic
        $html | Should -Match 'View 2 resources'
        $html | Should -Match 'View 3 assignments'
        $html | Should -Not -Match 'View \d+ affected'
    }

    It "STORAGE-002 group block carries both public-access caveats" {
        $html = Render-P32Classic
        $html | Should -Match 'Public network access does not mean anonymous data access\.'
        $html | Should -Match 'Account-level public blob access does not prove public containers\.'
    }

    It "IDENTITY-007 group block carries the RBAC assignment caveat" {
        $html = Render-P32Classic
        $html | Should -Match 'RBAC assignment counts are not unique users\.'
    }

    It "attention section carries the NotEvaluated caveat" {
        $html = Render-P32Classic
        $html | Should -Match 'NotEvaluated is not Pass\.'
    }

    It "caveats render as small muted notes (caveat class)" {
        $html = Render-P32Classic
        $html | Should -Match 'class="muted caveat"'
    }
}

Describe "Pentester layout - count labels and caveats" {

    BeforeEach { New-P32State }

    It "affected column and finding detail headers use count labels" {
        $html = Render-P32Pentester
        $html | Should -Match '<td>2 resources</td>'
        $html | Should -Match '<td>3 assignments</td>'
        $html | Should -Match '2 resources'
        $html | Should -Match '3 assignments'
    }

    It "fd- detail block for STORAGE-002 carries the caveats" {
        $html = Render-P32Pentester
        $start = $html.IndexOf('id="fd-0"')
        $start | Should -BeGreaterOrEqual 0
        $block = $html.Substring($start, $html.IndexOf('</details>', $start) - $start)
        $block | Should -Match 'Public network access does not mean anonymous data access\.'
        $block | Should -Match 'Account-level public blob access does not prove public containers\.'
    }

    It "attention section carries the NotEvaluated caveat" {
        $html = Render-P32Pentester
        $html | Should -Match 'NotEvaluated is not Pass\.'
    }

    It "findings without a caveat map entry render no caveat note" {
        # IDENTITY-007 has a caveat; NETWORK-003 (NotEvaluated, no real finding
        # group) must not gain one - count the caveat paragraphs per layout.
        $html = Render-P32Pentester
        # STORAGE-002 block: 2 caveats in one note; IDENTITY-007 block: 1 note;
        # attention section: 1 note => 3 caveat paragraphs total.
        ([regex]::Matches($html, 'class="muted caveat"')).Count | Should -Be 3
    }
}
