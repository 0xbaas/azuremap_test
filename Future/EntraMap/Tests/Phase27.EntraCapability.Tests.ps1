#==============================================================================
# AzureMap v2 - Tests/EntraMap/Phase27.EntraCapability.Tests.ps1
# Phase 27 - EntraMap capability model. Mocked/local only: no Azure, no Graph,
# no authentication. The model reads ONLY already-collected in-memory state
# (State.Results evidence, State.Entra, TenantWideData, EntraFootprint) and
# must make ZERO Graph/Azure API calls.
#
# Covers:
#   (a) zero-Graph-call contract: Build-EntraCapabilityModel succeeds with all
#       Graph/Azure entry points stubbed to throw (a swallowed builder failure
#       would drop insights -> caught by the insight-count assertions)
#   (b) per-insight detection: all 10 insight types fire from the synthetic
#       fixture with the expected severities
#   (c) escalation ordering: combined dangerous-perms + weak-ownership ranks
#       above the permissions-only insight
#   (d) weak signals never escalate (expired/multiple creds, excessive owners
#       without dangerous perms -> no insight)
#   (e) confidence rules (confirmed=High, inferred PIM=Medium, heuristic-only
#       break-glass=Low)
#   (f) caps, dedupe, sorting, sequential CAP ids, evidence non-mutation
#   (g) CLI top-5 rendering, HTML capability section (Entra-flavored intro),
#       JSON CapabilityModel shape
#   (h) safety contract: static analysis of Future/EntraMap/Core, Future/EntraMap/Checks and
#       entramap.ps1 (read-only; no write verbs, no secret retrieval, no
#       non-GET outside the Graph batch envelope, no bare Connect-AzAccount)
#==============================================================================

BeforeAll {
    # Parked under Future/EntraMap/Tests: repo root is three levels up.
    $projectRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Shared\Core\Capability.ps1"
    . "$projectRoot\Future\EntraMap\Capability\CapabilityModel.Entra.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"
    . "$projectRoot\Shared\Export\Html.ps1"
    . "$projectRoot\Shared\Export\Json.ps1"

    # The HTML/JSON exporters probe Get-AzContext for account/tenant display;
    # stub it so the render tests never touch a real Az session.
    function global:Get-AzContext { $null }

    # Zero-Graph-call contract: every Graph/Azure entry point the capability
    # model could possibly reach is stubbed to THROW. A builder that called one
    # would fail and be skipped (logged WARN + Limits.Notes entry), which the
    # insight-completeness assertions then catch.
    function global:Invoke-GraphCommand     { throw 'TEST SAFETY: Invoke-GraphCommand must never be called by the capability model' }
    function global:Invoke-GraphBatch       { throw 'TEST SAFETY: Invoke-GraphBatch must never be called by the capability model' }
    function global:Get-GraphToken          { throw 'TEST SAFETY: Get-GraphToken must never be called by the capability model' }
    function global:Get-AzAccessToken       { throw 'TEST SAFETY: Get-AzAccessToken must never be called by the capability model' }
    function global:Invoke-RestMethod       { throw 'TEST SAFETY: Invoke-RestMethod must never be called by the capability model' }
    function global:Get-AzADApplication     { throw 'TEST SAFETY: Get-AzADApplication must never be called by the capability model' }
    function global:Get-AzADServicePrincipal { throw 'TEST SAFETY: Get-AzADServicePrincipal must never be called by the capability model' }

    $script:FixtureDir = Join-Path $projectRoot 'Tests\Fixtures\Entra'

    function script:New-EntraCapState {
        $script:State = Initialize-EntraAuditState
        $script:State.Config.Quiet  = $true
        $script:State.Config.NoColor = $true
        $script:State.LogFile = Join-Path $TestDrive 'EntraMap-test.log'
        # Entra collection: only PrincipalCache is consumed by the model
        # (guest/external classification via collected UPNs).
        $script:State.Entra = [PSCustomObject]@{
            PrincipalCache = @{
                'aaaa0001-0000-4000-8000-000000000001' = @{ upn = 'admin1@contoso.onmicrosoft.com'; displayName = 'Admin One' }
                'aaaa0001-0000-4000-8000-000000000002' = @{ upn = 'admin2@contoso.onmicrosoft.com'; displayName = 'Admin Two' }
                'aaaa0001-0000-4000-8000-000000000003' = @{ upn = 'extuser_vendor.com#EXT#@contoso.onmicrosoft.com'; displayName = 'Ext Vendor (Contoso)' }
                'aaaa0001-0000-4000-8000-000000000005' = @{ upn = 'appowner@contoso.onmicrosoft.com'; displayName = 'App Owner' }
            }
        }
    }

    # Loads the synthetic finding set (shaped exactly like check output) into
    # State.Results. Drives all 10 insight builders.
    function script:Import-FixtureFindings {
        $findings = Get-Content -Raw (Join-Path $script:FixtureDir 'expected-findings.json') | ConvertFrom-Json
        foreach ($f in $findings) { $script:State.Results.Add($f) }
    }

    function script:Get-InsightByTitle {
        param($Model, [string]$Title)
        @($Model.Insights | Where-Object { $_.Title -eq $Title })[0]
    }

    function script:Get-StrippedCode {
        # Mirrors Phase24: drop <#...#> block comments and full-line comments
        # before pattern matching so docstrings never trip the greps.
        param([string]$Path)
        $raw = Get-Content -Raw -Path $Path
        $noBlock = [regex]::Replace($raw, '(?s)<#.*?#>', '')
        $lines = @($noBlock -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' })
        return ($lines -join "`n")
    }
}

Describe "Entra capability model - zero Graph/Azure calls" {

    BeforeEach {
        New-EntraCapState
        Import-FixtureFindings
    }

    It "builds the full model with every Graph/Azure entry point stubbed to throw" {
        { $model = Build-EntraCapabilityModel } | Should -Not -Throw
        $model = Build-EntraCapabilityModel
        @($model.Insights).Count | Should -Be 10
        @($model.Limits.Notes).Count | Should -Be 0 -Because 'a builder failure (e.g. a swallowed Graph-call throw) is recorded here'
    }

    It "does not throw and returns an empty model on empty state" {
        $script:State.Results.Clear()
        { $model = Build-EntraCapabilityModel } | Should -Not -Throw
        $model = Build-EntraCapabilityModel
        $model.Summary.InsightCount | Should -Be 0
        @($model.Nodes).Count  | Should -Be 0
        @($model.Edges).Count  | Should -Be 0
        $model.Summary.HighestSeverity | Should -BeNullOrEmpty
    }
}

Describe "Entra capability model - per-insight detection from fixtures" {

    BeforeAll {
        New-EntraCapState
        Import-FixtureFindings
        $script:FixtureModel = Build-EntraCapabilityModel
    }

    It "produces all 10 insights with the expected titles" {
        $expected = @(
            'Permanent privileged role assignments',
            'PIM-eligible privileged roles without strong activation controls',
            'Applications with high-privilege Graph permissions',
            'Dangerous app permissions combined with weak ownership',
            'Long-lived application credentials',
            'Role-assignable groups conferring indirect privilege',
            'External/guest users with privileged access',
            'Break-glass and Global Administrator hygiene gaps',
            'Workload identity federation into privileged applications',
            'Conditional Access coverage gaps for privileged or risky sign-ins'
        )
        @($script:FixtureModel.Insights).Count | Should -Be 10
        foreach ($t in $expected) {
            @($script:FixtureModel.Insights | Where-Object { $_.Title -eq $t }).Count | Should -Be 1 -Because "insight '$t' must fire from the fixture"
        }
    }

    It "models the confirmed no-PIM + no-admin-MFA standing GA combination as CRITICAL" {
        $i = Get-InsightByTitle $script:FixtureModel 'Permanent privileged role assignments'
        $i.Severity   | Should -Be 'CRITICAL'
        $i.Confidence | Should -Be 'High'
        $i.ImpactedResourceCount | Should -Be 3
        (@($i.ImpactedResources) -match 'Admin One' -match 'no PIM eligible').Count | Should -Be 1
    }

    It "models dangerous app permissions + non-admin ownership as CRITICAL (confirmed combination)" {
        $i = Get-InsightByTitle $script:FixtureModel 'Dangerous app permissions combined with weak ownership'
        $i.Severity   | Should -Be 'CRITICAL'
        $i.Confidence | Should -Be 'High'
        $i.ImpactedResourceCount | Should -Be 1
        @($i.ImpactedResources)[0] | Should -Match 'sp-ci-cd'
        @($i.ImpactedResources)[0] | Should -Match 'App Owner'
    }

    It "models wildcard workload identity federation into a privileged app as CRITICAL" {
        $i = Get-InsightByTitle $script:FixtureModel 'Workload identity federation into privileged applications'
        $i.Severity   | Should -Be 'CRITICAL'
        $i.Confidence | Should -Be 'High'
        @($i.ImpactedResources)[0] | Should -Match 'app-github-federation'
    }

    It "models guest privileged access as CRITICAL when no guest-MFA policy is enforced" {
        $i = Get-InsightByTitle $script:FixtureModel 'External/guest users with privileged access'
        $i.Severity   | Should -Be 'CRITICAL'
        $i.Confidence | Should -Be 'High'
        $i.ImpactedResourceCount | Should -Be 1
        @($i.ImpactedResources)[0] | Should -Match 'Ext Vendor'
    }

    It "models long-lived credentials as HIGH when the app also holds dangerous permissions" {
        $i = Get-InsightByTitle $script:FixtureModel 'Long-lived application credentials'
        $i.Severity | Should -Be 'HIGH'
        @($i.ImpactedResources)[0] | Should -Match 'app-ci-cd'
    }

    It "models the remaining insights at their expected severities" {
        (Get-InsightByTitle $script:FixtureModel 'Applications with high-privilege Graph permissions').Severity            | Should -Be 'HIGH'
        (Get-InsightByTitle $script:FixtureModel 'PIM-eligible privileged roles without strong activation controls').Severity | Should -Be 'HIGH'
        (Get-InsightByTitle $script:FixtureModel 'Role-assignable groups conferring indirect privilege').Severity           | Should -Be 'HIGH'
        (Get-InsightByTitle $script:FixtureModel 'Conditional Access coverage gaps for privileged or risky sign-ins').Severity | Should -Be 'HIGH'
        (Get-InsightByTitle $script:FixtureModel 'Break-glass and Global Administrator hygiene gaps').Severity                | Should -Be 'MEDIUM'
        $script:FixtureModel.Summary.HighestSeverity | Should -Be 'CRITICAL'
    }

    It "populates the capability graph (nodes + edges) from collected evidence" {
        @($script:FixtureModel.Nodes).Count | Should -BeGreaterThan 0
        @($script:FixtureModel.Edges).Count | Should -BeGreaterThan 0
        $script:FixtureModel.Summary.NodeCount | Should -Be @($script:FixtureModel.Nodes).Count
        $script:FixtureModel.Summary.EdgeCount | Should -Be @($script:FixtureModel.Edges).Count
        foreach ($chk in @('ENTRA-01','ENTRA-02','ENTRA-03','ENTRA-04','ENTRA-05','ENTRA-07','ENTRA-09','ENTRA-10','ENTRA-11','ENTRA-12')) {
            $script:FixtureModel.SourceChecks | Should -Contain $chk
        }
    }
}

Describe "Entra capability model - escalation ordering and weak-signal discipline" {

    BeforeEach {
        New-EntraCapState
        Import-FixtureFindings
    }

    It "ranks the combined ownership escalation strictly above the permissions-only insight" {
        $model = Build-EntraCapabilityModel
        $combined = Get-InsightByTitle $model 'Dangerous app permissions combined with weak ownership'
        $permsOnly = Get-InsightByTitle $model 'Applications with high-privilege Graph permissions'
        $combined.Severity | Should -Be 'CRITICAL'
        $permsOnly.Severity | Should -Be 'HIGH'
        $script:CapabilitySeverityRank[$combined.Severity] | Should -BeLessThan $script:CapabilitySeverityRank[$permsOnly.Severity]
        # ... and the model sort must place it earlier.
        $idxCombined = [array]::IndexOf(@($model.Insights), $combined)
        $idxPerms = [array]::IndexOf(@($model.Insights), $permsOnly)
        $idxCombined | Should -BeLessThan $idxPerms
    }

    It "weak signals never escalate: no insight references app-weak-api" {
        $model = Build-EntraCapabilityModel
        foreach ($i in @($model.Insights)) {
            foreach ($res in @($i.ImpactedResources)) {
                $res | Should -Not -Match 'app-weak-api' -Because "expired/multiple credentials and excessive-owners rows on '$($i.Title)' are weak signals"
            }
        }
        # The combined insight must only contain the dangerous+non-admin-owner app.
        $combined = Get-InsightByTitle $model 'Dangerous app permissions combined with weak ownership'
        @($combined.ImpactedResources).Count | Should -Be 1
        # The credential insight must only contain the long-lived credential row.
        $creds = Get-InsightByTitle $model 'Long-lived application credentials'
        $creds.ImpactedResourceCount | Should -Be 1
    }

    It "narrow (non-wildcard) FIC on a privileged app is HIGH, not CRITICAL" {
        # Rewrite the ENTRA-12 evidence to a tightly-scoped subject.
        foreach ($f in @($script:State.Results)) {
            if ($f.CheckId -ne 'ENTRA-12') { continue }
            $f.Evidence = @([PSCustomObject]@{
                AppDisplayName = 'app-github-federation'
                AppId          = 'cccc0003-0000-4000-8000-0000000000a2'
                Issuer         = 'https://token.actions.githubusercontent.com'
                Subject        = 'repo:contoso/app:environment:production'
                Risk           = 'Federated credential on an app with dangerous permissions'
                Severity       = 'MEDIUM'
            })
        }
        $model = Build-EntraCapabilityModel
        $i = Get-InsightByTitle $model 'Workload identity federation into privileged applications'
        $i.Severity | Should -Be 'HIGH'
    }

    It "no guest-MFA escalation without the guest-MFA gap (HIGH instead of CRITICAL)" {
        # Drop the guest-MFA gap row from ENTRA-09 evidence.
        foreach ($f in @($script:State.Results)) {
            if ($f.CheckId -ne 'ENTRA-09') { continue }
            $f.Evidence = @($f.Evidence | Where-Object { "$($_.Gap)" -notmatch 'guest/external' })
            $f.Count = @($f.Evidence).Count
        }
        $model = Build-EntraCapabilityModel
        $i = Get-InsightByTitle $model 'External/guest users with privileged access'
        $i.Severity | Should -Be 'HIGH'
    }
}

Describe "Entra capability model - confidence rules" {

    BeforeEach {
        New-EntraCapState
        Import-FixtureFindings
    }

    It "confirmed combinations are High confidence, inferred PIM combination is Medium" {
        $model = Build-EntraCapabilityModel
        (Get-InsightByTitle $model 'Dangerous app permissions combined with weak ownership').Confidence              | Should -Be 'High'
        (Get-InsightByTitle $model 'Applications with high-privilege Graph permissions').Confidence                   | Should -Be 'High'
        (Get-InsightByTitle $model 'Conditional Access coverage gaps for privileged or risky sign-ins').Confidence    | Should -Be 'High'
        (Get-InsightByTitle $model 'PIM-eligible privileged roles without strong activation controls').Confidence     | Should -Be 'Medium'
    }

    It "count-based break-glass risks are High confidence" {
        $model = Build-EntraCapabilityModel
        (Get-InsightByTitle $model 'Break-glass and Global Administrator hygiene gaps').Confidence | Should -Be 'High'
    }

    It "heuristic-only break-glass risks are Low confidence" {
        $script:State.Results.Clear()
        $script:State.Results.Add([PSCustomObject]@{
            CheckId = 'ENTRA-11'; Finding = '1 possible break-glass gap(s)'; Count = 1
            Status = 'FAIL'; Severity = 'LOW'
            Evidence = @([PSCustomObject]@{
                Risk       = 'No break-glass account identified by naming convention'
                Limitation = 'Naming-convention heuristic only; validate manually'
            })
        })
        $model = Build-EntraCapabilityModel
        $i = Get-InsightByTitle $model 'Break-glass and Global Administrator hygiene gaps'
        $i.Confidence | Should -Be 'Low'
    }

    It "display-name-only guest classification drops insight confidence to Medium" {
        # Remove the guest's UPN from the collected principal data so only the
        # display-name heuristic remains; put the '#EXT#' marker into the
        # evidence display name (what the heuristic keys on).
        $script:State.Entra.PrincipalCache.Remove('aaaa0001-0000-4000-8000-000000000003')
        foreach ($f in @($script:State.Results)) {
            if ($f.CheckId -ne 'ENTRA-01') { continue }
            foreach ($ev in @($f.Evidence)) {
                if ("$($ev.PrincipalId)" -eq 'aaaa0001-0000-4000-8000-000000000003') {
                    $ev.PrincipalDisplayName = 'extuser_vendor.com#EXT#@contoso.onmicrosoft.com'
                }
            }
        }
        $model = Build-EntraCapabilityModel
        $i = Get-InsightByTitle $model 'External/guest users with privileged access'
        $i | Should -Not -BeNullOrEmpty
        $i.Confidence | Should -Be 'Medium'
    }
}

Describe "Entra capability model - caps, dedupe and sorting" {

    BeforeEach {
        New-EntraCapState
        Import-FixtureFindings
    }

    It "sorts severity-first, then impacted count, and assigns sequential CAP ids" {
        $model = Build-EntraCapabilityModel
        $model.Insights[0].Severity | Should -Be 'CRITICAL'
        $model.Insights[0].Title    | Should -Be 'Permanent privileged role assignments'  # CRITICAL with the highest count
        for ($i = 0; $i -lt $model.Insights.Count; $i++) {
            $model.Insights[$i].Id | Should -Be ('CAP-{0:d3}' -f ($i + 1))
            if ($i -gt 0) {
                $script:CapabilitySeverityRank[$model.Insights[$i].Severity] |
                    Should -BeGreaterOrEqual $script:CapabilitySeverityRank[$model.Insights[$i - 1].Severity]
            }
        }
        $model.Summary.InsightCount | Should -BeLessOrEqual $script:CapabilityLimits.MaxInsights
    }

    It "dedupes repeated evidence rows (duplicate finding does not double-count)" {
        $dup = [PSCustomObject]@{
            CheckId = 'ENTRA-01'; Finding = 'duplicate row'; Count = 1; Status = 'FAIL'; Severity = 'HIGH'
            Evidence = @([PSCustomObject]@{
                PrincipalId = 'aaaa0001-0000-4000-8000-000000000001'; PrincipalType = 'User'
                PrincipalDisplayName = 'Admin One'; RoleName = 'Global Administrator'
                RoleCriticality = 'Critical'; IsBuiltIn = $true; GroupMemberCount = 0; Severity = 'HIGH'
            })
        }
        $script:State.Results.Add($dup)
        $model = Build-EntraCapabilityModel
        (Get-InsightByTitle $model 'Permanent privileged role assignments').ImpactedResourceCount | Should -Be 3
        (Get-InsightByTitle $model 'External/guest users with privileged access').ImpactedResourceCount | Should -Be 1
    }

    It "respects node caps and the 50-resource listing cap on a large state" {
        $rows = 1..600 | ForEach-Object {
            [PSCustomObject]@{
                PrincipalId = "aaaa9999-0000-4000-8000-{0:d12}" -f $_
                PrincipalType = 'User'; PrincipalDisplayName = "User $_"
                RoleName = 'Directory Writers'; RoleCriticality = 'Medium'
                IsBuiltIn = $true; GroupMemberCount = 0; Severity = 'MEDIUM'
            }
        }
        $script:State.Results.Add([PSCustomObject]@{
            CheckId = 'ENTRA-01'; Finding = '600 more standing assignments'; Count = 600
            Status = 'FAIL'; Severity = 'MEDIUM'; Evidence = @($rows)
        })
        $model = Build-EntraCapabilityModel
        @($model.Nodes).Count | Should -BeLessOrEqual $script:CapabilityLimits.MaxNodes
        @($model.Edges).Count | Should -BeLessOrEqual $script:CapabilityLimits.MaxEdges
        ($model.Limits.NodesTruncated + $model.Limits.EdgesTruncated) | Should -BeGreaterThan 0
        $i = Get-InsightByTitle $model 'Permanent privileged role assignments'
        $i.ImpactedResourceCount | Should -Be 603
        @($i.ImpactedResources).Count | Should -Be $script:CapabilityLimits.MaxImpactedResourcesPerInsight
    }

    It "original finding evidence is never mutated (annotation goes to clones)" {
        [void](Build-EntraCapabilityModel)
        foreach ($f in @($script:State.Results)) {
            foreach ($ev in @($f.Evidence)) {
                $ev.PSObject.Properties.Name | Should -Not -Contain '_CheckId'
                $ev.PSObject.Properties.Name | Should -Not -Contain '_FindingMessage'
            }
        }
    }
}

Describe "Entra capability model - rendering (CLI / HTML / JSON)" {

    BeforeEach {
        New-EntraCapState
        Import-FixtureFindings
        $script:State.CapabilityModel = Build-EntraCapabilityModel
    }

    It "CLI shows 'Capability insights' with at most 5 numbered lines plus the overflow note" {
        $script:State.Config.Quiet = $false
        $out = Show-AuditConsole -ExportedFiles @() 6>&1 | Out-String
        $out | Should -Match 'Capability insights'
        $insightCount = @($script:State.CapabilityModel.Insights).Count
        $insightCount | Should -BeGreaterThan 5   # fixture must exercise the overflow line
        $out | Should -Match ("\.\.\. and {0} more\. See HTML/JSON exports\." -f ($insightCount - 5))
        $capSection = (($out -split 'Capability insights', 2)[1] -split 'Needs attention', 2)[0]
        $numbered = [regex]::Matches($capSection, '(?m)^\s+\d+\.\s')
        $numbered.Count | Should -Be 5
    }

    It "HTML export contains the capability section with the Entra-flavored intro" {
        $htmlPath = Export-ResultsHtml -Results @($script:State.Results) -OutputPath (Join-Path $TestDrive 'cap.html')
        $html = [System.IO.File]::ReadAllText($htmlPath)
        $html | Should -Match 'id="capability"'
        $html | Should -Match 'Dangerous app permissions combined with weak ownership'
        $html | Should -Match 'Capability Graph'
        # Product-specific intro: Entra examples, not the AzureMap examples.
        $html | Should -Match 'standing privileged roles without PIM or MFA'
        $html | Should -Not -Match 'shared key \+ key-capable RBAC'
    }

    It "JSON export contains the CapabilityModel with the full shared shape" {
        $jsonFile = Export-ResultsJson -Results @($script:State.Results) -BaseName (Join-Path $TestDrive 'cap')
        $json = Get-Content -Raw -Path $jsonFile | ConvertFrom-Json
        $cap = $json.CapabilityModel
        $cap | Should -Not -BeNullOrEmpty
        $cap.ModelVersion | Should -Be '1.0'
        @($cap.Insights).Count | Should -Be 10
        $cap.PSObject.Properties.Name | Should -Contain 'Summary'
        $cap.PSObject.Properties.Name | Should -Contain 'Nodes'
        $cap.PSObject.Properties.Name | Should -Contain 'Edges'
        $cap.PSObject.Properties.Name | Should -Contain 'SourceChecks'
        $cap.PSObject.Properties.Name | Should -Contain 'Limits'
        $cap.Summary.HighestSeverity | Should -Be 'CRITICAL'
        $cap.Insights[0].Id | Should -Be 'CAP-001'
    }
}

Describe "Entra product safety contract (static analysis)" {

    BeforeAll {
        $script:GraphTransportFiles = @('Graph.ps1', 'Footprint.Entra.ps1')
        $script:EntraProductFiles = @(
            Get-ChildItem -Path (Join-Path $projectRoot 'Future\EntraMap\Core\*.ps1') -File
            Get-ChildItem -Path (Join-Path $projectRoot 'Future\EntraMap\Capability\*.ps1') -File
            Get-ChildItem -Path (Join-Path $projectRoot 'Future\EntraMap\Checks\*.ps1') -File
            Get-Item -Path (Join-Path $projectRoot 'Future\EntraMap\entramap.ps1')
        )
    }

    It "no Entra product file references secret/key/content retrieval patterns" {
        $forbidden = @(
            'Get-AzStorageAccountKey', 'listKeys', 'listSecrets', 'SecretValue',
            'Get-AzKeyVaultSecret', 'secretText', 'privateKeyData',
            'ConvertFrom-SecureString', 'Invoke-AzRestMethod'
        )
        foreach ($file in $script:EntraProductFiles) {
            $raw = Get-Content -Raw -Path $file.FullName
            foreach ($pattern in $forbidden) {
                $raw.Contains($pattern) | Should -BeFalse -Because "$($file.Name) must never reference '$pattern'"
            }
        }
    }

    It "no Invoke-WebRequest anywhere; Invoke-RestMethod only in the Graph transport files" {
        foreach ($file in $script:EntraProductFiles) {
            $code = Get-StrippedCode -Path $file.FullName
            if ($file.Name -eq 'entramap.ps1') {
                # entramap.ps1 only hardens PSDefaultParameterValues for these
                # cmdlets (keys in a hashtable), it must never INVOKE them.
                $code | Should -Not -Match '(?m)^\s*Invoke-(RestMethod|WebRequest)\s' -Because 'entramap.ps1 must never invoke web cmdlets directly'
                continue
            }
            $code.Contains('Invoke-WebRequest') | Should -BeFalse -Because "$($file.Name) must never call Invoke-WebRequest"
            if ($file.Name -notin $script:GraphTransportFiles) {
                $code.Contains('Invoke-RestMethod') | Should -BeFalse -Because "$($file.Name) is not a Graph transport file and must go through the Graph helpers"
            }
        }
    }

    It "no write-verb Az/AzureAD/Mg cmdlets in Entra product code (comments stripped)" {
        foreach ($file in $script:EntraProductFiles) {
            $code = Get-StrippedCode -Path $file.FullName
            $code | Should -Not -Match '\b(New|Set|Update|Remove|Add|Enable|Disable)-(Az|AzureAD|Mg)[A-Za-z]' `
                -Because "$($file.Name) must be read-only"
        }
    }

    It "no non-GET Graph methods and no -AllowNonGet outside Future/EntraMap/Core/Graph.ps1" {
        foreach ($file in $script:EntraProductFiles) {
            if ($file.Name -eq 'Graph.ps1') { continue }
            $code = Get-StrippedCode -Path $file.FullName
            $code | Should -Not -Match "-Method\s+['""]?(POST|PATCH|PUT|DELETE)" `
                -Because "$($file.Name): the only non-GET allowed is the /`$batch envelope inside Graph.ps1"
            $code | Should -Not -Match '-AllowNonGet' `
                -Because "$($file.Name): non-GET opt-in is internal to Graph.ps1"
        }
    }

    It "Graph.ps1 forces every /`$batch inner request to GET" {
        $code = Get-StrippedCode -Path (Join-Path $projectRoot 'Future\EntraMap\Core\Graph.ps1')
        $code | Should -Match 'method\s*=\s*"GET"'
    }

    It "no bare Connect-AzAccount invocation (guidance strings allowed, calls are not)" {
        foreach ($file in $script:EntraProductFiles) {
            $code = Get-StrippedCode -Path $file.FullName
            $code | Should -Not -Match '(?m)^\s*Connect-AzAccount\b' `
                -Because "$($file.Name) may print the Connect-AzAccount guidance string but must never invoke it"
        }
    }

    It "CapabilityModel.Entra.ps1 itself contains no Graph/Azure call surface at all" {
        $code = Get-StrippedCode -Path (Join-Path $projectRoot 'Future\EntraMap\Capability\CapabilityModel.Entra.ps1')
        $code | Should -Not -Match '\b(Get-Az|Invoke-Az)[A-Za-z]'
        foreach ($pattern in @('Invoke-GraphCommand', 'Invoke-GraphBatch', 'Get-GraphToken', 'Invoke-RestMethod', 'Invoke-WebRequest')) {
            $code.Contains($pattern) | Should -BeFalse -Because "CapabilityModel.Entra.ps1 must never reference '$pattern'"
        }
    }
}
