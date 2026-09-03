#==============================================================================
# EntraMap (parked) - Future/EntraMap/Tests/Phase15.GraphSafety.Tests.ps1
# Non-interactive runtime guard for the parked Graph core:
#   * every Invoke-RestMethod call site in Core\Graph.ps1 passes
#     -UseBasicParsing explicitly (PS 5.1 "Script Execution Risk" prompt must
#     be impossible even if the session pin is lost).
# Moved from Tests/Shared/Phase15.SmokeCleanup.Tests.ps1 when the active
# suite was decoupled from the parked tree. Mocked/local only.
#==============================================================================

BeforeAll {
    # Parked under Future/EntraMap/Tests: repo root is three levels up.
    $script:RepoRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -Parent
}

Describe "Graph.ps1 non-interactive web calls" {
    It "every Invoke-RestMethod call site passes -UseBasicParsing explicitly" {
        $graph = Get-Content (Join-Path $script:RepoRoot 'Future\EntraMap\Core\Graph.ps1') -Raw
        $callCount = ([regex]::Matches($graph, 'Invoke-RestMethod')).Count
        $callCount | Should -BeGreaterThan 0
        ([regex]::Matches($graph, 'UseBasicParsing')).Count | Should -BeGreaterOrEqual $callCount
    }
}
