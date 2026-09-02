#==============================================================================
# AzureMap v2 - Export/Summary.ps1
# Runs the export phase, then renders the clean sectioned console summary via
# Core/Console.ps1 (Show-AuditConsole). References $script:State.
#==============================================================================

function Show-AuditSummary {
    <#
    .SYNOPSIS
        Exports results (CSV/JSON/HTML) and renders the clean console summary.
    .DESCRIPTION
        1. Writes exports according to $script:State.Config.ExportFormats.
        2. Delegates all console rendering to Show-AuditConsole, which prints a
           sectioned summary (Authentication, Scope, Collection, Check Execution,
           Findings, Top Findings, Not Evaluated / Permission Issues) followed
           by the report locations block (full paths, "Done.") and honors
           -Quiet / -VerboseOutput. No raw objects are printed.
    #>
    [CmdletBinding()]
    param()

    $results = $script:State.Results

    # ---- Export phase (HTML styling untouched) ----
    if (-not $script:State.Config.Quiet) { Write-UiHost -Text 'Writing report...' -Color Cyan }
    $exportStart  = Get-Date
    $baseName     = "AzureSecurityAudit-$($script:State.Timestamp)"
    $createdFiles = [System.Collections.Generic.List[string]]::new()
    $formats      = $script:State.Config.ExportFormats

    foreach ($format in $formats) {
        switch ($format.ToUpper()) {
            "CSV" {
                $csvFiles = Export-ResultsCsv -Results $results -BaseName $baseName
                foreach ($f in $csvFiles) { $createdFiles.Add($f) }
            }
            "JSON" {
                $jsonFile = Export-ResultsJson -Results $results -BaseName $baseName
                $createdFiles.Add($jsonFile)
            }
            "HTML" {
                if ($script:State.Config.GenerateHTMLReport) {
                    # Pentester dashboard layout is the default; 'Classic' is
                    # the legacy opt-in (byte-unchanged).
                    if ($script:State.Config.ReportLayout -eq 'Pentester') {
                        $htmlFile = Export-ResultsHtmlPentester -Results $results -OutputPath "$baseName.html"
                    } else {
                        $htmlFile = Export-ResultsHtml -Results $results -OutputPath "$baseName.html"
                    }
                    $createdFiles.Add($htmlFile)
                }
            }
        }
    }

    $script:State.Timing.Phases['Export'] = [Math]::Round(((Get-Date) - $exportStart).TotalSeconds, 1)

    # Resolve relative export names to full paths so the console can print
    # exactly where each file landed (exports are written to the CWD).
    $createdFullPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $createdFiles) {
        $createdFullPaths.Add($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("$f"))
    }

    # ---- Clean console summary ----
    if (Get-Command -Name "Show-AuditConsole" -ErrorAction SilentlyContinue) {
        Show-AuditConsole -ExportedFiles $createdFullPaths
    }
}
