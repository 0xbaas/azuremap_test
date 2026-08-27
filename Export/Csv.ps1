#==============================================================================
# AzureMap v2 - Export/Csv.ps1
# CSV export: summary findings + detailed evidence rows.
# References $script:State for logging.
#==============================================================================

function Export-ResultsCsv {
    <#
    .SYNOPSIS
        Exports audit results to summary and detailed CSV files.
    .DESCRIPTION
        Creates two CSV files:
          1. Summary CSV   -- one row per finding with flattened Tags.
          2. Detailed CSV  -- one row per evidence item with finding metadata
             plus up to 20 evidence properties (complex sub-objects serialized
             to JSON).
    .PARAMETER Results
        Array of finding objects produced by Write-Finding.
    .PARAMETER BaseName
        File name stem (without extension). Two files are created:
        <BaseName>.csv and <BaseName>-Detailed.csv.
    .OUTPUTS
        [string[]] Paths of files created.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Results,

        [Parameter(Mandatory)]
        [string]$BaseName
    )

    $createdFiles = [System.Collections.Generic.List[string]]::new()

    try {
        # ---- Summary CSV ----
        $csvFile = "$BaseName.csv"

        $exportData = $Results | Select-Object `
            FindingId,
            Timestamp,
            CheckId,
            Severity,
            Finding,
            Count,
            Service,
            Status,
            SummaryText,
            SubscriptionId,
            SubscriptionName,
            ResourceId,
            ResourceName,
            DiscoveredResourceCount,
            EvaluatedResourceCount,
            SkippedResourceCount,
            FailedCollectionCount,
            CollectionStatus,
            CompleteEvaluation,
            PartialEvaluation,
            CoverageSummary,
            Confidence,
            FindingType,
            SeverityReason,
            IsInventoryOnly,
            DataPlaneRequired,
            ManualValidationRequired,
            @{Name = "Tags"; Expression = {
                if ($_.Tags) {
                    ($_.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
                } else { "" }
            }},
            Remediation

        $exportData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        if (Test-RedactionEnabled) {
            Protect-SensitiveFile -Path $csvFile
        }
        $createdFiles.Add($csvFile)
        Write-AuditLog -Message "Exported results to CSV: $csvFile" -Level INFO

        # ---- Detailed CSV (one row per evidence item) ----
        $detailedResults = [System.Collections.Generic.List[object]]::new()

        foreach ($result in $Results | Where-Object { $_.Count -gt 0 -and $_.Evidence }) {
            foreach ($evidence in $result.Evidence) {
                $flatEvidence = [ordered]@{
                    FindingId        = $result.FindingId
                    FindingCheckId   = $result.CheckId
                    FindingStatus    = $result.Status
                    FindingMessage   = $result.Finding
                    FindingSeverity  = $result.Severity
                    FindingService   = $result.Service
                    SubscriptionId   = $result.SubscriptionId
                    SubscriptionName = $result.SubscriptionName
                }

                $propCount = 0
                if ($evidence -is [PSCustomObject] -or $evidence -is [System.Management.Automation.PSObject]) {
                    foreach ($prop in $evidence.PSObject.Properties | Select-Object -First 20) {
                        $propCount++
                        $value = $prop.Value
                        if ($value -is [System.Collections.IDictionary] -or $value -is [System.Array]) {
                            $value = ($value | ConvertTo-Json -Compress -Depth 2)
                        } elseif ($value -is [PSCustomObject]) {
                            $value = ($value | ConvertTo-Json -Compress -Depth 2)
                        }
                        $flatEvidence[$prop.Name] = $value
                    }
                } else {
                    $flatEvidence["Value"] = $evidence.ToString()
                }

                $detailedResults.Add([PSCustomObject]$flatEvidence)
            }
        }

        if ($detailedResults.Count -gt 0) {
            $detailedFile = "$BaseName-Detailed.csv"
            $detailedResults | Export-Csv -Path $detailedFile -NoTypeInformation -Encoding UTF8
            if (Test-RedactionEnabled) {
                Protect-SensitiveFile -Path $detailedFile
            }
            $createdFiles.Add($detailedFile)
            Write-AuditLog -Message "Exported detailed findings to: $detailedFile ($($detailedResults.Count) records)" -Level INFO
        }
    }
    catch {
        Write-AuditLog -Message "Failed to export CSV results: $_" -Level ERROR
    }

    return @($createdFiles)
}
