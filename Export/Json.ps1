#==============================================================================
# AzureMap v2 - Export/Json.ps1
# Structured JSON export with metadata, summary, findings, and failed subs.
# References $script:State for ExecutedChecks, FailedSubscriptions, Metadata.
#==============================================================================

function Get-JsonSummaryBlock {
    <#
    .SYNOPSIS
        Builds the JSON Summary block from the corrected run diagnostics.
    .DESCRIPTION
        Uses Get-RunDiagnostics so the numbers match the console summary and use
        the real status vocabulary (Pass/Fail/Error/NotEvaluated/Skipped) - the
        old block filtered Status -eq "Success"/"Failed", which never matched and
        always reported 0. TotalFindings counts real FAIL finding GROUPS only
        (Count>0 and NOT NotEvaluated/Skipped), so Count=0 PASS records and
        NotEvaluated records can never inflate or hide the true finding count.
    #>
    [CmdletBinding()]
    param([array]$Results)

    $diag = Get-RunDiagnostics
    $sev  = $diag.BySeverity

    return [ordered]@{
        TotalChecksRun     = $diag.ChecksAttempted
        ChecksSuccessful   = $diag.Passed          # Status = Pass
        ChecksFailed       = $diag.Failed          # Status = Fail
        ChecksPartial      = $diag.Partial         # Status = Partial
        ChecksError        = $diag.Errors          # Status = Error
        ChecksNotEvaluated = $diag.NotEvaluated    # Status = NotEvaluated
        ChecksNotApplicable = $diag.NotApplicable  # Status = NotApplicable (no relevant resources in scope)
        ChecksSkipped      = $diag.Skipped         # Status = Skipped
        TotalFindings      = $diag.FindingGroups   # real FAIL groups (Count>0, not NotEvaluated)
        AffectedResources  = $diag.AffectedResources
        SeverityBreakdown  = [ordered]@{
            Critical = [int]$sev['CRITICAL']
            High     = [int]$sev['HIGH']
            Medium   = [int]$sev['MEDIUM']
            Low      = [int]$sev['LOW']
            Info     = [int]$sev['INFO']
        }
    }
}

function Export-ResultsJson {
    <#
    .SYNOPSIS
        Exports audit results to a structured JSON file.
    .DESCRIPTION
        JSON structure:
          - Metadata       : timestamp, account, tenant, tool info
          - Summary        : check counts, severity breakdown
          - ExecutedChecks  : from $script:State.ExecutedChecks
          - Findings       : evidence truncated to 10 items; complex objects
                             replaced with placeholder text
          - FailedSubscriptions
        Depth is capped at 5 to prevent JSON explosion.
    .PARAMETER Results
        Array of finding objects produced by Write-Finding.
    .PARAMETER BaseName
        File name stem (without extension).
    .OUTPUTS
        [string] Path of the created JSON file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Results,

        [Parameter(Mandatory)]
        [string]$BaseName
    )

    $jsonFile = "$BaseName.json"

    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        $account = if ($ctx -and $ctx.Account) { $ctx.Account.Id } else { "Unknown" }
        $tenant  = if ($ctx -and $ctx.Tenant)  { $ctx.Tenant.Id }  else { "Unknown" }

        # Flatten evidence per finding (max 10 items, complex objects replaced)
        $findingsForExport = $Results | ForEach-Object {
            $finding = $_
            $exportFinding = $finding | Select-Object FindingId, Timestamp, CheckId, Severity, Finding,
                Count, EvidenceCount, Service, Status, SubscriptionId, SubscriptionName,
                ResourceId, ResourceName, Remediation,
                SummaryText, DiscoveredResourceCount, EvaluatedResourceCount, SkippedResourceCount,
                FailedCollectionCount, CollectionStatus, CompleteEvaluation, PartialEvaluation,
                CoverageSummary, Confidence, FindingType, ApiSources, DataPlaneRequired,
                ManualValidationRequired

            if ($finding.Evidence -and @($finding.Evidence).Count -gt 0) {
                $evidenceSample = $finding.Evidence | Select-Object -First 10 | ForEach-Object {
                    $ev = $_
                    if ($ev -is [PSCustomObject] -or $ev -is [System.Management.Automation.PSObject]) {
                        $evHash = @{}
                        foreach ($prop in $ev.PSObject.Properties | Select-Object -First 15) {
                            $val = $prop.Value
                            if ($val -is [System.Collections.IDictionary] -or $val -is [System.Array]) {
                                $evHash[$prop.Name] = "Complex object (see detailed CSV)"
                            } elseif ($val -is [PSCustomObject]) {
                                $evHash[$prop.Name] = "Nested object (see detailed CSV)"
                            } else {
                                $evHash[$prop.Name] = $val
                            }
                        }
                        $evHash
                    } else {
                        @{ Value = $ev.ToString() }
                    }
                }
                $exportFinding | Add-Member -NotePropertyName "EvidenceSample" -NotePropertyValue $evidenceSample -Force
                $exportFinding | Add-Member -NotePropertyName "EvidenceTotalCount" -NotePropertyValue $finding.EvidenceCount -Force
            }
            $exportFinding
        }

        $jsonOutput = @{
            Metadata = @{
                GeneratedAt   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Account       = $account
                Tenant        = $tenant
                ToolName      = $script:State.Metadata.ToolName
                ScriptVersion = $script:State.Metadata.Version
                Author        = $script:State.Metadata.Author
                # Phase B3: whether data-plane checks (STORAGE-004, KEYVAULT-003)
                # were enabled for this run. Skipped data-plane checks appear in
                # ExecutedChecks with Status=Skipped and DataPlaneRequired=$true.
                DataPlaneIncluded = [bool]$script:State.Config.IncludeDataPlane
                Note          = "Evidence is truncated to 10 items per finding. See detailed CSV for complete evidence."
            }
            Summary = (Get-JsonSummaryBlock -Results $Results)
            Footprint           = $script:State.Footprint
            ExecutedChecks      = $script:State.ExecutedChecks
            Performance         = (Get-PerformanceSummary -Top 10)
            Findings            = $findingsForExport
            FailedSubscriptions = $script:State.FailedSubscriptions
        }

        $jsonText = $jsonOutput | ConvertTo-Json -Depth 5
        if (Test-RedactionEnabled) {
            $jsonText = Protect-SensitiveText -Text $jsonText
            Write-AuditLog -Message "Redaction active (-RedactSensitive): emails/GUIDs masked in JSON export." -Level INFO
        }
        $jsonText | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-AuditLog -Message "Exported results to JSON: $jsonFile (evidence truncated to prevent size explosion)" -Level INFO
    }
    catch {
        Write-AuditLog -Message "Failed to export JSON results: $_" -Level ERROR
    }

    return $jsonFile
}
