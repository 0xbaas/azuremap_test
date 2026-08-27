#==============================================================================
# AzureMap v2 - Core/Redaction.ps1
# Optional sensitive-value redaction for exports and operator-facing output.
# Enabled via -RedactSensitive (masks account/UPN emails and GUIDs - tenant,
# subscription, object IDs, which also sanitizes resource IDs) and
# -RedactPublicIps (additionally masks IPv4 addresses).
# Never redacts structure: only text values are masked, exports stay valid.
#==============================================================================

function Test-RedactionEnabled {
    <#
    .SYNOPSIS
        Returns $true when -RedactSensitive is active for this run.
    #>
    return [bool]($script:State -and $script:State.Config -and $script:State.Config.RedactSensitive)
}

function Protect-SensitiveText {
    <#
    .SYNOPSIS
        Masks sensitive identifiers in a text value when redaction is enabled.
    .DESCRIPTION
        Masks:
          * email addresses / account UPNs          -> ***@***
            (including B2B guest UPNs with the '#EXT#' marker)
          * GUIDs (tenant, subscription, object IDs -> ********-****-****-****-************
            and therefore the subscription GUID embedded in ARM resource IDs)
          * IPv4 addresses (only with -RedactPublicIps) -> x.x.x.x
        Owner/admin/person-style fields are covered insofar as they contain
        emails or object IDs; free-text person names cannot be detected
        reliably and are NOT masked (documented limitation).
        No-op when Config.RedactSensitive is off.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    if (-not (Test-RedactionEnabled)) { return $Text }

    $t = $Text
    # emails / UPNs ('#' included so B2B guest UPNs like user_dom.com#EXT#@tenant
    # are fully masked, not left with an unmasked local-part remnant)
    $t = [regex]::Replace($t, '[\w.+\-#]+@[\w-]+(\.[\w-]+)+', '***@***')
    # GUIDs (tenant IDs, subscription IDs, object IDs, GUIDs inside resource IDs)
    $t = [regex]::Replace($t, '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', '********-****-****-****-************')
    # public IPv4 (opt-in)
    if ($script:State.Config.RedactPublicIps) {
        $t = [regex]::Replace($t, '\b(?:\d{1,3}\.){3}\d{1,3}\b', 'x.x.x.x')
    }
    return $t
}

function Protect-SensitiveFile {
    <#
    .SYNOPSIS
        Applies Protect-SensitiveText to an entire exported file in place.
    .DESCRIPTION
        Used for formats written directly to disk (CSV). No-op when redaction
        is disabled. Preserves file encoding (UTF8).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-RedactionEnabled)) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    $redacted = Protect-SensitiveText -Text $content
    if ($redacted -ne $content) {
        Set-Content -LiteralPath $Path -Value $redacted -Encoding UTF8 -NoNewline -ErrorAction Stop
    }
}
