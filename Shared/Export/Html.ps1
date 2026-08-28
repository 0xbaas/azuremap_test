#==============================================================================
# AzureMap v2 - Export/Html.ps1
# Self-contained, offline-viewable HTML report (embedded CSS, no JavaScript,
# no external dependencies). Dark-mode friendly via prefers-color-scheme.
#
# Design rules:
#   * Explicit Status is ALWAYS preserved - the report never recomputes
#     PASS/FAIL from Count. A Count=0 NOTEVALUATED renders as NOTEVALUATED.
#   * Count=0 coverage records (PASS/PARTIAL) render as informational coverage
#     notes, never as "successful CRITICAL findings".
#   * Raw Azure exception blocks and stack traces stay out of the report body
#     (log file only); only sanitized, escaped, length-capped text is rendered.
#==============================================================================

function Escape-HtmlContent {
    <#
    .SYNOPSIS
        Escapes the five HTML-sensitive characters to prevent XSS.
    .OUTPUTS
        [string] Safe HTML text.
    #>
    [CmdletBinding()]
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return "" }

    $Text = Protect-SensitiveText -Text $Text

    return $Text -replace '&', '&amp;' `
                 -replace '<', '&lt;' `
                 -replace '>', '&gt;' `
                 -replace '"', '&quot;' `
                 -replace "'", '&#39;'
}

function Group-HtmlFindings {
    <#
    .SYNOPSIS
        Aggregates per-subscription finding records into one row per finding.
    .DESCRIPTION
        Multi-subscription checks emit one record per subscription (e.g. 28
        identical AZURE-EXPOSURE-001 rows). For the report body these are
        grouped by CheckId+Severity+Service+Finding: Count is summed, the
        subscription span is counted (excluding the 'Multiple' aggregate
        marker), evidence is concatenated, and coverage degrades to Partial if
        ANY record in the group was partial. Per-subscription rows remain in
        JSON/CSV exports untouched - this grouping is display-only.
    .OUTPUTS
        Array of grouped finding objects (superset of the input fields).
    #>
    [CmdletBinding()]
    param([object[]]$Findings)

    $grouped = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Findings | Group-Object -Property { "$($_.CheckId)|$($_.Severity)|$($_.Service)|$($_.Finding)" })) {
        $first  = $g.Group[0]
        $count  = 0
        $anyPartial  = $false
        $allComplete = $true
        $evidence = New-Object System.Collections.Generic.List[object]
        $subs = New-Object System.Collections.Generic.List[string]
        foreach ($r in $g.Group) {
            if ($null -ne $r.Count) { $count += [int]$r.Count }
            if ($r.PartialEvaluation) { $anyPartial = $true }
            if (-not $r.CompleteEvaluation) { $allComplete = $false }
            foreach ($e in @($r.Evidence)) { if ($null -ne $e) { $evidence.Add($e) } }
            $sn = "$($r.SubscriptionName)"
            if ($sn -and $sn -ne 'Multiple' -and -not $subs.Contains($sn)) { $subs.Add($sn) }
        }
        $grouped.Add([PSCustomObject]@{
            CheckId                  = $first.CheckId
            Severity                 = $first.Severity
            Service                  = $first.Service
            Finding                  = $first.Finding
            Count                    = $count
            Status                   = $first.Status
            Confidence               = $first.Confidence
            PartialEvaluation        = $anyPartial
            CompleteEvaluation       = ($allComplete -and -not $anyPartial)
            SummaryText              = $first.SummaryText
            CoverageSummary          = $first.CoverageSummary
            Remediation              = $first.Remediation
            DataPlaneRequired        = $first.DataPlaneRequired
            ManualValidationRequired = $first.ManualValidationRequired
            IsInventoryOnly          = $first.IsInventoryOnly
            RecordCount              = $g.Count
            SubscriptionSpan         = $subs.Count
            Evidence                 = $evidence.ToArray()
        })
    }
    # NOTE: no @(...) around the generic List - PS 5.1 throws "Argument types do
    # not match" on that coercion. ToArray() enumerated onto the pipeline is safe
    # and lets callers wrap with @() without nesting.
    return $grouped.ToArray()
}

function Get-HtmlStatusPill {
    <#
    .SYNOPSIS
        Renders a status pill. Explicit status only - empty status renders as
        NOTEVALUATED (never assumed PASS).
    #>
    [CmdletBinding()]
    param([string]$Status)

    $s = "$Status".ToUpper()
    if (-not $s) { $s = 'NOTEVALUATED' }
    $cls = switch ($s) {
        'PASS'         { 'st-pass' }
        'FAIL'         { 'st-fail' }
        'PARTIAL'      { 'st-partial' }
        'WARNING'      { 'st-warning' }
        'INVENTORY'    { 'st-inventory' }
        'NOTEVALUATED' { 'st-noteval' }
        'NOTAPPLICABLE'{ 'st-notapp' }
        'ERROR'        { 'st-error' }
        'SKIPPED'      { 'st-skipped' }
        default        { 'st-noteval' }
    }
    $label = if ($s -eq 'NOTAPPLICABLE') { 'N/A' } else { $s }
    return "<span class=""pill $cls"">$label</span>"
}

function Get-HtmlSeverityPill {
    [CmdletBinding()]
    param([string]$Severity)
    $s = "$Severity".ToUpper()
    if (-not $s) { return '<span class="pill sv-none">-</span>' }
    return "<span class=""pill sv-$($s.ToLower())"">$s</span>"
}

function ConvertTo-HtmlCompactValue {
    <#
    .SYNOPSIS
        Renders an evidence property value as short, escaped, single-line text.
        Nested objects/hashtables are compacted; long values are truncated.
    #>
    [CmdletBinding()]
    param([object]$Value, [int]$MaxLength = 120)

    if ($null -eq $Value) { return '' }
    $text = $null
    if ($Value -is [string]) {
        $text = $Value
    }
    elseif ($Value -is [System.Collections.IDictionary]) {
        $pairs = @()
        foreach ($k in $Value.Keys) { $pairs += "$k=$($Value[$k])" }
        $text = ($pairs -join '; ')
    }
    elseif ($Value -is [System.Collections.IEnumerable]) {
        $text = (@($Value) -join ', ')
    }
    else {
        $text = "$Value"
    }
    $text = ($text -replace '\s+', ' ').Trim()
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + '...' }
    return (Escape-HtmlContent -Text $text)
}

function ConvertTo-HtmlEvidenceTable {
    <#
    .SYNOPSIS
        Builds a clean evidence table for a finding's affected components.
    .DESCRIPTION
        Columns are the union of evidence property names (preferred resource
        columns first). Rows are capped with a visible truncation note; the
        Write-Finding 1000-row cap marker (_Truncated) is surfaced as well.
    #>
    [CmdletBinding()]
    param(
        [object]$Evidence,
        [int]$MaxRows = 50
    )

    $rows = @()
    if ($null -ne $Evidence) {
        if ($Evidence -is [System.Collections.IEnumerable] -and $Evidence -isnot [string]) {
            foreach ($e in $Evidence) { $rows += $e }
        } else {
            $rows += $Evidence
        }
    }
    if ($rows.Count -eq 0) { return '<p class="muted">No per-resource evidence recorded for this finding.</p>' }

    $preferred = @('ResourceName','StorageAccount','StorageAccountName','VaultName','ServerName','Name',
                   'ResourceType','ResourceGroup','ResourceGroupName','SubscriptionName','Location',
                   'Risk','Issue','Reason','Reasons','Role','RoleDefinitionName','Principal','PrincipalName','Scope')
    $propNames = New-Object System.Collections.Generic.List[string]
    foreach ($name in $preferred) {
        if ($rows[0].PSObject.Properties.Name -contains $name) { $propNames.Add($name) }
    }
    foreach ($r in $rows) {
        foreach ($p in $r.PSObject.Properties.Name) {
            if ($p -eq '_Truncated') { continue }
            if (-not $propNames.Contains($p) -and $preferred -notcontains $p) { $propNames.Add($p) }
        }
    }
    if ($propNames.Count -eq 0) { return '<p class="muted">Evidence recorded in non-tabular form.</p>' }

    $shown = $rows
    $truncatedNote = ''
    if ($rows.Count -gt $MaxRows) {
        $shown = $rows[0..($MaxRows - 1)]
        $truncatedNote = "<p class=""trunc-note"">Truncated: showing first $MaxRows of $($rows.Count) affected components. Full evidence is in the JSON/CSV export.</p>"
    }
    if ($rows[0].PSObject.Properties.Name -contains '_Truncated') {
        $truncatedNote = "<p class=""trunc-note"">Evidence was capped during collection ($($rows[0]._Truncated)). Full detail in the log.</p>" + $truncatedNote
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table class="evidence"><thead><tr>')
    foreach ($p in $propNames) { [void]$sb.Append("<th>$(Escape-HtmlContent -Text $p)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $shown) {
        [void]$sb.Append('<tr>')
        foreach ($p in $propNames) {
            $v = $null
            if ($r.PSObject.Properties.Name -contains $p) { $v = $r.$p }
            [void]$sb.Append("<td>$(ConvertTo-HtmlCompactValue -Value $v)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return ($truncatedNote + $sb.ToString())
}

function Add-HtmlCapabilitySection {
    <#
    .SYNOPSIS
        Appends the Phase B2 "Capability insights" section to the HTML report.
    .DESCRIPTION
        Renders the top 25 grouped capability insights as collapsible cards
        (severity, confidence, affected resources, why it matters, source
        checks, evidence summary, recommended review) plus a capped graph
        table of modeled capability edges. The model is read-only: it was
        built from already-collected metadata without retrieving keys,
        secrets, tokens or content.
    .PARAMETER StringBuilder
        The report StringBuilder to append to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Text.StringBuilder]$StringBuilder
    )

    $model = $script:State.CapabilityModel
    if (-not $model) { return }

    $sb = $StringBuilder
    [void]$sb.Append('<section id="capability"><h2>Capability Insights</h2>')
    $capIntro = '<p class="muted">Read-only capability / attack-path modeling over already-collected metadata. These insights connect findings into higher-order risk (public exposure + privileged identity, shared key + key-capable RBAC, detection gaps on exposed resources). Nothing here is exploitation: no keys, secrets, tokens or content were retrieved, and no write actions were performed.</p>'
    if (Test-EntraMapProductLoaded) {
        $capIntro = '<p class="muted">Read-only capability / attack-path modeling over already-collected metadata. These insights connect findings into higher-order risk (standing privileged roles without PIM or MFA, dangerous app permissions combined with weak ownership or federation, guest privileged access, Conditional Access gaps). Nothing here is exploitation: no secrets, tokens, keys or content were retrieved, and no write actions were performed.</p>'
    }
    [void]$sb.Append($capIntro)

    $insights = @($model.Insights)
    if ($insights.Count -eq 0) {
        [void]$sb.Append('<p class="muted">No capability insights were modeled from this run''s findings.</p>')
    } else {
        [void]$sb.Append("<div class=""cards""><div class=""card""><div class=""num"">$($insights.Count)</div><div class=""lbl"">Capability Insights</div></div>")
        [void]$sb.Append("<div class=""card""><div class=""num"">$($model.Summary.NodeCount)</div><div class=""lbl"">Graph Nodes</div></div>")
        [void]$sb.Append("<div class=""card""><div class=""num"">$($model.Summary.EdgeCount)</div><div class=""lbl"">Graph Edges</div></div>")
        if ($model.Summary.HighestSeverity) {
            [void]$sb.Append("<div class=""card""><div class=""num"">$(Get-HtmlSeverityPill -Severity $model.Summary.HighestSeverity)</div><div class=""lbl"">Highest Insight Severity</div></div>")
        }
        [void]$sb.Append('</div>')

        $shown = @($insights | Select-Object -First 25)
        foreach ($ci in $shown) {
            $checks = Escape-HtmlContent -Text (@($ci.SourceCheckIds) -join ', ')
            [void]$sb.Append("<details><summary>$(Get-HtmlSeverityPill -Severity $ci.Severity) $(Escape-HtmlContent -Text $ci.Title) <span class=""muted"">($(Escape-HtmlContent -Text $ci.Id) &middot; $($ci.ImpactedResourceCount) $(Escape-HtmlContent -Text $ci.ResourceUnit) &middot; confidence $(Escape-HtmlContent -Text $ci.Confidence))</span></summary>")
            [void]$sb.Append('<div class="body"><dl class="kv">')
            [void]$sb.Append("<dt>Why it matters</dt><dd>$(Escape-HtmlContent -Text $ci.Description)</dd>")
            if ($ci.EvidenceSummary)   { [void]$sb.Append("<dt>Evidence summary</dt><dd>$(Escape-HtmlContent -Text $ci.EvidenceSummary)</dd>") }
            [void]$sb.Append("<dt>Source checks</dt><dd>$checks</dd>")
            if ($ci.RecommendedReview) { [void]$sb.Append("<dt>Recommended review</dt><dd>$(Escape-HtmlContent -Text $ci.RecommendedReview)</dd>") }
            [void]$sb.Append('</dl>')
            $res = @($ci.ImpactedResources)
            if ($res.Count -gt 0) {
                [void]$sb.Append('<h3>Affected resources</h3><ul>')
                foreach ($line in @($res | Select-Object -First 25)) {
                    [void]$sb.Append("<li>$(Escape-HtmlContent -Text $line)</li>")
                }
                [void]$sb.Append('</ul>')
                if ($res.Count -gt 25) { [void]$sb.Append("<p class=""trunc-note"">Showing 25 of $($res.Count) listed resources; see JSON export for the full insight.</p>") }
                if ([int]$ci.ImpactedResourceCount -gt $res.Count) { [void]$sb.Append("<p class=""trunc-note"">Insight covers $($ci.ImpactedResourceCount) $(Escape-HtmlContent -Text $ci.ResourceUnit) in total; the list above is capped.</p>") }
            }
            [void]$sb.Append('</div></details>')
        }
        if ($insights.Count -gt 25) {
            [void]$sb.Append("<p class=""trunc-note"">Showing top 25 of $($insights.Count) insights. See the JSON export (CapabilityModel) for the complete set.</p>")
        }
    }

    # Graph table (capped): modeled capability edges.
    $edges = @($model.Edges)
    if ($edges.Count -gt 0) {
        $nodeNames = @{}
        foreach ($n in @($model.Nodes)) { $nodeNames["$($n.Id)"] = "$($n.Name)" }
        $edgeRows = @($edges | Select-Object -First 200)
        [void]$sb.Append("<h3>Capability Graph <span class=""muted"">($($edges.Count) edge(s), top 200 shown)</span></h3>")
        [void]$sb.Append('<table><thead><tr><th>Source</th><th>Capability</th><th>Target</th><th>Supporting findings</th><th>Confidence</th><th>Severity</th></tr></thead><tbody>')
        foreach ($e in $edgeRows) {
            $fromName = $(if ($nodeNames.ContainsKey("$($e.From)")) { $nodeNames["$($e.From)"] } else { "$($e.From)" })
            $toName   = $(if ($nodeNames.ContainsKey("$($e.To)"))   { $nodeNames["$($e.To)"] }   else { "$($e.To)" })
            $reason   = $(if ($e.Reason) { " $(ConvertTo-HtmlCompactValue -Value $e.Reason -MaxLength 160)" } else { '' })
            [void]$sb.Append("<tr><td>$(Escape-HtmlContent -Text $fromName)</td><td>$(ConvertTo-HtmlCompactValue -Value $e.Capability -MaxLength 120)$reason</td><td>$(Escape-HtmlContent -Text $toName)</td><td>$(Escape-HtmlContent -Text (@($e.SourceCheckIds) -join ', '))</td><td>$(Escape-HtmlContent -Text $e.Confidence)</td><td>$(Get-HtmlSeverityPill -Severity $e.Severity)</td></tr>")
        }
        [void]$sb.Append('</tbody></table>')
        if ($edges.Count -gt 200) { [void]$sb.Append("<p class=""trunc-note"">Graph capped at 200 of $($edges.Count) edges; see the JSON export for the full model.</p>") }
    }
    if ($model.Limits -and @($model.Limits.Notes).Count -gt 0) {
        [void]$sb.Append("<p class=""muted"">Model limits: $(Escape-HtmlContent -Text (@($model.Limits.Notes) -join ' | '))</p>")
    }
    [void]$sb.Append('</section>')
}

function Export-ResultsHtml {
    <#
    .SYNOPSIS
        Generates the self-contained HTML audit report.
    .DESCRIPTION
        Sections: executive summary cards, coverage summary, findings overview,
        affected components (per-finding evidence tables), per-check sections
        (collapsible), Not Evaluated/Partial/Errors, failed subscriptions.
        Explicit check/finding Status is preserved verbatim - never recomputed.
    .PARAMETER Results
        Array of finding objects produced by Write-Finding.
    .PARAMETER OutputPath
        Destination HTML file path.
    .OUTPUTS
        [string] Path of the created HTML file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    try {
        $diag = Get-RunDiagnostics
        $exec = @($script:State.ExecutedChecks)
        $ctx  = Get-AzContext -ErrorAction SilentlyContinue
        $account = Escape-HtmlContent -Text $(if ($ctx -and $ctx.Account) { $ctx.Account.Id } else { 'Unknown' })
        $tenant  = Escape-HtmlContent -Text $(if ($ctx -and $ctx.Tenant)  { $ctx.Tenant.Id }  else { 'Unknown' })
        $mode    = Get-RunModeLabel
        $dpMode  = if ($script:State.Config.IncludeDataPlane) { 'enabled (-IncludeDataPlane)' } else { 'disabled (default; -IncludeDataPlane to enable)' }

        # Real finding groups = rows representing affected resources. Coverage
        # records (Count=0) and NotEvaluated/Error side records are excluded here;
        # they appear in the coverage / not-evaluated sections instead.
        $findingGroups = @($Results | Where-Object {
            ($null -ne $_.Count) -and ([int]$_.Count -gt 0) -and
            ("$($_.Status)".ToUpper() -notin @('NOTEVALUATED','ERROR','SKIPPED'))
        })

        # Scope: union of evaluated subscriptions from coverage metadata.
        $scopeSubs = New-Object System.Collections.Generic.List[string]
        foreach ($c in $exec) {
            if ($c.Coverage) {
                foreach ($s in @($c.Coverage.SubscriptionsEvaluated)) {
                    if ($s -and -not $scopeSubs.Contains($s)) { $scopeSubs.Add($s) }
                }
            }
        }
        $scopeText = if ($scopeSubs.Count -gt 0) { "$($scopeSubs.Count) subscription(s) evaluated" } else { 'See per-check coverage' }

        $sevOrder = @{ CRITICAL = 1; HIGH = 2; MEDIUM = 3; LOW = 4; INFO = 5 }

        # BAAS house style: dark-mode first (security dashboard look), light scheme
        # only as an explicit prefers-color-scheme: light fallback.
        $css = @'
<style>
:root {
  /* Official BAAS / AzureMap dark palette */
  --bg:#111214; --header:#16171A; --panel:#1D1F23; --panel2:#202227; --control:#202227;
  --panel-light:#23262B; --line:#30343A; --ink:#F1F3F5; --muted:#9AA5B1;
  --accent:#38A8DC; --accent-dark:#163746; --brand:#38A8DC;
  --pass:#5FBF7A; --fail:#E05D5D; --partial:#D6A84B;
  --warning:#D6A84B; --noteval:#9AA5B1; --error:#FF6B6B; --skipped:#6F7782;
  --crit:#F05252; --high:#E68A3A; --med:#D6A84B; --low:#9BE7A1; --low-ink:#12301A; --info:#38A8DC; --notapp:#6F7782;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg:#f5f6f8; --header:#ffffff; --panel:#ffffff; --panel2:#f0f2f5; --control:#f0f2f5;
    --panel-light:#f0f2f5; --line:#d7dae0; --ink:#1b1b1f; --muted:#5f6368;
    --accent:#0f6cbd; --accent-dark:#dff0fa; --brand:#1a7f37;
    --pass:#107c10; --fail:#d13438; --partial:#b35900;
    --warning:#8a5a00; --noteval:#5a5a5a; --error:#a4262c; --skipped:#8a8886;
    --crit:#a4262c; --high:#ca5010; --med:#b35900; --low:#0f6cbd; --info:#0f6cbd; --notapp:#8a8886;
  }
}
* { box-sizing:border-box; }
body { font-family:"Segoe UI",SegoeUI,Arial,sans-serif; margin:0; background:var(--bg); color:var(--ink); line-height:1.5; }
header.topbar { background:linear-gradient(135deg, var(--header) 0%, var(--panel) 100%); border-bottom:3px solid var(--accent); padding:28px 32px; }
header.topbar h1 { margin:0; font-size:1.7rem; letter-spacing:.01em; }
header.topbar h1 .ver { color:var(--accent); font-size:1rem; font-weight:600; margin-left:8px; }
header.topbar .tagline { color:var(--muted); margin:2px 0 10px 0; font-size:.95rem; }
header.topbar .brand { color:var(--brand); font-weight:600; }
header.topbar .meta { color:var(--muted); font-size:.88rem; display:flex; flex-wrap:wrap; gap:8px 20px; }
nav { background:var(--panel); border-bottom:1px solid var(--line); padding:9px 32px; position:sticky; top:0; z-index:10; }
nav a { color:var(--accent); text-decoration:none; margin-right:20px; font-size:.88rem; font-weight:600; }
nav a:hover { text-decoration:underline; }
main { padding:26px 32px 60px 32px; max-width:1500px; margin:0 auto; }
section { margin-bottom:38px; }
h2 { font-size:1.25rem; border-bottom:2px solid var(--accent); padding-bottom:7px; margin:0 0 16px 0; }
h3 { font-size:1.02rem; margin:18px 0 8px 0; }
.cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(165px,1fr)); gap:14px; margin-bottom:14px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; transition:border-color .15s, transform .1s; }
a.card { text-decoration:none; color:inherit; display:block; }
a.card:hover { border-color:var(--accent); transform:translateY(-2px); }
.card .num { font-size:1.7rem; font-weight:700; }
.card .lbl { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }
.card.c-pass .num { color:var(--pass); } .card.c-fail .num { color:var(--fail); }
.card.c-partial .num { color:var(--partial); } .card.c-noteval .num { color:var(--noteval); }
.card.c-error .num { color:var(--error); } .card.c-skip .num { color:var(--skipped); }
.card.c-crit .num { color:var(--crit); } .card.c-high .num { color:var(--high); }
.card.c-med .num { color:var(--med); } .card.c-low .num { color:var(--low); }
.card.c-info .num { color:var(--info); }
table { border-collapse:collapse; width:100%; background:var(--panel); margin:10px 0; font-size:.88rem; border-radius:8px; overflow:hidden; }
th, td { border:1px solid var(--line); padding:8px 10px; text-align:left; vertical-align:top; }
th { background:var(--panel2); font-weight:600; }
tbody tr:nth-child(even) { background:rgba(127,127,127,.06); }
tbody tr:hover { background:rgba(56,168,220,.08); }
td a.comp-link { color:var(--accent); text-decoration:none; font-weight:600; }
td a.comp-link:hover { text-decoration:underline; }
.pill { display:inline-block; padding:2px 10px; border-radius:11px; font-size:.78rem; font-weight:700; white-space:nowrap; }
.st-pass { background:rgba(95,191,122,.16); color:var(--pass); border:1px solid var(--pass); }
.st-fail { background:rgba(224,93,93,.16); color:var(--fail); border:1px solid var(--fail); }
.st-partial { background:rgba(214,168,75,.16); color:var(--partial); border:1px solid var(--partial); }
.st-warning { background:rgba(214,168,75,.16); color:var(--warning); border:1px solid var(--warning); }
.st-noteval { background:rgba(154,165,177,.15); color:var(--noteval); border:1px solid var(--noteval); }
.st-notapp { background:rgba(111,119,130,.10); color:var(--notapp); border:1px dashed var(--line); }
.st-error { background:rgba(255,107,107,.16); color:var(--error); border:1px solid var(--error); }
.st-skipped { background:rgba(111,119,130,.15); color:var(--skipped); border:1px solid var(--skipped); }
.st-inventory { background:rgba(56,168,220,.16); color:var(--info); border:1px solid var(--info); }
.sv-critical { background:var(--crit); color:#fff; } .sv-high { background:var(--high); color:#fff; }
.sv-medium { background:var(--med); color:#fff; } .sv-low { background:var(--low); color:var(--low-ink, #fff); }
.sv-info { background:var(--info); color:#fff; } .sv-none { color:var(--muted); }
.muted { color:var(--muted); }
.trunc-note { color:var(--partial); font-size:.85rem; font-style:italic; }
details { background:var(--panel); border:1px solid var(--line); border-radius:10px; margin:10px 0; }
details > summary { cursor:pointer; padding:11px 16px; font-weight:600; list-style:none; }
details > summary:hover { color:var(--accent); }
details > summary::-webkit-details-marker { display:none; }
details > summary::before { content:"\25B8"; display:inline-block; margin-right:8px; color:var(--accent); }
details[open] > summary::before { content:"\25BE"; }
details .body { padding:2px 16px 16px 16px; border-top:1px solid var(--line); }
.kv { display:grid; grid-template-columns:230px 1fr; gap:5px 16px; font-size:.88rem; margin:12px 0; }
.kv dt { color:var(--muted); font-weight:600; }
.kv dd { margin:0; }
.badge { display:inline-block; padding:1px 8px; border-radius:4px; border:1px solid var(--line); font-size:.76rem; color:var(--muted); margin-left:6px; }
.badge.on { color:var(--partial); border-color:var(--partial); font-weight:700; }
.filterbar { display:flex; gap:10px; margin:6px 0 12px 0; flex-wrap:wrap; }
.filterbar input, .filterbar select { background:var(--panel2); border:1px solid var(--line); color:var(--ink); border-radius:6px; padding:7px 12px; font-size:.88rem; }
.filterbar input { flex:1; min-width:220px; }
.filterbar input:focus, .filterbar select:focus { outline:none; border-color:var(--accent); }
.warn-banner { background:rgba(214,168,75,.12); border:1px solid var(--warning); border-radius:10px; padding:12px 16px; margin:0 0 26px 0; color:var(--warning); font-weight:600; }
footer { padding:20px 32px; color:var(--muted); font-size:.84rem; border-top:1px solid var(--line); display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }
footer .brand { color:var(--brand); font-weight:600; }
</style>
'@

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append("<!DOCTYPE html>`n<html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1"">")
        [void]$sb.Append("<title>$($script:State.Metadata.ToolName) Report - $($script:State.Timestamp)</title>")
        [void]$sb.Append($css)
        [void]$sb.Append("</head><body>")

        # ---- Header + nav ----
        [void]$sb.Append("<header class=""topbar""><h1>$(Escape-HtmlContent -Text $script:State.Metadata.ToolName) <span class=""ver"">v$($script:State.Metadata.Version)</span></h1>")
        [void]$sb.Append("<div class=""tagline"">$(Escape-HtmlContent -Text (Get-ProductTagline)) &middot; <span class=""brand"">Created by BAAS &middot; 0xbaas.com</span></div>")
        [void]$sb.Append("<div class=""meta""><span>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span><span>Account: $account</span><span>Tenant: $tenant</span><span>Mode: $mode</span><span>Data-plane checks: $dpMode</span></div></header>")
        [void]$sb.Append('<nav><a href="#exec">Executive Summary</a><a href="#coverage">Coverage</a><a href="#findings">Findings</a><a href="#components">Affected Components</a><a href="#capability">Capability Insights</a><a href="#checks">Per-Check Detail</a><a href="#attention">Not Evaluated / Errors</a></nav>')
        [void]$sb.Append('<main>')

        # Result integrity: never present a clean-looking report when the
        # environment footprint itself is unproven - applicability decisions
        # were disabled and results may be incomplete.
        $fpTop = $script:State.Footprint
        if ($fpTop -and ($fpTop.PSObject.Properties.Name -contains 'Confidence') -and
            ($fpTop.Confidence -ne 'High' -or $fpTop.CoverageStatus -ne 'Complete')) {
            $fpNote = if ($fpTop.Note) { $fpTop.Note } else { 'Footprint coverage could not be fully proven.' }
            [void]$sb.Append("<div class=""warn-banner"">Environment footprint incomplete ($(Escape-HtmlContent -Text $fpTop.CoverageStatus), $($fpTop.SubscriptionsCovered)/$($fpTop.SubscriptionsExpected) subscriptions). Applicability decisions were not used; results may be incomplete. $(Escape-HtmlContent -Text $fpNote)</div>")
        }

        # ---- 1. Executive summary ----
        $withCovExec = @($exec | Where-Object { $_.Coverage })
        $completeExec = @($withCovExec | Where-Object { $_.Coverage.CompleteEvaluation }).Count

        [void]$sb.Append('<section id="exec"><h2>Executive Summary</h2><div class="cards">')
        $cards = @(
            @{ N = $diag.ChecksAttempted;        L = 'Checks Planned';     C = '';           H = '#checks' },
            @{ N = $diag.Passed;                 L = 'Passed';             C = 'c-pass';     H = '#checks' },
            @{ N = $diag.Failed;                 L = 'Failed';             C = 'c-fail';     H = '#findings' },
            @{ N = $diag.Partial;                L = 'Partial';            C = 'c-partial';  H = '#attention' },
            @{ N = $diag.NotEvaluated;           L = 'Not Evaluated';      C = 'c-noteval';  H = '#attention' },
            @{ N = $diag.NotApplicable;          L = 'Not Applicable';     C = 'c-skip';     H = '#coverage' },
            @{ N = $diag.Inventory;              L = 'Inventory-only';     C = 'c-info';     H = '#checks' },
            @{ N = $diag.Errors;                 L = 'Errors';             C = 'c-error';    H = '#attention' },
            @{ N = $diag.FindingGroups;          L = 'Finding Groups';     C = '';           H = '#findings' },
            @{ N = $diag.AffectedResources;      L = 'Affected Resources'; C = '';           H = '#components' },
            @{ N = "$completeExec/$($withCovExec.Count)"; L = 'Coverage-aware checks complete'; C = 'c-pass'; H = '#coverage' }
        )
        foreach ($card in $cards) {
            [void]$sb.Append("<a class=""card $($card.C)"" href=""$($card.H)""><div class=""num"">$($card.N)</div><div class=""lbl"">$($card.L)</div></a>")
        }
        [void]$sb.Append('</div>')

        # Severity overview as its own card row
        [void]$sb.Append('<h3>Severity Overview</h3><div class="cards">')
        $sevCards = @(
            @{ N = $diag.BySeverity['CRITICAL']; L = 'Critical'; C = 'c-crit' },
            @{ N = $diag.BySeverity['HIGH'];     L = 'High';     C = 'c-high' },
            @{ N = $diag.BySeverity['MEDIUM'];   L = 'Medium';   C = 'c-med' },
            @{ N = $diag.BySeverity['LOW'];      L = 'Low';      C = 'c-low' },
            @{ N = $diag.BySeverity['INFO'];     L = 'Info';     C = 'c-info' }
        )
        foreach ($card in $sevCards) {
            [void]$sb.Append("<div class=""card $($card.C)""><div class=""num"">$($card.N)</div><div class=""lbl"">$($card.L) finding groups</div></div>")
        }
        [void]$sb.Append('</div>')

        [void]$sb.Append("<p><strong>Scope:</strong> $(Escape-HtmlContent -Text $scopeText) &middot; <strong>Mode:</strong> $mode</p>")
        [void]$sb.Append("<p class=""muted"">Export metadata: run id $($script:State.Timestamp) &middot; log file $(Escape-HtmlContent -Text $script:State.LogFile) &middot; this HTML plus companion JSON/CSV exports.</p>")
        [void]$sb.Append('</section>')

        # ---- 1.5 Environment footprint ----
        $fp = $script:State.Footprint
        if ($fp -and $fp.Source -ne 'Unavailable') {
            [void]$sb.Append('<section id="footprint"><h2>Environment Footprint</h2><div class="cards">')
            [void]$sb.Append("<div class=""card""><div class=""num"">$($fp.Subscriptions)</div><div class=""lbl"">Subscriptions</div></div>")
            [void]$sb.Append("<div class=""card""><div class=""num"">$($fp.ResourceGroups)</div><div class=""lbl"">Resource Groups</div></div>")
            [void]$sb.Append("<div class=""card""><div class=""num"">$($fp.Resources)</div><div class=""lbl"">Resources</div></div>")
            [void]$sb.Append("<div class=""card""><div class=""num"">$($fp.ResourceTypeCount)</div><div class=""lbl"">Resource Types</div></div>")
            [void]$sb.Append("<div class=""card""><div class=""num"">$($fp.RegionCount)</div><div class=""lbl"">Regions</div></div>")
            [void]$sb.Append('</div>')
            if ($fp.TopTypes.Count -gt 0) {
                [void]$sb.Append('<h3>Top services</h3><table><thead><tr><th>Service</th><th>Resource type</th><th>Count</th></tr></thead><tbody>')
                foreach ($t in $fp.TopTypes) {
                    [void]$sb.Append("<tr><td>$(Escape-HtmlContent -Text $t.Label)</td><td>$(Escape-HtmlContent -Text $t.Type)</td><td>$($t.Count)</td></tr>")
                }
                [void]$sb.Append('</tbody></table>')
            }
            [void]$sb.Append("<p class=""muted"">Footprint source: $(Escape-HtmlContent -Text $fp.Source) &middot; regions: $(Escape-HtmlContent -Text ($fp.Regions -join ', '))</p>")
            if (($fp.PSObject.Properties.Name -contains 'CoverageStatus') -and $fp.CoverageStatus) {
                $fpCov = "Footprint coverage: $($fp.CoverageStatus) ($($fp.SubscriptionsCovered)/$($fp.SubscriptionsExpected) subscriptions) &middot; confidence: $($fp.Confidence)"
                if ($fp.Confidence -eq 'Low') {
                    [void]$sb.Append("<p><span class=""pill st-partial"">LOW CONFIDENCE FOOTPRINT</span> $(Escape-HtmlContent -Text $fpCov)</p>")
                    if ($fp.Note) { [void]$sb.Append("<p class=""trunc-note"">$(Escape-HtmlContent -Text $fp.Note)</p>") }
                } else {
                    [void]$sb.Append("<p class=""muted"">$(Escape-HtmlContent -Text $fpCov)</p>")
                }
            }
            [void]$sb.Append('</section>')
        }

        # ---- 2. Coverage summary ----
        $withCov    = @($exec | Where-Object { $_.Coverage })
        $complete   = @($withCov | Where-Object { $_.Coverage.CompleteEvaluation }).Count
        $partialCov = @($withCov | Where-Object { $_.Coverage.PartialEvaluation }).Count
        # Data-plane checks are identified from the execution record flag
        # (Phase B3) so gated-off checks - which produce no findings - still
        # appear in the Data-Plane Checks table with their Skipped status.
        $dataPlane  = @($exec | Where-Object {
            ($_.PSObject.Properties.Name -contains 'DataPlaneRequired') -and $_.DataPlaneRequired
        })

        $legacyChecks = $exec.Count - $withCov.Count

        [void]$sb.Append('<section id="coverage"><h2>Coverage Summary</h2><div class="cards">')
        [void]$sb.Append("<div class=""card""><div class=""num"">$($exec.Count)</div><div class=""lbl"">Total Checks</div></div>")
        [void]$sb.Append("<div class=""card""><div class=""num"">$($withCov.Count)</div><div class=""lbl"">Coverage-aware Checks</div></div>")
        [void]$sb.Append("<div class=""card c-pass""><div class=""num"">$complete</div><div class=""lbl"">Complete Coverage</div></div>")
        [void]$sb.Append("<div class=""card c-partial""><div class=""num"">$partialCov</div><div class=""lbl"">Partial Coverage</div></div>")
        [void]$sb.Append("<div class=""card""><div class=""num"">$legacyChecks</div><div class=""lbl"">Legacy Checks (no coverage data)</div></div>")
        [void]$sb.Append("<div class=""card c-noteval""><div class=""num"">$($diag.NotEvaluated)</div><div class=""lbl"">Not Evaluated</div></div>")
        [void]$sb.Append("<div class=""card c-error""><div class=""num"">$($diag.Errors)</div><div class=""lbl"">Errors</div></div>")
        [void]$sb.Append('</div>')
        [void]$sb.Append("<p class=""muted"">Coverage-aware checks: $($withCov.Count) &middot; complete: $complete &middot; partial: $partialCov &middot; legacy checks without coverage metadata: $legacyChecks &middot; not evaluated: $($diag.NotEvaluated) &middot; errors: $($diag.Errors). Legacy checks keep their explicit status but do not prove evaluation coverage yet.</p>")

        # Resource/subscription totals across coverage-reporting checks
        $totDisc = 0; $totEval = 0; $totSkip = 0; $totFail = 0
        $subsEval = @(); $subsSkip = @()
        foreach ($c in $withCov) {
            $totDisc += [int]$c.Coverage.DiscoveredResourceCount
            $totEval += [int]$c.Coverage.EvaluatedResourceCount
            $totSkip += [int]$c.Coverage.SkippedResourceCount
            $totFail += [int]$c.Coverage.FailedCollectionCount
            foreach ($s in @($c.Coverage.SubscriptionsEvaluated)) { if ($s -and $subsEval -notcontains $s) { $subsEval += $s } }
            foreach ($s in @($c.Coverage.SubscriptionsSkipped))   { if ($s -and $subsSkip -notcontains $s) { $subsSkip += $s } }
        }
        if ($withCov.Count -gt 0) {
            [void]$sb.Append("<h3>Resource Totals <span class=""muted"">(across $($withCov.Count) coverage-reporting checks)</span></h3><div class=""cards"">")
            [void]$sb.Append("<div class=""card""><div class=""num"">$totDisc</div><div class=""lbl"">Resources Discovered</div></div>")
            [void]$sb.Append("<div class=""card c-pass""><div class=""num"">$totEval</div><div class=""lbl"">Resources Evaluated</div></div>")
            [void]$sb.Append("<div class=""card c-partial""><div class=""num"">$totSkip</div><div class=""lbl"">Resources Skipped</div></div>")
            [void]$sb.Append("<div class=""card c-error""><div class=""num"">$totFail</div><div class=""lbl"">Failed Collections</div></div>")
            [void]$sb.Append("<div class=""card""><div class=""num"">$($subsEval.Count)</div><div class=""lbl"">Subscriptions Evaluated</div></div>")
            [void]$sb.Append("<div class=""card c-partial""><div class=""num"">$($subsSkip.Count)</div><div class=""lbl"">Subscriptions Skipped</div></div>")
            [void]$sb.Append('</div>')
        }
        [void]$sb.Append('<p class="muted">PASS is shown only when a check proved evaluation (explicit coverage record). Checks without coverage metadata are legacy checks that have not been migrated to the coverage model yet; their explicit status is still preserved.</p>')
        $dpIncluded = [bool]$script:State.Config.IncludeDataPlane
        if ($dataPlane.Count -gt 0) {
            if ($dpIncluded) {
                [void]$sb.Append("<p class=""muted""><strong>Data-plane checks: enabled</strong> (-IncludeDataPlane) - $($dataPlane.Count) check(s) require data-plane access and ran with safe metadata reads only (never secret values, keys, SAS tokens, connection strings, or blob/file content). See the Data-Plane Checks table below for skipped/failed access.</p>")
            } else {
                [void]$sb.Append("<p class=""muted""><strong>Data-plane checks: disabled</strong> (default) - $($dataPlane.Count) relevant check(s) were gated off and did not run; pass -IncludeDataPlane to enable safe metadata-only evaluation. See the Data-Plane Checks table below.</p>")
            }
        }

        # Check Coverage table (per-check execution + coverage)
        [void]$sb.Append('<h3>Check Coverage</h3><table><thead><tr><th>Status</th><th>Check</th><th>Name</th><th>Service</th><th>Discovered</th><th>Evaluated</th><th>Skipped</th><th>Failed collections</th><th>Subscriptions (eval/skip)</th><th>Summary</th></tr></thead><tbody>')
        foreach ($check in $exec) {
            $cov = $check.Coverage
            $disc = if ($cov) { $cov.DiscoveredResourceCount } else { '' }
            $eval = if ($cov) { $cov.EvaluatedResourceCount }  else { '' }
            $skip = if ($cov) { $cov.SkippedResourceCount }    else { '' }
            $fail = if ($cov) { $cov.FailedCollectionCount }   else { '' }
            $subs = if ($cov) { "$(@($cov.SubscriptionsEvaluated).Count) / $(@($cov.SubscriptionsSkipped).Count)" } else { '' }
            $cSummary = ''
            if (($check.PSObject.Properties.Name -contains 'SummaryText') -and $check.SummaryText) { $cSummary = $check.SummaryText }
            elseif ($cov -and $cov.Summary) { $cSummary = $cov.Summary }
            elseif ($check.Detail) { $cSummary = $check.Detail }
            [void]$sb.Append('<tr>')
            [void]$sb.Append("<td>$(Get-HtmlStatusPill -Status $check.Status)</td>")
            [void]$sb.Append("<td>$(Escape-HtmlContent -Text $check.CheckId)</td>")
            [void]$sb.Append("<td>$(Escape-HtmlContent -Text $check.Name)</td>")
            [void]$sb.Append("<td>$(Escape-HtmlContent -Text $check.Service)</td>")
            [void]$sb.Append("<td>$disc</td><td>$eval</td><td>$skip</td><td>$fail</td><td>$subs</td>")
            [void]$sb.Append("<td>$(Escape-HtmlContent -Text $cSummary)</td>")
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table>')

        # Data-plane checks visibility
        [void]$sb.Append('<h3>Data-Plane Checks</h3>')
        if ($dataPlane.Count -gt 0) {
            [void]$sb.Append('<table><thead><tr><th>Status</th><th>Check</th><th>Name</th><th>Skipped/Failed</th><th>Note</th></tr></thead><tbody>')
            foreach ($c in $dataPlane) {
                $skipFail = if ($c.Coverage) { "$($c.Coverage.SkippedResourceCount) / $($c.Coverage.FailedCollectionCount)" } else { '' }
                $note = 'Data-plane access required.'
                if ("$($c.Status)" -eq 'Partial') { $note = 'Data-plane access required; coverage partial - findings may be incomplete.' }
                if ("$($c.Status)" -eq 'Skipped' -and $c.Detail) { $note = "$($c.Detail) - the check did not run; pass -IncludeDataPlane to enable safe metadata-only evaluation." }
                elseif ("$($c.Status)" -eq 'NotEvaluated' -and -not $c.Coverage) { $note = 'Data-plane access required; access denied or collection failed - nothing could be evaluated.' }
                [void]$sb.Append("<tr><td>$(Get-HtmlStatusPill -Status $c.Status)</td><td>$(Escape-HtmlContent -Text $c.CheckId)</td><td>$(Escape-HtmlContent -Text $c.Name)</td><td>$skipFail</td><td>$(Escape-HtmlContent -Text $note)</td></tr>")
            }
            [void]$sb.Append('</tbody></table>')
        } else {
            [void]$sb.Append('<p class="muted">No data-plane checks were registered for this run.</p>')
        }
        [void]$sb.Append('</section>')

        # ---- 3. Findings overview ----
        # Aggregate per-subscription records into one row per finding group
        # (CheckId+Severity+Service+Finding); per-subscription rows stay in
        # the JSON/CSV exports.
        $groupedFindings = @(Group-HtmlFindings -Findings $findingGroups)
        # One sorted view shared by the Findings Overview rows and the Affected
        # Components blocks so per-row anchors (#comp-N) line up deterministically.
        $sortedFindings = @($groupedFindings | Sort-Object { $sevOrder["$($_.Severity)".ToUpper()] }, Service, CheckId)
        [void]$sb.Append('<section id="findings"><h2>Findings Overview</h2>')
        if ($groupedFindings.Count -eq 0) {
            [void]$sb.Append('<p class="muted">No findings with affected resources were recorded. See Coverage Summary for evaluation status per check.</p>')
        } else {
            [void]$sb.Append('<div class="filterbar"><input id="fFilter" type="text" placeholder="Filter findings..."><select id="fSev"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select></div>')
            [void]$sb.Append('<table id="findingsTable"><thead><tr><th>Severity</th><th>Check</th><th>Service</th><th>Finding</th><th>Count</th><th>Status</th><th>Confidence</th><th>Coverage</th><th>Summary</th><th>Recommendation</th></tr></thead><tbody>')
            $gi = 0
            foreach ($f in $sortedFindings) {
                $covState = if ($f.PartialEvaluation) { 'Partial' } elseif ($f.CompleteEvaluation) { 'Complete' } else { '' }
                $fSum = if ($f.SummaryText) { $f.SummaryText } elseif ($f.CoverageSummary) { $f.CoverageSummary } else { '' }
                $countCell = "<a href=""#comp-$gi"" class=""comp-link"">View $($f.Count) affected</a>"
                $gi++
                if ($f.SubscriptionSpan -gt 1) { $countCell += "<div class=""muted"">across $($f.SubscriptionSpan) subscriptions</div>" }
                [void]$sb.Append("<tr data-sev=""$("$($f.Severity)".ToUpper())"">")
                [void]$sb.Append("<td>$(Get-HtmlSeverityPill -Severity $f.Severity)</td>")
                [void]$sb.Append("<td>$(Escape-HtmlContent -Text $f.CheckId)</td>")
                [void]$sb.Append("<td>$(Escape-HtmlContent -Text $f.Service)</td>")
                [void]$sb.Append("<td>$(Escape-HtmlContent -Text $f.Finding)</td>")
                [void]$sb.Append("<td>$countCell</td>")
                [void]$sb.Append("<td>$(Get-HtmlStatusPill -Status $f.Status)</td>")
                [void]$sb.Append("<td>$(Escape-HtmlContent -Text $f.Confidence)</td>")
                [void]$sb.Append("<td>$(Escape-HtmlContent -Text $covState)</td>")
                [void]$sb.Append("<td>$(Escape-HtmlContent -Text $fSum)</td>")
                [void]$sb.Append("<td>$(ConvertTo-HtmlCompactValue -Value $f.Remediation -MaxLength 200)</td>")
                [void]$sb.Append('</tr>')
            }
            [void]$sb.Append('</tbody></table>')
        }
        [void]$sb.Append('</section>')

        # ---- 4. Affected components ----
        [void]$sb.Append('<section id="components"><h2>Affected Components</h2>')
        if ($groupedFindings.Count -eq 0) {
            [void]$sb.Append('<p class="muted">No affected components recorded.</p>')
        } else {
            $ci = 0
            foreach ($f in $sortedFindings) {
                $badges = ''
                if ($f.DataPlaneRequired)        { $badges += '<span class="badge on">data-plane required</span>' }
                if ($f.ManualValidationRequired) { $badges += '<span class="badge on">manual validation</span>' }
                if ($f.IsInventoryOnly)          { $badges += '<span class="badge">inventory / context</span>' }
                if ($f.PartialEvaluation)        { $badges += '<span class="badge on">partial coverage - may be incomplete</span>' }
                $scopeNote = ''
                if ($f.SubscriptionSpan -gt 1) { $scopeNote = " &middot; $($f.SubscriptionSpan) subscriptions" }
                [void]$sb.Append("<details id=""comp-$ci""><summary>$(Get-HtmlSeverityPill -Severity $f.Severity) $(Escape-HtmlContent -Text $f.Finding) <span class=""muted"">($(Escape-HtmlContent -Text $f.CheckId) &middot; $($f.Count) affected$scopeNote)</span>$badges</summary>")
                $ci++
                [void]$sb.Append('<div class="body">')
                [void]$sb.Append($(ConvertTo-HtmlEvidenceTable -Evidence $f.Evidence))
                if ($f.Remediation) { [void]$sb.Append("<p><strong>Recommendation:</strong> $(ConvertTo-HtmlCompactValue -Value $f.Remediation -MaxLength 400)</p>") }
                [void]$sb.Append('<p class="muted">Full per-subscription detail in the CSV/JSON exports.</p>')
                [void]$sb.Append('</div></details>')
            }
        }
        [void]$sb.Append('</section>')

        # ---- 4.5 Capability insights (Phase B2) ----
        Add-HtmlCapabilitySection -StringBuilder $sb

        # ---- 5. Per-check sections ----
        [void]$sb.Append('<section id="checks"><h2>Per-Check Detail</h2>')
        foreach ($check in $exec) {
            $cid = $check.CheckId
            $checkFindings = @($Results | Where-Object { $_.CheckId -eq $cid })
            $cov = $check.Coverage

            $highestSev = $null
            foreach ($f in $checkFindings) {
                $s = "$($f.Severity)".ToUpper()
                if ($sevOrder.Contains($s) -and (-not $highestSev -or $sevOrder[$s] -lt $sevOrder[$highestSev])) { $highestSev = $s }
            }
            $confidence = ''; $techSum = ''; $collectionStatus = ''; $sevReason = ''
            $apis = New-Object System.Collections.Generic.List[string]
            $dpRequired = ($check.PSObject.Properties.Name -contains 'DataPlaneRequired') -and $check.DataPlaneRequired
            $mvRequired = $false; $invOnly = $false
            $remediations = New-Object System.Collections.Generic.List[string]
            foreach ($f in $checkFindings) {
                if (-not $confidence -and $f.Confidence)       { $confidence = "$($f.Confidence)" }
                if (-not $sevReason -and $f.SeverityReason)    { $sevReason = "$($f.SeverityReason)" }
                if (-not $techSum -and $f.TechnicalSummary)    { $techSum = "$($f.TechnicalSummary)" }
                if (-not $collectionStatus -and $f.CollectionStatus) { $collectionStatus = "$($f.CollectionStatus)" }
                foreach ($a in @($f.ApiSources)) { if ($a -and -not $apis.Contains($a)) { $apis.Add($a) } }
                if ($f.DataPlaneRequired)        { $dpRequired = $true }
                if ($f.ManualValidationRequired) { $mvRequired = $true }
                if ($f.IsInventoryOnly)          { $invOnly = $true }
                if ($f.Remediation -and -not $remediations.Contains("$($f.Remediation)")) { $remediations.Add("$($f.Remediation)") }
            }
            $regEntry = @($script:State.CheckRegistry | Where-Object { $_.CheckId -eq $cid }) | Select-Object -First 1
            $whatChecked = ''
            if ($regEntry -and ($regEntry.PSObject.Properties.Name -contains 'Description')) { $whatChecked = "$($regEntry.Description)" }

            $cSummary = ''
            if (($check.PSObject.Properties.Name -contains 'SummaryText') -and $check.SummaryText) { $cSummary = $check.SummaryText }
            elseif ($cov -and $cov.Summary) { $cSummary = $cov.Summary }

            [void]$sb.Append("<details><summary>$(Get-HtmlStatusPill -Status $check.Status) $(Escape-HtmlContent -Text $cid) &middot; $(Escape-HtmlContent -Text $check.Name)</summary><div class=""body"">")
            [void]$sb.Append('<dl class="kv">')
            [void]$sb.Append("<dt>Status</dt><dd>$(Get-HtmlStatusPill -Status $check.Status)</dd>")
            [void]$sb.Append("<dt>Service / Category</dt><dd>$(Escape-HtmlContent -Text $check.Service) / $(Escape-HtmlContent -Text $check.Category)</dd>")
            if ($highestSev) { [void]$sb.Append("<dt>Highest severity</dt><dd>$(Get-HtmlSeverityPill -Severity $highestSev)</dd>") }
            if ($confidence) { [void]$sb.Append("<dt>Confidence</dt><dd>$(Escape-HtmlContent -Text $confidence)</dd>") }
            if ($sevReason)  { [void]$sb.Append("<dt>Severity reason</dt><dd>$(Escape-HtmlContent -Text $sevReason)</dd>") }
            if ($cSummary)   { [void]$sb.Append("<dt>Summary</dt><dd>$(Escape-HtmlContent -Text $cSummary)</dd>") }
            if ($techSum)    { [void]$sb.Append("<dt>Technical summary</dt><dd>$(Escape-HtmlContent -Text $techSum)</dd>") }
            if ($whatChecked){ [void]$sb.Append("<dt>What was checked</dt><dd>$(Escape-HtmlContent -Text $whatChecked)</dd>") }
            if ($apis.Count -gt 0) { [void]$sb.Append("<dt>APIs / cmdlets used</dt><dd>$(Escape-HtmlContent -Text ($apis -join '; '))</dd>") }
            if ($cov) {
                [void]$sb.Append("<dt>Coverage</dt><dd>Discovered: $($cov.DiscoveredResourceCount) &middot; Evaluated: $($cov.EvaluatedResourceCount) &middot; Skipped: $($cov.SkippedResourceCount) &middot; Failed collections: $($cov.FailedCollectionCount)</dd>")
                [void]$sb.Append("<dt>Subscriptions</dt><dd>Evaluated: $(Escape-HtmlContent -Text (@($cov.SubscriptionsEvaluated) -join ', ')) $(if (@($cov.SubscriptionsSkipped).Count -gt 0) { '<br>Skipped: ' + (Escape-HtmlContent -Text (@($cov.SubscriptionsSkipped) -join ', ')) })</dd>")
                $collText = if ($collectionStatus) { $collectionStatus } elseif ($cov.CompleteEvaluation) { 'Complete' } elseif ($cov.PartialEvaluation) { 'Partial' } else { '' }
                if ($collText) { [void]$sb.Append("<dt>Collection status</dt><dd>$(Escape-HtmlContent -Text $collText)</dd>") }
            }
            $flags = @()
            if ($dpRequired) { $flags += 'requires data-plane access' }
            if ($mvRequired) { $flags += 'manual validation recommended' }
            if ($invOnly)    { $flags += 'inventory/context records - not exploitable findings by themselves' }
            if ("$($check.Status)" -eq 'NotApplicable' -and $check.Detail) { $flags += $check.Detail }
            if ($cov -and $cov.PartialEvaluation) { $flags += 'coverage incomplete - findings may be missing' }
            if ("$($check.Status)" -eq 'Skipped' -and $check.Detail) { $flags += $check.Detail }
            if ("$($check.Status)" -eq 'Error' -and $check.Detail)   { $flags += "error: $($check.Detail)" }
            if ($flags.Count -gt 0) { [void]$sb.Append("<dt>Limitations</dt><dd>$(Escape-HtmlContent -Text ($flags -join '; '))</dd>") }
            [void]$sb.Append('</dl>')

            foreach ($f in $checkFindings) {
                # Count=0 coverage records render as informational notes, never as
                # severity-colored "successful findings".
                if ([int]$f.Count -le 0) {
                    [void]$sb.Append("<p class=""muted"">$(Get-HtmlStatusPill -Status $f.Status) $(Escape-HtmlContent -Text $f.Finding) (no affected resources)</p>")
                    continue
                }
                [void]$sb.Append("<h3>$(Get-HtmlSeverityPill -Severity $f.Severity) $(Escape-HtmlContent -Text $f.Finding) ($($f.Count) affected)</h3>")
                [void]$sb.Append($(ConvertTo-HtmlEvidenceTable -Evidence $f.Evidence))
            }
            if ($remediations.Count -gt 0) {
                [void]$sb.Append('<h3>Remediation</h3><ul>')
                foreach ($r in $remediations) { [void]$sb.Append("<li>$(ConvertTo-HtmlCompactValue -Value $r -MaxLength 400)</li>") }
                [void]$sb.Append('</ul>')
            }
            [void]$sb.Append('</div></details>')
        }

        # Orphan records: findings whose CheckId has no execution record (e.g.
        # findings written outside the orchestrator). Explicit status is preserved
        # here too - they must not silently disappear from the report.
        $execIds = @($exec | ForEach-Object { "$($_.CheckId)" })
        $orphans = @($Results | Where-Object { $execIds -notcontains "$($_.CheckId)" })
        if ($orphans.Count -gt 0) {
            [void]$sb.Append('<details><summary><span class="pill st-noteval">RECORDS</span> Additional finding records (no execution record)</summary><div class="body">')
            foreach ($f in $orphans) {
                if ([int]$f.Count -le 0) {
                    [void]$sb.Append("<p class=""muted"">$(Get-HtmlStatusPill -Status $f.Status) $(Get-HtmlSeverityPill -Severity $f.Severity) [$(Escape-HtmlContent -Text $f.CheckId)] $(Escape-HtmlContent -Text $f.Finding) (no affected resources)</p>")
                    continue
                }
                [void]$sb.Append("<h3>$(Get-HtmlSeverityPill -Severity $f.Severity) $(Get-HtmlStatusPill -Status $f.Status) [$(Escape-HtmlContent -Text $f.CheckId)] $(Escape-HtmlContent -Text $f.Finding) ($($f.Count) affected)</h3>")
                [void]$sb.Append($(ConvertTo-HtmlEvidenceTable -Evidence $f.Evidence))
            }
            [void]$sb.Append('</div></details>')
        }
        [void]$sb.Append('</section>')

        # ---- 6. Not Evaluated / Partial / Errors ----
        $attention = @($exec | Where-Object { "$($_.Status)" -in @('NotEvaluated','Partial','Error','Skipped','Warning') })
        [void]$sb.Append('<section id="attention"><h2>Not Evaluated / Partial / Errors</h2>')
        if ($attention.Count -eq 0) {
            [void]$sb.Append('<p class="muted">All checks completed with proven coverage.</p>')
        } else {
            [void]$sb.Append('<table><thead><tr><th>Status</th><th>Check</th><th>Name</th><th>Reason</th><th>Failed</th><th>Skipped</th><th>Suggested next action</th></tr></thead><tbody>')
            foreach ($c in $attention) {
                $reason = ''
                if (($c.PSObject.Properties.Name -contains 'SummaryText') -and $c.SummaryText) { $reason = $c.SummaryText }
                elseif ($c.Coverage -and $c.Coverage.Summary) { $reason = $c.Coverage.Summary }
                elseif ($c.Detail) { $reason = $c.Detail }
                $failN = if ($c.Coverage) { $c.Coverage.FailedCollectionCount } else { '' }
                $skipN = if ($c.Coverage) { $c.Coverage.SkippedResourceCount }   else { '' }
                $next = 'Review permissions/modules and re-run.'
                if ("$($c.Status)" -eq 'Skipped') { $next = 'Install the required module(s) and re-run.' }
                elseif ("$($c.Status)" -eq 'Error') { $next = 'Inspect the log file for the full error and stack trace.' }
                elseif ("$($c.Status)" -eq 'Partial') { $next = 'Grant missing read/data-plane permissions and re-run to complete coverage.' }
                [void]$sb.Append("<tr><td>$(Get-HtmlStatusPill -Status $c.Status)</td><td>$(Escape-HtmlContent -Text $c.CheckId)</td><td>$(Escape-HtmlContent -Text $c.Name)</td><td>$(ConvertTo-HtmlCompactValue -Value $reason -MaxLength 200)</td><td>$failN</td><td>$skipN</td><td>$(Escape-HtmlContent -Text $next)</td></tr>")
            }
            [void]$sb.Append('</tbody></table>')
        }
        [void]$sb.Append('</section>')

        # ---- Failed subscriptions ----
        [void]$sb.Append('<section id="failedsubs"><h2>Failed Subscriptions</h2>')
        if ($script:State.FailedSubscriptions.Count -gt 0) {
            [void]$sb.Append('<ul>')
            foreach ($failed in $script:State.FailedSubscriptions) {
                [void]$sb.Append("<li>$(Escape-HtmlContent -Text $failed.SubscriptionName) ($(Escape-HtmlContent -Text $failed.SubscriptionId)): $(ConvertTo-HtmlCompactValue -Value $failed.Error -MaxLength 200)</li>")
            }
            [void]$sb.Append('</ul>')
        } else {
            [void]$sb.Append('<p class="muted">All subscriptions processed successfully.</p>')
        }
        [void]$sb.Append('</section>')

        [void]$sb.Append('</main>')

        # Minimal offline filter for the findings table (no external dependencies).
        $js = @'
<script>
(function () {
    var filter = document.getElementById('fFilter');
    var sev = document.getElementById('fSev');
    var table = document.getElementById('findingsTable');
    if (!table) { return; }
    var rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
    function apply() {
        var q = (filter && filter.value || '').toLowerCase();
        var s = (sev && sev.value || '');
        for (var i = 0; i < rows.length; i++) {
            var okSev = !s || rows[i].getAttribute('data-sev') === s;
            var okTxt = !q || rows[i].textContent.toLowerCase().indexOf(q) !== -1;
            rows[i].style.display = (okSev && okTxt) ? '' : 'none';
        }
    }
    if (filter) { filter.addEventListener('input', apply); }
    if (sev) { sev.addEventListener('change', apply); }
})();
</script>
'@
        [void]$sb.Append($js)
        [void]$sb.Append("<footer><span>Built by <span class=""brand"">BAAS</span> | 0xbaas.com | $(Escape-HtmlContent -Text $script:State.Metadata.ToolName) v$($script:State.Metadata.Version)</span><span>Log file: $(Escape-HtmlContent -Text $script:State.LogFile)</span></footer>")
        [void]$sb.Append('</body></html>')

        $sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-AuditLog -Message "Generated HTML report: $OutputPath" -Level INFO
    }
    catch {
        Write-AuditLog -Message "Failed to generate HTML report: $_" -Level ERROR
    }

    return $OutputPath
}
