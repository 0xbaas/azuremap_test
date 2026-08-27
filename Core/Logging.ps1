#==============================================================================
# AzureMap v2 - Core/Logging.ps1
# Buffered logging with severity-colored console output, thread-safe flush,
# startup banner, and section header utilities.
# All functions reference $script:State.
#==============================================================================

# Official BAAS / AzureMap palette: maps the ConsoleColor names used by
# callers to brand RGB triples for truecolor (ANSI 24-bit) terminals.
#   Cyan=#38A8DC accent  Green=#5FBF7A pass  Red=#E05D5D fail
#   Yellow=#D6A84B warn  Magenta=#FF6B6B err Gray=#9AA5B1 muted
#   DarkGray=#6F7782 n/a White=#F1F3F5 text Blue=#7AA2C7 low
#   DarkYellow=#E68A3A high
$script:BaasAnsiColors = @{
    Cyan       = '56;168;220'
    Green      = '95;191;122'
    Red        = '224;93;93'
    Yellow     = '214;168;75'
    Magenta    = '255;107;107'
    Gray       = '154;165;177'
    DarkGray   = '111;119;130'
    White      = '241;243;245'
    Blue       = '122;162;199'
    DarkYellow = '230;138;58'
    # CVSS-like severity ramp additions (product UX phase):
    #   LightGreen=#9BE7A1 low   CritRed=#F05252 critical
    LightGreen = '155;231;161'
    CritRed    = '240;82;82'
}
# Palette names that are not real [ConsoleColor] values fall back to the
# nearest console color on hosts without truecolor support (PS 5.1).
$script:BaasConsoleFallback = @{
    LightGreen = 'Green'
    CritRed    = 'Red'
}
# Test hook: $true/$false forces the ANSI decision; $null = auto-detect.
$script:UiForceAnsi = $null

function Test-UiAnsiSupport {
    <#
    .SYNOPSIS
        Returns $true when the host can render 24-bit ANSI color.
    .DESCRIPTION
        Truecolor is used on PowerShell 7+ hosts that report virtual-terminal
        support (Windows Terminal, VS Code, modern conhost). Windows PowerShell
        5.1 falls back to the nearest ConsoleColor because its ANSI passthrough
        is unreliable. $script:UiForceAnsi overrides detection (tests).
    #>
    if ($null -ne $script:UiForceAnsi) { return [bool]$script:UiForceAnsi }
    return ($PSVersionTable.PSVersion.Major -ge 7 -and $Host.UI.SupportsVirtualTerminal)
}

function Write-UiHost {
    <#
    .SYNOPSIS
        Central console writer honoring the NoColor setting.
    .DESCRIPTION
        Colors are emitted only when color output is enabled: Config.NoColor
        (from -NoColor) or the NO_COLOR environment variable disable them, in
        which case the text is written without -ForegroundColor. Use this for
        all operator-facing UI lines (banner, per-check status lines, summary).
        On truecolor hosts the BAAS brand RGB values are emitted via ANSI
        escape sequences; elsewhere the nearest ConsoleColor is used.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Text = '',
        [string]$Color = 'Gray',
        [switch]$NoNewline
    )

    $noColor = $false
    if ($script:State -and $script:State.Config -and $script:State.Config.NoColor) { $noColor = $true }
    if ($env:NO_COLOR) { $noColor = $true }

    if ($noColor) {
        if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
        return
    }

    $rgb = $null
    if ($script:BaasAnsiColors.ContainsKey("$Color")) { $rgb = $script:BaasAnsiColors["$Color"] }

    if ($rgb -and (Test-UiAnsiSupport)) {
        $esc = [char]27
        $out = "$esc[38;2;${rgb}m$Text$esc[0m"
        if ($NoNewline) { Write-Host $out -NoNewline } else { Write-Host $out }
    }
    else {
        $cc = "$Color"
        if ($script:BaasConsoleFallback.ContainsKey($cc)) { $cc = $script:BaasConsoleFallback[$cc] }
        if ($NoNewline) { Write-Host $Text -ForegroundColor $cc -NoNewline }
        else { Write-Host $Text -ForegroundColor $cc }
    }
}

function Format-UiNumber {
    <#
    .SYNOPSIS
        Formats a count with invariant thousands separators (5,663) so CLI
        numbers render identically regardless of the host's culture.
    #>
    [CmdletBinding()]
    param([object]$Number)
    $n = 0
    try { $n = [int]$Number } catch { $n = 0 }
    return $n.ToString('#,##0', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-UiDuration {
    <#
    .SYNOPSIS
        Formats a duration in seconds as a compact human string ("8m 12s",
        "43s") for the Performance summary. Sub-second values show one decimal.
    #>
    [CmdletBinding()]
    param([object]$Seconds)
    $s = 0.0
    try { $s = [double]$Seconds } catch { $s = 0.0 }
    if ($s -ge 3600) { return '{0}h {1}m {2}s' -f [int]($s / 3600), [int](($s % 3600) / 60), [int]($s % 60) }
    if ($s -ge 60)   { return '{0}m {1}s' -f [int]($s / 60), [int]($s % 60) }
    if ($s -ge 10)   { return '{0}s' -f [int]$s }
    return '{0:n1}s' -f $s
}

function Get-PerformanceSummary {
    <#
    .SYNOPSIS
        Builds the run performance summary object from State timing data.
    .DESCRIPTION
        Aggregates phase durations (Discovery/Collection/Assessment/Export),
        the slowest checks (top N by DurationSeconds), and the slowest
        subscriptions (top N by inventory-collection time, when measured).
        Pure read of $script:State - safe to call from CLI and JSON export.
    .OUTPUTS
        [pscustomobject] with Phases, TotalSeconds, SlowestChecks,
        SlowestSubscriptions, ExportSeconds.
    #>
    [CmdletBinding()]
    param([int]$Top = 10)

    $phases = @{}
    if ($script:State.Timing -and $script:State.Timing.Phases) {
        foreach ($k in $script:State.Timing.Phases.Keys) { $phases[$k] = [double]$script:State.Timing.Phases[$k] }
    }

    $slowestChecks = @($script:State.ExecutedChecks |
        Where-Object { $null -ne $_.DurationSeconds } |
        Sort-Object { [double]$_.DurationSeconds } -Descending |
        Select-Object -First $Top |
        ForEach-Object {
            [PSCustomObject]@{
                CheckId         = $_.CheckId
                Name            = $_.Name
                DurationSeconds = [double]$_.DurationSeconds
            }
        })

    $slowestSubs = @()
    if ($script:State.Timing -and $script:State.Timing.SubscriptionFetchSeconds -and $script:State.Timing.SubscriptionFetchSeconds.Count -gt 0) {
        $slowestSubs = @($script:State.Timing.SubscriptionFetchSeconds.GetEnumerator() |
            Sort-Object { [double]$_.Value } -Descending |
            Select-Object -First $Top |
            ForEach-Object {
                [PSCustomObject]@{ Subscription = $_.Key; FetchSeconds = [Math]::Round([double]$_.Value, 1) }
            })
    }

    $total = 0.0
    if ($script:State.StartTime) { $total = ((Get-Date) - $script:State.StartTime).TotalSeconds }

    [PSCustomObject]@{
        Phases                = $phases
        ExportSeconds         = if ($phases.ContainsKey('Export')) { [double]$phases['Export'] } else { $null }
        TotalSeconds          = [Math]::Round($total, 1)
        SlowestChecks         = $slowestChecks
        SlowestSubscriptions  = $slowestSubs
    }
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Buffered log writer with severity-colored console output.
    .DESCRIPTION
        Appends a timestamped log entry to $script:State.LogBuffer.
        Flushes automatically when buffer threshold or 30-second timer is reached.
        Console output is color-coded by severity and respects Quiet mode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO",

        [switch]$NoConsole,
        [switch]$ForceConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry  = "$timestamp [$Level] $Message"

    $script:State.LogBuffer.Add($logEntry)

    # Per-check error aggregation: while a check executes (CurrentCheckId set by
    # Invoke-AuditChecks), bucket WARN/ERROR messages by a normalized key (GUIDs
    # and known subscription names stripped) so the CLI prints one summarized
    # line per distinct failure instead of N repeated raw errors. The log file
    # always keeps every original line.
    if (($Level -eq 'WARN' -or $Level -eq 'ERROR') -and $script:State.CurrentCheckId) {
        $cid = "$($script:State.CurrentCheckId)"
        if (-not $script:State.CheckErrors.ContainsKey($cid)) { $script:State.CheckErrors[$cid] = @{} }
        $norm = $Message -replace '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', '<id>'
        if ($script:State.Subscriptions) {
            foreach ($s in @($script:State.Subscriptions)) {
                $sn = "$($s.Name)"
                if ($sn) { $norm = $norm -replace [regex]::Escape($sn), '<sub>' }
            }
        }
        $bucket = $script:State.CheckErrors[$cid]
        if ($bucket.ContainsKey($norm)) { $bucket[$norm] = [int]$bucket[$norm] + 1 } else { $bucket[$norm] = 1 }
    }

    # Determine whether to flush
    $shouldFlush = $false
    if ($script:State.LogBuffer.Count -ge $script:State.LogBufferSize) {
        $shouldFlush = $true
    }
    elseif ((Get-Date) -gt $script:State.LastLogFlush.AddSeconds(30)) {
        $shouldFlush = $true
    }

    if ($shouldFlush) {
        Flush-AuditLog
    }

    # Console output discipline (product UX): the log FILE is the system of
    # record; the console is an operator summary, not a raw log stream.
    #   * default        -> nothing on console (file only)
    #   * -VerboseOutput -> INFO lines on console
    #   * -DebugOutput   -> INFO/WARN/ERROR raw timestamped lines on console
    #   * -ForceConsole  -> always shown (preflight/fatal operator guidance)
    # The per-check human summary line (Invoke-AuditChecks) is the normal
    # console signal for check failures; raw errors never spam a normal run.
    $quiet   = [bool]$script:State.Config.Quiet
    $verbose = [bool]$script:State.Config.VerboseOutput
    $debug   = [bool]$script:State.Config.DebugOutput

    $showOnConsole = $false
    if ($ForceConsole) { $showOnConsole = $true }
    elseif (-not $quiet -and -not $NoConsole) {
        if ($Level -eq 'INFO' -and ($verbose -or $debug)) { $showOnConsole = $true }
        if (($Level -eq 'WARN' -or $Level -eq 'ERROR') -and $debug) { $showOnConsole = $true }
    }

    # Console dedupe: identical WARN/ERROR lines are always counted (tests and
    # diagnostics rely on the counts); printing happens only in debug mode -
    # the first occurrence plus one suppression note on the first repeat.
    $repeatNote = $false
    if ($Level -in @('WARN','ERROR')) {
        if (-not ($script:State.PSObject.Properties.Name -contains 'LogConsoleSeen') -or $null -eq $script:State.LogConsoleSeen) {
            $script:State | Add-Member -NotePropertyName LogConsoleSeen -NotePropertyValue @{}
        }
        $seenKey = "$Level|$Message"
        if ($script:State.LogConsoleSeen.ContainsKey($seenKey)) {
            $script:State.LogConsoleSeen[$seenKey] = [int]$script:State.LogConsoleSeen[$seenKey] + 1
            if ($showOnConsole) {
                $showOnConsole = $false
                if ([int]$script:State.LogConsoleSeen[$seenKey] -eq 2) { $repeatNote = $true }
            }
        }
        else {
            $script:State.LogConsoleSeen[$seenKey] = 1
        }
    }

    if ($repeatNote) {
        Write-UiHost -Text "$timestamp [$Level] (identical message repeated; further repeats suppressed on console - full detail in log file)" -Color DarkGray
    }

    if ($showOnConsole) {
        $consoleMsg = $logEntry
        $firstNewline = $consoleMsg.IndexOfAny([char[]]@("`r","`n"))
        if ($firstNewline -ge 0) { $consoleMsg = $consoleMsg.Substring(0, $firstNewline) + ' ...' }
        if ($consoleMsg.Length -gt 220) { $consoleMsg = $consoleMsg.Substring(0, 220) + ' ...' }
        switch ($Level) {
            "ERROR" { Write-UiHost -Text $consoleMsg -Color Red    }
            "WARN"  { Write-UiHost -Text $consoleMsg -Color Yellow }
            "INFO"  { Write-UiHost -Text $consoleMsg -Color Gray   }
            "DEBUG" { Write-Debug $logEntry                          }
            default { Write-Verbose $logEntry                        }
        }
    }
}

function Flush-AuditLog {
    <#
    .SYNOPSIS
        Thread-safe flush of the log buffer to disk.
    .DESCRIPTION
        Uses System.Threading.Monitor for thread safety.
        Falls back to Add-Content if StreamWriter encounters an error.
    #>
    [CmdletBinding()]
    param()

    if ($script:State.LogBuffer.Count -eq 0) { return }

    try {
        $lockObject = $script:State.LogLock

        [System.Threading.Monitor]::Enter($lockObject)
        try {
            $writer = [System.IO.StreamWriter]::new(
                $script:State.LogFile,
                $true,
                [System.Text.Encoding]::UTF8
            )
            foreach ($line in $script:State.LogBuffer) {
                $writer.WriteLine($line)
            }
            $writer.Close()
            $script:State.LogBuffer.Clear()
            $script:State.LastLogFlush = Get-Date
        }
        finally {
            [System.Threading.Monitor]::Exit($lockObject)
        }
    }
    catch {
        # Fallback: Add-Content if StreamWriter fails
        $script:State.LogBuffer | Add-Content -Path $script:State.LogFile -Encoding UTF8
        $script:State.LogBuffer.Clear()
    }
}

function Show-Banner {
    <#
    .SYNOPSIS
        Displays the AzureMap branded startup banner.
    .PARAMETER SeverityLevel
        Current severity filter to display.
    .PARAMETER Services
        List of services being audited.
    #>
    [CmdletBinding()]
    param(
        [string]$SeverityLevel,
        [string[]]$Services
    )

    if ($script:State.Config.Quiet) { return }

    $meta    = $script:State.Metadata
    $title   = "$($meta.ToolName) v$($meta.Version)".ToUpper()
    $servicesText = if ($Services -and $Services.Count -gt 0) { $Services -join ", " } else { "All" }

    $w = 62
    $line = { param([string]$t) '  ' + ($t + (' ' * $w)).Substring(0, $w) }

    Write-UiHost -Text ("+" + ('=' * ($w + 4)) + "+") -Color Cyan
    Write-UiHost -Text ("|" + (& $line $title) + "  |") -Color Cyan
    Write-UiHost -Text ("|" + (& $line 'Azure / Entra Security Assessment') + "  |") -Color Cyan
    Write-UiHost -Text ("|" + (& $line 'Built by BAAS - 0xbaas.com') + "  |") -Color Cyan
    Write-UiHost -Text ("+" + ('=' * ($w + 4)) + "+") -Color Cyan
    Write-UiHost -Text ("  Started:  " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Color Yellow
    Write-UiHost -Text ("  Severity: " + $SeverityLevel + "   Services: " + $servicesText) -Color Gray
}

function Show-RunContext {
    <#
    .SYNOPSIS
        Prints the resolved run context (mode/account/tenant/scope) once
        preflight has completed.
    #>
    [CmdletBinding()]
    param()

    if ($script:State.Config.Quiet) { return }

    $ctx   = Get-AzContext -ErrorAction SilentlyContinue
    $acct  = if ($ctx -and $ctx.Account) { $ctx.Account.Id } else { 'Unknown' }
    $ten   = if ($ctx -and $ctx.Tenant)  { $ctx.Tenant.Id }  else { 'Unknown' }
    $acct  = Protect-SensitiveText -Text $acct
    $ten   = Protect-SensitiveText -Text $ten
    $mode  = if ($script:State.Config.SkipEntra) { 'Azure-only (-SkipEntra)' } else { 'Full (Azure + Entra)' }
    $dpMode = if ($script:State.Config.IncludeDataPlane) { 'enabled (-IncludeDataPlane)' } else { 'disabled' }

    Write-UiHost -Text ("  Mode:     " + $mode) -Color Gray
    Write-UiHost -Text ("  Data-plane checks: " + $dpMode) -Color Gray
    Write-UiHost -Text ("  Account:  " + $acct) -Color Gray
    Write-UiHost -Text ("  Tenant:   " + $ten) -Color Gray
    Write-UiHost -Text ""
}

function Write-Section {
    <#
    .SYNOPSIS
        Writes a visible section header and optionally updates Write-Progress.
    .PARAMETER Title
        Section title text.
    .PARAMETER Color
        Console color for the header border (default Cyan).
    .PARAMETER ProgressId
        Write-Progress -Id value. If > 0 the progress bar is updated.
    .PARAMETER Status
        Optional status line below the title.
    .NOTES
        Legacy per-check section banners are suppressed in normal product
        output: the grouped per-check status lines are the live signal.
        Banners only render under -DebugOutput (legacy diagnostic mode).
        The Write-Progress update still happens regardless.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [string]$Color = "Cyan",

        [int]$ProgressId = 0,

        [string]$Status = ""
    )

    if ($ProgressId -gt 0) {
        Write-Progress -Activity "AzureMap Security Audit" -Status $Title -Id $ProgressId
    }

    if ($script:State.Config.Quiet) { return }
    if (-not $script:State.Config.DebugOutput) { return }

    $border = "=" * 80
    Write-Host "`n$border" -ForegroundColor $Color
    Write-Host "  $Title"  -ForegroundColor $Color
    if (-not [string]::IsNullOrEmpty($Status)) {
        Write-Host "  Status: $Status" -ForegroundColor $Color
    }
    Write-Host "$border" -ForegroundColor $Color
}

function Get-SafeProgressPercent {
    <#
    .SYNOPSIS
        Computes a Write-Progress -PercentComplete value that is always a scalar
        integer clamped to [0,100].
    .DESCRIPTION
        Defensive against Windows PowerShell 5.1 pitfalls:
          * If a .Count access member-enumerates and yields an array, @($X)[0]
            collapses it back to a scalar (prevents "Argument types do not match"
            from int / array division).
          * Guards divide-by-zero (Total <= 0 -> 0).
          * Clamps the result to [0,100] so an over-counted 'Current' can never
            exceed Write-Progress's ValidateRange (fixes PercentComplete > 100).
    .OUTPUTS
        [int] between 0 and 100 inclusive.
    #>
    [CmdletBinding()]
    param(
        [object]$Current,
        [object]$Total
    )

    $c = 0
    $t = 0
    try { $c = [int](@($Current)[0]) } catch { $c = 0 }
    try { $t = [int](@($Total)[0]) }   catch { $t = 0 }

    if ($t -le 0) { return 0 }

    $p = [int](($c / $t) * 100)
    if ($p -lt 0)   { return 0 }
    if ($p -gt 100) { return 100 }
    return $p
}
