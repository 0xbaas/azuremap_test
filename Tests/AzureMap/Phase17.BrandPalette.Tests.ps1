#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase17.BrandPalette.Tests.ps1
# Official BAAS / AzureMap dark palette: HTML CSS variables, truecolor CLI
# mapping, NoColor safety, and status-line alignment under ANSI escapes.
# Mocked/local only. No Azure, no Graph, no data-plane.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Products\AzureMap\Core\Footprint.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"
    . "$projectRoot\Shared\Export\Csv.ps1"
    . "$projectRoot\Shared\Export\Json.ps1"
    . "$projectRoot\Shared\Export\Html.ps1"

    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }
    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }

    function script:Remove-Ansi {
        param([AllowEmptyString()][string]$Text)
        return ("$Text" -replace "$([char]27)\[[0-9;]*m", '')
    }
}

Describe "HTML uses the official BAAS palette" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $script:htmlPath = Join-Path $TestDrive 'palette.html'
        Export-ResultsHtml -Results @() -OutputPath $script:htmlPath | Out-Null
        $script:html = Get-Content -Path $script:htmlPath -Raw
    }

    It "declares the official core palette variables" {
        foreach ($hex in @('#111214','#16171A','#1D1F23','#202227','#23262B','#30343A','#38A8DC','#163746','#F1F3F5','#9AA5B1','#D6A84B')) {
            $script:html | Should -Match ([regex]::Escape($hex))
        }
    }

    It "declares the official status and severity colors" {
        foreach ($hex in @('#5FBF7A','#E05D5D','#F05252','#E68A3A','#9BE7A1','#FF6B6B','#6F7782')) {
            $script:html | Should -Match ([regex]::Escape($hex))
        }
    }

    It "uses #38A8DC as the accent color" {
        $script:html | Should -Match '--accent:#38A8DC'
    }

    It "no longer uses the old GitHub-ish defaults" {
        foreach ($hex in @('#0d1117','#161b22','#58a6ff','#3fb950','#f85149','#d29922','#f0883e','#7ee787','#bb8009','#ff7b72','#6e7681','#1c2330','#e6e9ef','#8b949e','#2d333d')) {
            $script:html | Should -Not -Match ([regex]::Escape($hex))
        }
    }
}

Describe "Write-UiHost BAAS truecolor mapping" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.NoColor = $false
        if ($env:NO_COLOR) { $env:NO_COLOR = $null }
        $script:UiForceAnsi = $null
    }

    AfterEach {
        $script:UiForceAnsi = $null
    }

    It "emits ANSI truecolor for brand-mapped colors when the host supports it" {
        $script:UiForceAnsi = $true
        Mock Write-Host {}
        Write-UiHost -Text 'risky' -Color Red
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter {
            "$Object" -match [regex]::Escape("$([char]27)[38;2;224;93;93m") -and
            "$Object" -match 'risky' -and
            -not $PSBoundParameters.ContainsKey('ForegroundColor')
        }
    }

    It "maps Cyan to the BAAS accent RGB" {
        $script:UiForceAnsi = $true
        Mock Write-Host {}
        Write-UiHost -Text 'hdr' -Color Cyan
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter {
            "$Object" -match [regex]::Escape("$([char]27)[38;2;56;168;220m")
        }
    }

    It "falls back to ForegroundColor when ANSI is not supported" {
        $script:UiForceAnsi = $false
        Mock Write-Host {}
        Write-UiHost -Text 'legacy' -Color Red
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter {
            $ForegroundColor -eq 'Red' -and "$Object" -eq 'legacy' -and "$Object" -notmatch "$([char]27)\["
        }
    }

    It "NoColor emits plain text without ANSI escapes or ForegroundColor" {
        $script:State.Config.NoColor = $true
        $script:UiForceAnsi = $true
        Mock Write-Host {}
        Write-UiHost -Text 'plain' -Color Red
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter {
            "$Object" -eq 'plain' -and
            "$Object" -notmatch "$([char]27)\[" -and
            -not $PSBoundParameters.ContainsKey('ForegroundColor')
        }
    }

    It "passes NoNewline through" {
        $script:UiForceAnsi = $false
        Mock Write-Host {}
        Write-UiHost -Text 'seg' -Color Green -NoNewline
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter {
            $NoNewline -eq $true -and $ForegroundColor -eq 'Green'
        }
    }

    It "auto-detection never throws and returns a bool" {
        $script:UiForceAnsi = $null
        $result = Test-UiAnsiSupport
        $result | Should -BeOfType [bool]
    }
}

Describe "Write-CheckStatusLine alignment with BAAS colors" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $false
        $script:State.Config.NoColor = $true
        $script:UiForceAnsi = $null
        $script:captured = New-Object System.Collections.Generic.List[string]
    }

    AfterEach {
        $script:UiForceAnsi = $null
    }

    It "status label starts at a fixed column with NoColor" {
        Mock Write-Host { param($Object) [void]$script:captured.Add("$Object") }
        $check  = [PSCustomObject]@{ CheckId = 'STORAGE-001'; Name = 'Shared Key Authentication'; Service = 'Storage'; Category = 'Azure' }
        $record = [PSCustomObject]@{ Status = 'Fail'; SummaryText = '20 of 60 risky; coverage complete' }
        Write-CheckStatusLine -Index 1 -Total 41 -Check $check -Record $record
        $line = ($script:captured -join '')
        # Human layout: domain header, display name, human label, summary, muted CheckId.
        $line | Should -Match 'Storage'
        $line | Should -Match '  Shared key authentication\s+Needs review\s+20 of 60 risky\s+STORAGE-001'
        # Fixed columns: name segment is exactly 40 chars, label starts right after.
        $script:captured[2] | Should -Match '^  Shared key authentication\s+$'
        $script:captured[2].Length | Should -Be 40
        $script:captured[3] | Should -Match '^Needs review\s+$'
        $line | Should -Not -Match '\bFAIL\b'
        $line | Should -Not -Match '^\[01/41\]'
    }

    It "alignment survives ANSI escapes when truecolor is active" {
        $script:State.Config.NoColor = $false
        $script:UiForceAnsi = $true
        Mock Write-Host { param($Object) [void]$script:captured.Add("$Object") }
        $check  = [PSCustomObject]@{ CheckId = 'STORAGE-001'; Name = 'Shared Key Authentication'; Service = 'Storage'; Category = 'Azure' }
        $record = [PSCustomObject]@{ Status = 'Fail'; SummaryText = '20 of 60 risky; coverage complete' }
        Write-CheckStatusLine -Index 1 -Total 41 -Check $check -Record $record
        $raw = ($script:captured -join '')
        $raw | Should -Match "$([char]27)\[38;2;"
        $plain = script:Remove-Ansi -Text $raw
        # Name segment (index 2, after blank + domain header) stays exactly 40
        # chars even when every segment carries ANSI escapes.
        $plainSeg = script:Remove-Ansi -Text "$($script:captured[2])"
        $plainSeg | Should -Match '^  Shared key authentication\s+$'
        $plainSeg.Length | Should -Be 40
        $plain | Should -Match '  Shared key authentication\s+Needs review\s+20 of 60 risky\s+STORAGE-001'
    }

    It "colors only the status label, not the whole line" {
        $script:State.Config.NoColor = $false
        $script:UiForceAnsi = $false
        Mock Write-Host { param($Object, $ForegroundColor) [void]$script:captured.Add("$ForegroundColor|$Object") }
        $check  = [PSCustomObject]@{ CheckId = 'STORAGE-001'; Name = 'Shared Key Authentication'; Service = 'Storage'; Category = 'Azure' }
        $record = [PSCustomObject]@{ Status = 'Fail'; SummaryText = '20 of 60 risky; coverage complete' }
        Write-CheckStatusLine -Index 1 -Total 41 -Check $check -Record $record
        $segments = @($script:captured)
        $segments.Count | Should -BeGreaterThan 1
        ($segments | Where-Object { $_ -match '^\w+\|Storage$' })        | Should -Match '^Cyan\|'
        ($segments | Where-Object { $_ -match 'Needs review' })          | Should -Match '^DarkYellow\|'
        ($segments | Where-Object { $_ -match 'risky' })                 | Should -Match '^Gray\|'
        ($segments | Where-Object { $_ -match 'STORAGE-001' })           | Should -Match '^DarkGray\|'
    }
}
