#==============================================================================
# AzureMap v2 - Core/Cache.ps1
# Three-tier in-memory cache (Graph, AzBatch, General) with TTL, optional
# GZip compression, and LRU eviction.
# All functions reference $script:State. Strictly read-only data.
#==============================================================================

# Maximum entries per cache tier before LRU eviction kicks in
$script:MaxCacheSize = 100

function Set-AuditCache {
    <#
    .SYNOPSIS
        Stores a value in the specified cache tier with TTL and optional GZip.
    .PARAMETER Key
        Cache key string.
    .PARAMETER Value
        The object to cache.
    .PARAMETER Type
        Cache tier: Graph, AzBatch, or General (default General).
    .PARAMETER TTLMinutes
        Time-to-live in minutes (default 30).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [object]$Value,

        [ValidateSet("Graph","AzBatch","General")]
        [string]$Type = "General",

        [int]$TTLMinutes = 30
    )

    $tier = $script:State.Cache[$Type]
    if (-not $tier) {
        $script:State.Cache[$Type] = @{}
        $tier = $script:State.Cache[$Type]
    }

    # LRU eviction when at capacity
    if ($tier.Count -ge $script:MaxCacheSize -and -not $tier.ContainsKey($Key)) {
        $oldest = $tier.GetEnumerator() |
                  Sort-Object { $_.Value.LastAccess } |
                  Select-Object -First 1
        if ($oldest) {
            $tier.Remove($oldest.Key)
            Write-AuditLog -Message "Cache LRU eviction ($Type): removed key '$($oldest.Key)'" -Level DEBUG
        }
    }

    # Optional GZip for payloads > 1 KB
    $compressed  = $false
    $storedValue = $Value

    try {
        $serialized = [System.Management.Automation.PSSerializer]::Serialize($Value)
        if ($serialized.Length -gt 1024) {
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes($serialized)
            $ms     = [System.IO.MemoryStream]::new()
            $gz     = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress)
            $gz.Write($bytes, 0, $bytes.Length)
            $gz.Close()
            $storedValue = $ms.ToArray()
            $ms.Close()
            $compressed = $true
        }
    }
    catch {
        # Serialization or compression failed - store raw
        $storedValue = $Value
        $compressed  = $false
    }

    $tier[$Key] = @{
        Value      = $storedValue
        Compressed = $compressed
        ExpiresAt  = (Get-Date).AddMinutes($TTLMinutes)
        LastAccess = Get-Date
        CreatedAt  = Get-Date
    }
}

function Get-AuditCache {
    <#
    .SYNOPSIS
        Retrieves a value from the specified cache tier.
    .DESCRIPTION
        Returns $null if the key is missing or expired. Expired entries are
        automatically removed. GZip-compressed entries are decompressed
        transparently.
    .PARAMETER Key
        Cache key string.
    .PARAMETER Type
        Cache tier: Graph, AzBatch, or General (default General).
    .OUTPUTS
        The cached object, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [ValidateSet("Graph","AzBatch","General")]
        [string]$Type = "General"
    )

    $tier = $script:State.Cache[$Type]
    if (-not $tier -or -not $tier.ContainsKey($Key)) {
        return $null
    }

    $entry = $tier[$Key]

    # Auto-expire stale entries
    if ((Get-Date) -gt $entry.ExpiresAt) {
        $tier.Remove($Key)
        return $null
    }

    $entry.LastAccess = Get-Date

    if ($entry.Compressed) {
        try {
            $ms  = [System.IO.MemoryStream]::new($entry.Value)
            $gz  = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $sr  = [System.IO.StreamReader]::new($gz, [System.Text.Encoding]::UTF8)
            $xml = $sr.ReadToEnd()
            $sr.Close()
            $gz.Close()
            $ms.Close()
            return [System.Management.Automation.PSSerializer]::Deserialize($xml)
        }
        catch {
            Write-AuditLog -Message "Cache decompression failed for key '$Key' ($Type): $_" -Level WARN
            $tier.Remove($Key)
            return $null
        }
    }

    return $entry.Value
}

function Invoke-CacheableOperation {
    <#
    .SYNOPSIS
        Cache-through wrapper: check cache -> execute scriptblock -> store result.
    .PARAMETER Key
        Cache key string.
    .PARAMETER Type
        Cache tier (default General).
    .PARAMETER TTLMinutes
        TTL for the stored result (default 30).
    .PARAMETER ScriptBlock
        The operation to execute on cache miss.
    .OUTPUTS
        The cached or freshly computed result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [ValidateSet("Graph","AzBatch","General")]
        [string]$Type = "General",

        [int]$TTLMinutes = 30,

        [Parameter(Mandatory)]
        [ScriptBlock]$ScriptBlock
    )

    $cached = Get-AuditCache -Key $Key -Type $Type
    if ($null -ne $cached) {
        Write-AuditLog -Message "Cache hit ($Type): $Key" -Level DEBUG
        return $cached
    }

    Write-AuditLog -Message "Cache miss ($Type): $Key - executing operation" -Level DEBUG
    $result = & $ScriptBlock

    if ($null -ne $result) {
        Set-AuditCache -Key $Key -Value $result -Type $Type -TTLMinutes $TTLMinutes
    }

    return $result
}

function Clear-AuditCache {
    <#
    .SYNOPSIS
        Clears one or all cache tiers.
    .PARAMETER Type
        Specific tier to clear. If omitted, all tiers are cleared.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Graph","AzBatch","General")]
        [string]$Type
    )

    if ($Type) {
        if ($script:State.Cache[$Type]) {
            $count = $script:State.Cache[$Type].Count
            $script:State.Cache[$Type] = @{}
            Write-AuditLog -Message "Cleared cache tier '$Type' ($count entries)" -Level INFO
        }
    }
    else {
        foreach ($tier in @("Graph","AzBatch","General")) {
            if ($script:State.Cache[$tier]) {
                $script:State.Cache[$tier] = @{}
            }
        }
        Write-AuditLog -Message "All cache tiers cleared" -Level INFO
    }
}
