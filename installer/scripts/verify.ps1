param(
    [Alias("Artifact")]
    [string]$MsiArtifact = (Join-Path $PSScriptRoot "..\..\build\installer\en-us\GnxNode.msi"),
    [string]$BurnArtifact = (Join-Path $PSScriptRoot "..\..\build\installer\GnxNodeSetup.exe")
)
$ErrorActionPreference = "Stop"
function Assert-Artifact([string]$Path, [string]$Label) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing $Label artifact: $Path" }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -le 0) { throw "$Label artifact is empty: $Path" }
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    [pscustomobject]@{
        Artifact = $Label
        Path = $item.FullName
        Bytes = $item.Length
        SHA256 = $hash.Hash
    }
}

Assert-Artifact $MsiArtifact "MSI"
Assert-Artifact $BurnArtifact "Burn"
