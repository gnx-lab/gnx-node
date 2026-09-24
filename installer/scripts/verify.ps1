param(
    [Alias("Artifact")]
    [string]$MsiArtifact = (Join-Path $PSScriptRoot "..\..\build\installer\en-us\GnxNode.msi"),
    [string]$BurnArtifact = (Join-Path $PSScriptRoot "..\..\build\installer\GnxNodeSetup.exe")
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$rootfsArtifact = Join-Path $root "payload\host\gnx-node-rootfs.tar"
$rootfsManifest = Join-Path $root "payload\host\gnx-node-rootfs.tar.sha256"
$expectedRootfsDigest = "5215c762cd1562b9b6836b01f6e1a2207cee7bae0ee334e50316af72b9a871af"
if (!(Test-Path -LiteralPath $rootfsArtifact -PathType Leaf)) { throw "Missing sealed WSL rootfs artifact: $rootfsArtifact" }
if (!(Test-Path -LiteralPath $rootfsManifest -PathType Leaf)) { throw "Missing sealed WSL rootfs manifest: $rootfsManifest" }
$manifestLine = (Get-Content -LiteralPath $rootfsManifest -Raw).Trim()
if ($manifestLine -notmatch '^[0-9a-f]{64}  gnx-node-rootfs\.tar$') { throw "Invalid sealed WSL rootfs manifest format: $rootfsManifest" }
$manifestDigest = $manifestLine.Substring(0, 64)
if ($manifestDigest -ne $expectedRootfsDigest) { throw "Unexpected sealed WSL rootfs digest: $manifestDigest" }
$actualRootfsDigest = (Get-FileHash -LiteralPath $rootfsArtifact -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualRootfsDigest -ne $manifestDigest) { throw "Sealed WSL rootfs digest mismatch: expected $manifestDigest, got $actualRootfsDigest" }
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
