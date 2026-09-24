param([string]$Configuration = "release")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$out = Join-Path $root "build\installer"
$hostPayloadSource = Join-Path $root "payload\host"
$rootfsArtifact = Join-Path $hostPayloadSource "gnx-node-rootfs.tar"
$rootfsManifest = Join-Path $hostPayloadSource "gnx-node-rootfs.tar.sha256"
$expectedRootfsDigest = "5215c762cd1562b9b6836b01f6e1a2207cee7bae0ee334e50316af72b9a871af"
if (!(Test-Path -LiteralPath $rootfsArtifact -PathType Leaf)) {
    throw "Missing sealed WSL rootfs artifact: $rootfsArtifact"
}
if (!(Test-Path -LiteralPath $rootfsManifest -PathType Leaf)) {
    throw "Missing sealed WSL rootfs manifest: $rootfsManifest"
}
$manifestLine = (Get-Content -LiteralPath $rootfsManifest -Raw).Trim()
if ($manifestLine -notmatch '^[0-9a-f]{64}  gnx-node-rootfs\.tar$') {
    throw "Invalid sealed WSL rootfs manifest format: $rootfsManifest"
}
$manifestDigest = $manifestLine.Substring(0, 64)
if ($manifestDigest -ne $expectedRootfsDigest) {
    throw "Unexpected sealed WSL rootfs digest: $manifestDigest"
}
$actualRootfsDigest = (Get-FileHash -LiteralPath $rootfsArtifact -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualRootfsDigest -ne $manifestDigest) {
    throw "Sealed WSL rootfs digest mismatch: expected $manifestDigest, got $actualRootfsDigest"
}
New-Item -ItemType Directory -Force $out | Out-Null
$msi = Join-Path $out "en-us\GnxNode.msi"
$exe = Join-Path $out "GnxNodeSetup.exe"
foreach ($artifact in @($msi, $exe)) {
    if (Test-Path -LiteralPath $artifact -PathType Leaf) {
        Remove-Item -LiteralPath $artifact -Force
    }
}
Push-Location $root
try {
    cargo build --workspace --release
    if ($LASTEXITCODE) { throw "cargo build failed" }
}
finally { Pop-Location }
$ui = Join-Path $out "ui"; if (Test-Path -LiteralPath $ui) { Remove-Item -LiteralPath $ui -Recurse -Force }; New-Item -ItemType Directory -Force $ui | Out-Null
Copy-Item (Join-Path $root "apps\setup\ui\*") $ui -Recurse -Force
$node = Join-Path $out "..\payload\node"; if (Test-Path -LiteralPath $node) { Remove-Item -LiteralPath $node -Recurse -Force }; New-Item -ItemType Directory -Force $node | Out-Null
Copy-Item (Join-Path $root "payload\node\*") $node -Recurse -Force
$hostPayload = Join-Path $out "..\payload\host"; if (Test-Path -LiteralPath $hostPayload) { Remove-Item -LiteralPath $hostPayload -Recurse -Force }; New-Item -ItemType Directory -Force $hostPayload | Out-Null
Copy-Item (Join-Path $hostPayloadSource "*") $hostPayload -Recurse -Force
$web = Join-Path $node "web-app"; New-Item -ItemType Directory -Force $web | Out-Null
Copy-Item (Join-Path $root "apps\web-app\*") $web -Recurse -Force
# Linux consumes shell scripts, Quadlets, nftables, Caddy and web assets from
# this staged tree. Normalize before hashing so Windows checkout settings can
# never inject CRLF into parsers or systemd units.
Get-ChildItem $node -File -Recurse | ForEach-Object {
    $text = [IO.File]::ReadAllText($_.FullName)
    $normalized = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    [IO.File]::WriteAllText($_.FullName, $normalized, [Text.UTF8Encoding]::new($false))
}
$nodeRoot = (Resolve-Path $node).Path
$marker = Join-Path $nodeRoot ".gnx-payload.sha256"
$payloadLines = Get-ChildItem $nodeRoot -File -Recurse | Where-Object { $_.FullName -ne $marker } | Sort-Object FullName | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $relative = $_.FullName.Substring($nodeRoot.Length + 1).Replace('\', '/')
    "$hash  /opt/gnx/payload/node/$relative"
}
$payloadLines | Set-Content $marker -Encoding ASCII
$manifest = Join-Path $out "..\manifests\payload.sha256"; New-Item -ItemType Directory -Force (Split-Path $manifest) | Out-Null
Get-ChildItem (Join-Path $out "..\payload") -File -Recurse | Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $($_.Path.Substring($root.Length + 1))" } | Set-Content $manifest -Encoding UTF8
$project = Join-Path $PSScriptRoot "..\GnxNode.wixproj"
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "WiX build unavailable: dotnet SDK not found" }
dotnet build $project -p:Configuration=$Configuration -p:OutputPath=$out
if ($LASTEXITCODE) { throw "WiX build failed" }
if (!(Test-Path -LiteralPath $msi)) { throw "WiX did not produce the localized MSI: $msi" }

# Burn is intentionally built after MSI so the bundle embeds this exact MSI.
$bundle = Join-Path $PSScriptRoot "..\bundle\Bundle.wixproj"
dotnet build $bundle -p:Configuration=$Configuration -p:OutputPath=$out
if ($LASTEXITCODE) { throw "Burn build failed" }
if (!(Test-Path -LiteralPath $exe)) { throw "Burn did not produce the setup bundle: $exe" }
Write-Output "Installer build complete: $out"
Write-Output "MSI: $msi"
Write-Output "Burn: $exe"
