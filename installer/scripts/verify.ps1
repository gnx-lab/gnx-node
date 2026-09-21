param([string]$Artifact = (Join-Path $PSScriptRoot "..\..\build\installer\GnxNode.msi"))
$ErrorActionPreference = "Stop"
if (!(Test-Path $Artifact)) { throw "Missing MSI artifact: $Artifact" }
$item = Get-Item $Artifact
Write-Output "Verified MSI: $($item.FullName) ($($item.Length) bytes)"
Get-FileHash $Artifact -Algorithm SHA256 | Select-Object Algorithm,Hash,Path
