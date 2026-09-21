param([string]$Configuration = "release")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$out = Join-Path $root "build\installer"
New-Item -ItemType Directory -Force $out | Out-Null
Push-Location $root; cargo build --workspace --release; if ($LASTEXITCODE) { throw "cargo build failed" }; Pop-Location
$ui = Join-Path $out "ui"; New-Item -ItemType Directory -Force $ui | Out-Null
Copy-Item (Join-Path $root "apps\setup\ui\*") $ui -Recurse -Force
$project = Join-Path $PSScriptRoot "..\GnxNode.wixproj"
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "WiX build unavailable: dotnet SDK not found" }
dotnet build $project -p:Configuration=$Configuration -p:OutputPath=$out
if ($LASTEXITCODE) { throw "WiX build failed" }
Write-Output "Installer build complete: $out"
