param([string]$Configuration = "release")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$out = Join-Path $root "build\installer"
New-Item -ItemType Directory -Force $out | Out-Null
Push-Location $root; cargo build --workspace --release; if ($LASTEXITCODE) { throw "cargo build failed" }; Pop-Location
$ui = Join-Path $out "ui"; New-Item -ItemType Directory -Force $ui | Out-Null
Copy-Item (Join-Path $root "apps\setup\ui\*") $ui -Recurse -Force
$node = Join-Path $out "..\payload\node"; New-Item -ItemType Directory -Force $node | Out-Null
Copy-Item (Join-Path $root "payload\node\*") $node -Recurse -Force
$web = Join-Path $node "web-app"; New-Item -ItemType Directory -Force $web | Out-Null
Copy-Item (Join-Path $root "apps\web-app\*") $web -Recurse -Force
$manifest = Join-Path $out "..\manifests\payload.sha256"; New-Item -ItemType Directory -Force (Split-Path $manifest) | Out-Null
Get-ChildItem (Join-Path $out "..\payload") -File -Recurse | Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $($_.Path.Substring($root.Length + 1))" } | Set-Content $manifest -Encoding UTF8
$project = Join-Path $PSScriptRoot "..\GnxNode.wixproj"
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "WiX build unavailable: dotnet SDK not found" }
dotnet build $project -p:Configuration=$Configuration -p:OutputPath=$out
if ($LASTEXITCODE) { throw "WiX build failed" }
Write-Output "Installer build complete: $out"
