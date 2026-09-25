# Builds the Windows Installer packages for the Nexus agent (x64 and arm64).
#   build-msi.ps1 -Version 1.2.3 -ReleaseDir ..\..\dist\1.2.3 -OutDir ..\..\dist\1.2.3
#
# Needs the WiX Toolset v5: dotnet tool install --global wix --version 5.0.2
# Signing (optional, both the binary and the .msi), with signtool from the Windows SDK:
#   NEXUS_WINDOWS_CERT           base64 of a code-signing .pfx
#   NEXUS_WINDOWS_CERT_PASSWORD  its password
#   NEXUS_TIMESTAMP_URL          default http://timestamp.digicert.com
param(
  [Parameter(Mandatory)] [string] $Version,
  [Parameter(Mandatory)] [string] $ReleaseDir,
  [Parameter(Mandatory)] [string] $OutDir,
  [string[]] $Arch = @("x64", "arm64")
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Windows Installer versions are numeric: 1.2.3-rc.1 becomes 1.2.3.
$msiVersion = ($Version -replace '^v', '') -replace '[-+].*$', ''
if ($msiVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Version must look like 1.2.3 (got $Version)" }

$pfx = $null
if ($env:NEXUS_WINDOWS_CERT) {
  $pfx = Join-Path ([IO.Path]::GetTempPath()) "nexus-signing.pfx"
  [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:NEXUS_WINDOWS_CERT))
}
$ts = if ($env:NEXUS_TIMESTAMP_URL) { $env:NEXUS_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }
function Sign([string] $path) {
  if (-not $pfx) { return }
  & signtool sign /fd SHA256 /td SHA256 /tr $ts /f $pfx /p $env:NEXUS_WINDOWS_CERT_PASSWORD /d "Votal Nexus agent" $path
  if ($LASTEXITCODE) { throw "signtool failed for $path" }
}

try {
  foreach ($a in $Arch) {
    $goarch = @{ x64 = "amd64"; arm64 = "arm64" }[$a]
    $src = Join-Path $ReleaseDir "nexus-agent-windows-$goarch.exe"
    if (-not (Test-Path $src)) { Write-Warning "skipping $a`: $src not found"; continue }
    $bin = Join-Path ([IO.Path]::GetTempPath()) "nexus-msi-$a"
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    Copy-Item $src (Join-Path $bin "nexus-agent.exe") -Force
    Sign (Join-Path $bin "nexus-agent.exe")

    $msi = Join-Path $OutDir "nexus-agent-$Version-$a.msi"
    Write-Host "==> wix build $msi"
    & wix build (Join-Path $here "Package.wxs") -arch $a -d "Version=$msiVersion" -d "BinDir=$bin" -o $msi
    if ($LASTEXITCODE) { throw "wix build failed for $a" }
    Sign $msi
    if (-not $pfx) { Write-Host "note: $msi is not signed (set NEXUS_WINDOWS_CERT and NEXUS_WINDOWS_CERT_PASSWORD)" }
  }
} finally {
  if ($pfx) { Remove-Item $pfx -Force -ErrorAction SilentlyContinue }
}
