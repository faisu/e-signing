# Build the AutoDCR Bridge MSI.
#
# Required env vars:
#   AUTODCR_VERSION         semver, e.g. "0.1.0" or "v0.1.0"
#   AUTODCR_EXTENSION_ID    Chrome extension ID
#
# Optional env vars:
#   AUTODCR_PFX_PATH        path to PFX for code signing the .msi
#   AUTODCR_PFX_PASSWORD    password for the PFX
#
# Required filesystem layout:
#   artifacts\windows-x64\autodcr-bridge.exe
#
# Output:
#   installer\windows\dist\AutoDCR-Bridge-<version>.msi

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $Env:AUTODCR_VERSION) { throw "AUTODCR_VERSION is required" }
if (-not $Env:AUTODCR_EXTENSION_ID) { throw "AUTODCR_EXTENSION_ID is required" }

$version = $Env:AUTODCR_VERSION.TrimStart("v")
$repoRoot = Resolve-Path "$PSScriptRoot\..\.."
$installerDir = Join-Path $repoRoot "installer\windows"
$distDir = Join-Path $installerDir "dist"
$workDir = Join-Path $installerDir "build"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

# Locate the binary produced by the build-native job.
$binarySource = Resolve-Path "$repoRoot\artifacts\windows-x64\autodcr-bridge.exe"

# Render the manifest with the actual extension id.
$manifestTemplate = Get-Content -Raw (Join-Path $repoRoot "native-host\manifests\com.example.autodcr.signer.json")
$rendered = $manifestTemplate `
  -replace '<ABSOLUTE_PATH_TO_LAUNCHER>', '[AUTODCR_BRIDGE_PATH_PLACEHOLDER]\autodcr-bridge.exe' `
  -replace '<EXTENSION_ID_PLACEHOLDER>', $Env:AUTODCR_EXTENSION_ID

# The MSI will substitute the real install path at runtime via the registry
# value, but the manifest JSON itself needs an absolute "path" too. Chrome
# resolves path relative to the manifest file when it's a relative path, so
# we use just the binary name.
$rendered = $rendered -replace '\[AUTODCR_BRIDGE_PATH_PLACEHOLDER\]\\autodcr-bridge\.exe', 'autodcr-bridge.exe'

$manifestPath = Join-Path $workDir "com.example.autodcr.signer.json"
Set-Content -Path $manifestPath -Value $rendered -Encoding UTF8

$msiPath = Join-Path $distDir "AutoDCR-Bridge-$version.msi"
$wxsPath = Join-Path $installerDir "autodcr-bridge.wxs"

Write-Host "Building $msiPath"
& wix build $wxsPath `
  -d "Version=$version" `
  -d "BinarySource=$binarySource" `
  -d "ManifestSource=$manifestPath" `
  -arch x64 `
  -out $msiPath

if ($LASTEXITCODE -ne 0) {
  throw "wix build failed with exit code $LASTEXITCODE"
}

if ($Env:AUTODCR_PFX_PATH) {
  Write-Host "Signing $msiPath"
  & signtool sign `
    /f $Env:AUTODCR_PFX_PATH `
    /p $Env:AUTODCR_PFX_PASSWORD `
    /tr "http://timestamp.digicert.com" `
    /td sha256 `
    /fd sha256 `
    $msiPath
  if ($LASTEXITCODE -ne 0) {
    throw "signtool failed with exit code $LASTEXITCODE"
  }
}

Write-Host "Built $msiPath"
