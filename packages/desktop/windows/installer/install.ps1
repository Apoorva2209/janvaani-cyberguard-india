# Installs the JanVaani MSIX package that ships next to this script.
# Run by the setup wizard (as administrator). The package is signed with a self-signed
# certificate, so that certificate is trusted for packages first.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$cert = Get-ChildItem -Path $here -Filter '*.cer' | Select-Object -First 1
if (-not $cert) { throw 'Certificate file (.cer) not found next to install.ps1.' }
Import-Certificate -FilePath $cert.FullName -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null

$package = Get-ChildItem -Path $here -Filter '*.msix' -File | Select-Object -First 1
if (-not $package) { throw 'Package file (.msix) not found next to install.ps1.' }

# Windows App Runtime and other framework packages the app needs, bundled for this machine's architecture.
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
$depDir = Join-Path $here (Join-Path 'Dependencies' $arch)
$dependencies = @()
if (Test-Path $depDir) {
    $dependencies = Get-ChildItem -Path $depDir -Filter '*.msix' -File | ForEach-Object { $_.FullName }
}

if ($dependencies.Count -gt 0) {
    Add-AppxPackage -Path $package.FullName -DependencyPath $dependencies -ForceApplicationShutdown
} else {
    Add-AppxPackage -Path $package.FullName -ForceApplicationShutdown
}
