###############################################################################
## Bootstrap
###############################################################################

$ProfileDir = Split-Path -parent $profile
$ComponentDir = Join-Path $ProfileDir "Components"
$FunctionsDir = Join-Path $ProfileDir "Functions"
$ModulesDir = Join-Path $ProfileDir "Modules\Functions"

New-Item $ProfileDir -ItemType Directory -Force -ErrorAction SilentlyContinue
New-Item $ComponentDir -ItemType Directory -Force -ErrorAction SilentlyContinue
New-Item $ModulesDir -ItemType Directory -Force -ErrorAction SilentlyContinue

Copy-Item -Path ./*.ps1 -Destination $ProfileDir -Exclude "Bootstrap.ps1"
Copy-Item -Path ./Components/** -Destination $ComponentDir -Include **
Copy-Item -Path ./Modules/Functions/** -Destination $ModulesDir -Include **
Copy-Item -Path ./Home/** -Destination $home -Include **

Remove-Variable componentDir
Remove-Variable profileDir

###############################################################################
## Install Modules
###############################################################################

if (!(Test-Path $env:USERPROFILE\Documents\WindowsPowerShell\Modules\posh-git)) {
  Install-Module posh-git -Scope CurrentUser
}

if (!(Test-Path $env:USERPROFILE\Documents\WindowsPowerShell\Modules\WebAdministration)) {
  Install-Module WebAdministration -Scope CurrentUser
}

PowerShell
