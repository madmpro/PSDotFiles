# These components will be loaded when running Microsoft.Powershell (i.e. Not Visual Studio)

Push-Location (Join-Path (Split-Path -parent $profile) "Components")

# From within the ./Components directory...
. .\VisualStudio.ps1
. .\Console.ps1

Pop-Location
