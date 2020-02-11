###############################################################################
### These components will be loaded for all PowerShell instances              #
###############################################################################

# Push the current location onto top of the stack of locations.
Push-Location (Join-Path (Split-Path -parent $profile) "Components")

# From within the ./components directory...
# Run:
. .\coreaudio.ps1
. .\git.ps1

# Change current location to most recently pushed location.
Pop-Location
