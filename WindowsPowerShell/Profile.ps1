###############################################################################
### Profile for the Microsoft.Powershell Shell, only.                         #
### All Users, All Hosts (Not Visual Studio or other PoSh instances)          #
###############################################################################


@"

                ___   ___  __  ___
         __ _  / _ | / _ \/  |/  / ___  _______
        /  ' \/ __ |/ // / /|_/ / / _ \/ __/ _ \
       /_/_/_/_/ |_/____/_/  /_(_) .__/_/  \___/
                                /_/

"@

echo "Importing modules..."
#Import-Module UCMClasses
Import-Module Functions
#Import-Module WebAdministration

# Push the current location onto top of the stack of locations.
Push-Location (Split-Path -parent $profile)
# Run:
"Components","Aliases","Exports","Extra" | Where-Object {Test-Path "$_.ps1"} | ForEach-Object -process {Invoke-Expression ". .\$_.ps1"}

# Change current location to most recently pushed location.
Pop-Location

# Set Solarized theme
switch($HOST.UI.RawUI.BackgroundColor.ToString()){'White'{Set-SolarizedLightColorDefaults}'Black'{Set-SolarizedDarkColorDefaults}default{return}}
