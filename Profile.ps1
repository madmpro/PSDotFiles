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


. (Join-Path -Path (Split-Path -Parent -Path $PROFILE) -ChildPath $(switch($HOST.UI.RawUI.BackgroundColor.ToString()){'White'{'Set-SolarizedLightColorDefaults.ps1'}'Black'{'Set-SolarizedDarkColorDefaults.ps1'}default{return}}))


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

# PowerShell drives
&{
New-PSDrive -Scope Global -PSProvider Registry -Name HKU -Root HKEY_USERS
New-PSDrive -Scope Global -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT
New-PSDrive -Scope Global -PSProvider Registry -Name HKCC -Root HKEY_CURRENT_CONFIG
} | Out-Null

###############################################################################
### Quick ways to navigate around the system, e.g. cd $documents
###############################################################################

$documents = $home + "\Documents"
$desktop = $home + "\Desktop"
$downloads = $home + "\Downloads"
$modules = $home + "\Documents\WindowsPowerShell\Modules"
