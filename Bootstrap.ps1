################################################################################
## Bootstrap
################################################################################

Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		If ($PSVersionTable.PSVersion.Major -eq 5) {
				Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		}
		ElseIf ($PSVersionTable.PSVersion.Major -eq 6) {
				Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		}

		Exit
	}
}

Function RestartPowerShell {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		If ($PSVersionTable.PSVersion.Major -eq 5) {
				Start-Process powershell.exe
		}
		ElseIf ($PSVersionTable.PSVersion.Major -eq 6) {
				Start-Process pwsh.exe
		}

		Exit
	}
}

RequireAdmin

#Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

$SourceDir = $PSScriptRoot
$ProfileDir = Split-Path -parent $profile

#-------------------- WindowsPowerShell --------------------------------------------------

If ($ProfileDir) { Remove-Item -Path $ProfileDir -Recurse -Force -ErrorAction SilentlyContinue }

New-Item -ItemType SymbolicLink -Path $ProfileDir -Target  $(Join-Path -Path $SourceDir -ChildPath "WindowsPowerShell") -Force


#----------------------- Home --------------------------------------------------

Get-ChildItem -Path $(Join-Path -Path $SourceDir -ChildPath "Home") | % {

  Remove-Item -Path $(Join-Path $Home $_.name) -Recurse -Force -ErrorAction SilentlyContinue

  New-Item -ItemType SymbolicLink -Path $(Join-Path $Home $_.name) -Target  $_.fullname

}

################################################################################
## Install Modules
################################################################################

Install-PackageProvider NuGet  -Force -AllowClobber
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

#----------------------- oh-my-posh  -------------------------------------------

Install-Module -Name PowerShellGet -Scope CurrentUser -Force -AllowClobber

#----------------------- PSReadLine  -------------------------------------------

Install-Module PSReadLine -AllowPrerelease -Force

#----------------------- Posh-Git ----------------------------------------------

Install-Module posh-git -Scope CurrentUser -Force -AllowClobber

#----------------------- oh-my-posh  -------------------------------------------

Install-Module oh-my-posh -Scope CurrentUser -Force -AllowClobber

#----------------------- oh-my-posh  -------------------------------------------

Install-Module -Name Get-ChildItemColor -Scope CurrentUser -AllowClobber

#----------------------- Chocolatey ---------------------------------------------

iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex

#Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))


cinst git.install -y --force

#----------------------- PowerLine prompt ---------------------------------------------

$SourceDir = $(Join-Path -Path $env:USERPROFILE -ChildPath "\Projects\PSDotFiles\")


if (Test-Path $SourceDir\WindowsPowerShell\Themes\powerline) {
  Remove-Item -Recurse -Force $SourceDir\WindowsPowerShell\Themes\powerline
}

git clone https://github.com/powerline/fonts.git $(Join-Path -Path $SourceDir -ChildPath "WindowsPowerShell\Themes\powerline")

. $(Join-Path -Path $SourceDir -ChildPath "WindowsPowerShell\Themes\powerline\install.ps1")


Install-Module Pansies -Scope CurrentUser -AllowClobber

Install-Module PowerLine -Scope CurrentUser -AllowClobber
Import-Module PowerLine

Set-Theme agnoster

################################################################################
## Install Solarized Theme
################################################################################

regedit /s .\Themes\Solarized\solarized-dark.reg
Update-Link "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk" dark
Update-Link "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" dark

# $SourceDir = $(Join-Path -Path $env:USERPROFILE -ChildPath "\Projects\PSDotFiles\")
git clone https://github.com/tpenguinltg/windows-solarized.git $(Join-Path -Path $SourceDir -ChildPath "WindowsPowerShell\Themes\windows-solarized")

################################################################################
## Windows Tweaks
################################################################################

Set-WinUserLanguageList -LanguageList en-US, ru -Force

################################################################################
## Windows Tweaks
################################################################################

RestartPowerShell
