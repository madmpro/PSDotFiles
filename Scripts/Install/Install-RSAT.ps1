<#
.SYNOPSIS
  Downloads RSAT and installs for Windows 10 v1709 (Fall Creators Update) or Installs RSAT Powershell Module on Server OS'
.DESCRIPTION
  In order to install Remote Server Administration Tools, this script will download from Microsoft's website, check the OS to see if it's
  running on a Server OS or Windows 10, and if it's running Windows 10, it will try and download the latest version of RSAT.
  Original script from https://blogs.technet.microsoft.com/drew/2016/12/23/installing-remote-server-admin-tools-rsat-via-powershell/
.NOTES
  Version:        1.0
  Author:         Jonathan Moss
  Creation Date:  1/2/18
  Purpose/Change: Initial script upload
  Requires Run As Administrator
.EXAMPLE
  .\Install-RSAT.ps1
#>

$web = Invoke-WebRequest https://www.microsoft.com/en-us/download/confirmation.aspx?id=45520 -UseBasicParsing

$MachineOS = (Get-WmiObject Win32_OperatingSystem).Name

$Windows10version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseID).ReleaseID

#Check for Windows Server 2012 R2
IF ($MachineOS -like "*Microsoft Windows Server*") {

    Add-WindowsFeature RSAT-AD-PowerShell
    Break
}

IF ($Windows10version -eq "1709" -and $ENV:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    Write-host "A 64-bit install is detected, proceeding!" -foregroundcolor yellow
    $Link = ($web.Links.href | Where-Object {$PSitem -like "*RSAT*" -and $PSitem -like "*x64*" -and $PSitem -notlike "*2016*"} | Select-Object -First 1)
}
ELSE {
    Write-host "Not running 64-bit or an incorrect Windows 10 version. The version of Windows is $Windows10version" -forgroundcolor red
    Break
}

$DLPath = ($ENV:TEMP) + ($link.split("/")[8])

## Changed to temp folder
$Temp = ($ENV:TEMP)

Write-Host "Downloading RSAT MSU file" -foregroundcolor yellow
Start-BitsTransfer -Source $Link -Destination $DLPath

$Authenticatefile = Get-AuthenticodeSignature $DLPath

if ($Authenticatefile.status -ne "valid") {write-host "Can't confirm download, exiting"; break}

## Section to install DNS module for RSAT  on Windows 10 v1709 Creators Update

Write-host "Creating temporary folder to configure DNS for Windows 10 v1709" -foregroundcolor yellow

$1ex = New-Item $Temp\ex1 -ItemType Directory

Write-host "Expanding $DLPath" -foregroundcolor yellow

expand.exe -f:* $DLPath $1ex

$cabfile = Get-ChildItem -Path $1ex -Filter "WindowsTH-KB2693643-x64.cab"
## XML required to install DNS
$xmlfile = Get-ChildItem -Path "$PSScriptRoot\Unattend_x64.xml"

#expand.exe -f:* $cabfile.FullName $1ex

Dism.exe /online /apply-unattend="$xmlfile"
Dism.exe /online /Add-Package /PackagePath:"$cabfile"
