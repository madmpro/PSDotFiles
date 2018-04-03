###############################################################################
### Progress Bar                                                              #
###############################################################################

# Disable the Progress Bar
$ProgressPreference = 'SilentlyContinue'
# Enable the Progress Bar
#$progressPreference = 'Continue'

###############################################################################
### User Environment Variables                                                #
### (Not System Variables!!)                                                  #
###############################################################################


# Make vim the default editor
Set-Environment "EDITOR" "atom"
Set-Environment "GIT_EDITOR" $Env:EDITOR
#Set-ItemProperty -path Registry::HKCR\batfile\shell\edit\command "(Default)" "%LOCALAPPDATA%\atom\bin\atom %1"

#Set-Environment "EDITOR" "nano"
#Set-Environment "GIT_EDITOR" $Env:EDITOR
#Set-Environment "GIT_SSH" "C:\Program Files\Git\usr\bin\ssh.exe"
#Set-Environment "GIT_EDITOR" "nano"
#Set-Environment "OneDrive" "E:\ProgramFiles\OneDrive"
#Set-Environment "Path" "C:\ProgramData\Oracle\Java\javapath;%INTEL_DEV_REDIST%redist\intel64\compiler;C:\Windows\system32;C:\Windows;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32;C:\HashiCorp\Vagrant\bin;C:\Program Files\Git\cmd;C:\Program Files\Oracle\VirtualBox;C:\Program Files (x86)\PuTTY;C:\Users\AlexF;C:\Users\AlexF\vv;C:\Program Files\Oracle\VirtualBox;C:\Program Files\Git\usr\bin;C:\Program Files\Git\cmd;C:\HashiCorp\Vagrant\bin;C:\Users\AlexF\vvvflip\;C:\MinGW\bin"

#[Environment]::SetEnvironmentVariable("TEMP", "%USERPROFILE%\AppData\Local\Temp", "User")
#[Environment]::SetEnvironmentVariable("TMP", "%USERPROFILE%\AppData\Local\Temp", "User")


###############################################################################
### System Machine Environment Variables                                      #
### It won't take effect within the same process,                             #
###  you'll have to make a new PowerShell process to see it.                  #
###############################################################################

#$value = [Environment]::GetEnvironmentVariable("TEMP", "Machine")
#[Environment]::SetEnvironmentVariable("TEMP", "%SystemRoot%\TEMP", "Machine")
#[Environment]::SetEnvironmentVariable("TMP", "%SystemRoot%\TEMP", "Machine")
#[Environment]::SetEnvironmentVariable("ComSpec", "%SystemRoot%\system32\cmd.exe", "Machine")
#[Environment]::SetEnvironmentVariable("OS", "Windows_NT", "Machine")
#[Environment]::SetEnvironmentVariable("PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.RB;.RBW", "Machine")
#[Environment]::SetEnvironmentVariable("windir", "%SystemRoot%", "Machine")
#[Environment]::SetEnvironmentVariable("ChocolateyInstall", "C:\ProgramData\chocolatey", "Machine")
#[Environment]::SetEnvironmentVariable("PSModulePath", "%ProgramFiles%\WindowsPowerShell\Modules;%SystemRoot%\system32\WindowsPowerShell\v1.0\Modules", "Machine")
