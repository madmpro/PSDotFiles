Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

RequireAdmin


###############################################################################
### Update Help for Modules                                                   #
###############################################################################

#Update-Help -Force -ErrorAction SilentlyContinue

###############################################################################
### Install Package Providers                                                 #
###############################################################################

Get-PackageProvider NuGet -Force

# Chocolatey Provider is not ready yet. Use normal Chocolatey
Get-PackageProvider Chocolatey -Force
Set-PackageSource -Name chocolatey -Trusted
Install-PackageProvider -Name ChocolateyGet

###############################################################################
### Chocolatey                                                                #
###############################################################################

### Install chocolatey and git at first boot.
cd $env:USERPROFILE

if ((which cinst) -eq $null) {
    iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
}

if (which cinst) {
    Refresh-Environment
    choco feature enable -n=allowGlobalConfirmation
}

# System and CLI
#------------------------------------------------------------------------------
#cinst curl #`curl` comes with GitHub
cinst nuget.commandline
#cinst webpi
cinst wget
cinst wput
cinst python2
cinst 7zip
cinst sysinternals
cinst windirstat
#cinst virtualbox


# Browsers
#------------------------------------------------------------------------------
cinst GoogleChrome
#cinst GoogleChrome.Canary
cinst tor-browser
#cinst Firefox
#cinst Opera

# Chat and social media
#------------------------------------------------------------------------------
#cinst skype
cinst whatsapp
cinst telegram

# Git
#------------------------------------------------------------------------------

if ((which git) -eq $null) {
    cinst git --params "/GitAndUnixToolsOnPath"
    Refresh-Environment
}

New-Item -ItemType Directory -Force -Path ~\.ssh
ssh-keyscan github.com | out-file -encoding ASCII ~\.ssh\known_hosts

# Dev Tools and Frameworks
#------------------------------------------------------------------------------

cinst gitextensions
cinst visualstudiocode
cinst visualstudio2017community
cinst sql-server-express
cinst sql-server-management-studio
#cinst mysql.workbench
cinst atom
cinst notepadplusplus
cinst github
cinst sourcetree
cinst hg
cinst javaruntime
cinst ilspy
#cinst Fiddler4
#cinst nodejs.install
#cinst ruby
#cinst vim
#cinst winmerge

# Network
#------------------------------------------------------------------------------
cinst filezilla
cinst putty
cinst wireshark

# Multimedia
#------------------------------------------------------------------------------
cinst vlc
cinst paint.net
# Open Broadcaster Studio
#cinst obs-studio

# Office
#------------------------------------------------------------------------------
cinst libreoffice
cinst adobereader

# Utilities
#------------------------------------------------------------------------------
cinst far
cinst bginfo
cinst powershell-core

# Other
#------------------------------------------------------------------------------
#cinst wincommandpaste # Copy/Paste is supported natively in Win10


### Completing PoshGit installation if installing GH4W
if (((choco list -lr | where {$_ -like "github*"}) -ne $null) -and ((which git) -eq $null)) {
    Write-Host ""
    Write-Host "You have installed GitHub but `git` was not found."
    Write-Host "In case GitHub is newly installed, execution has been"
    Write-Host "paused while you complete the installation."
    Write-Host ""
    Read-Host -Prompt "When (or if) installation has completed, press Enter to continue" | Out-Null
    Push-Location (Join-Path $env:LocalAppData "GitHub")
        Write-Host ""
        Write-Host "Relaunching GitHu to begin tooling installation."
        Write-Host "You will be prompted for your GitHub credentials, though feel free to Skip."
        Write-Host "A notification for Extracting Tools may display."
        Start-Process .\GitHub.appref-ms
        Read-Host -Prompt "Once GitHub displays the Repositories screen, press Enter to proceed." | Out-Null
        Write-Host ""
        Write-Host "Launching GitHub Shell to complete tooling installation."
        Start-Process .\GitHub.appref-ms -ArgumentList "--open-shell"
        Read-Host -Prompt "After launching, close the GitHub shell and press Enter to proceed" | Out-Null
        Refresh-Environment
        . (Join-Path (Split-Path -parent $PROFILE) "profile.ps1")
    Pop-Location
} else {
    Refresh-Environment
}

###############################################################################
### Web Platform Installer                                                    #
###############################################################################

#if (which webpicmd) {
#    webpicmd /Install /AcceptEula /Products:"StaticContent,DefaultDocument,DirectoryBrowse,RequestFiltering,HTTPErrors,HTTPLogging,ISAPIExtensions,ISAPIFilters,UrlRewrite2"
#    webpicmd /Install /AcceptEula /Products:"BasicAuthentication,WindowsAuthentication"
#    webpicmd /Install /AcceptEula /Products:"StaticContentCompression,DynamicContentCompression"
#    webpicmd /Install /AcceptEula /Products:"IISManagementConsole"
#    webpicmd /Install /AcceptEula /Products:"WebSockets"
#    webpicmd /Install /AcceptEula /Products:"NetFx3,NetFx4,NETFramework452,NetFx4Extended-ASPNET45,NETExtensibility,NetFxExtensibility45,ASPNET,ASPNET45"
#    webpicmd /Install /AcceptEula /Products:"Python279"
#}

###############################################################################
### Node Packages                                                             #
###############################################################################

#if (which npm) {
#    npm install -g azure-cli
#    npm install -g babel-cli
#    npm install -g bower
#    npm install -g coffee-script
#    npm install -g conventional-changelog
#    npm install -g grunt-cli
#    npm install -g gulp
#    npm install -g less
#    npm install -g lineman
#    npm install -g mocha
#    npm install -g node-inspector
#    npm install -g node-sass
#    npm install -g yo
#}


### Janus for vim
#if ((which vim) -and (which rake)) {
#    curl.exe -L https://bit.ly/janus-bootstrap | bash
#}


#----------------------- Atom --------------------------------------------------

cinst atom -y

$Packages = Get-Content $(Join-Path -Path $SourceDir -ChildPath "Home\.atom\package.list")
foreach ($Pack in $Packages) { apm install $Pack }

#----------------------- Windows Terminal --------------------------------------------------

cinst microsoft-windows-terminal -y

cinst vswhere -y

###############################################################################
### Visual Studio Plugins                                                     #
###############################################################################

if (which Install-VSExtension) {
    ### Visual Studio 2017
    # VsVim
    #Install-VSExtension https://visualstudiogallery.msdn.microsoft.com/59ca71b3-a4a3-46ca-8fe1-0e90e3f79329/file/6390/57/VsVim.vsix
		# GitHub Extension for Visual Studio
    # https://marketplace.visualstudio.com/items?itemName=GitHub.GitHubExtensionforVisualStudio
    Install-VSExtension "https://visualstudiogallery.msdn.microsoft.com/75be44fb-0794-4391-8865-c3279527e97d/file/159055/36/GitHub.VisualStudio.vsix" `
		# Snippet Designer
    # https://marketplace.visualstudio.com/items?itemName=vs-publisher-2795.SnippetDesigner
    Install-VSExtension "https://visualstudiogallery.msdn.microsoft.com/b08b0375-139e-41d7-af9b-faee50f68392/file/5131/16/SnippetDesigner.vsix" `

    # Web Essentials 2017
    # https://marketplace.visualstudio.com/items?itemName=MadsKristensen.WebExtensionPack2017
    Install-VSExtension "https://visualstudiogallery.msdn.microsoft.com/a5a27916-2099-4c5b-a3ff-6a46e4b01298/file/236262/11/Web%20Essentials%202017%20v1.5.8.vsix" `

    # Productivity Power Tools 2017
    # https://marketplace.visualstudio.com/items?itemName=VisualStudioProductTeam.ProductivityPowerPack2017
    Install-VSExtension "https://visualstudiogallery.msdn.microsoft.com/11693073-e58a-45b3-8818-b2cf5d925af7/file/244442/4/ProductivityPowerTools2017.vsix" `

    # Power Commands 2017
    # https://marketplace.visualstudio.com/items?itemName=VisualStudioProductTeam.PowerCommandsforVisualStudio
    Install-VSExtension "https://visualstudiogallery.msdn.microsoft.com/80f73460-89cd-4d93-bccb-f70530943f82/file/242896/4/PowerCommands.vsix" `

    # Power Shell Tools 2017
    # https://marketplace.visualstudio.com/items?itemName=AdamRDriscoll.PowerShellToolsforVisualStudio2017-18561
    Install-VSExtension "https://visualstudiogallery.msdn.microsoft.com/8389e80d-9e40-4fc1-907c-a07f7842edf2/file/257196/1/PowerShellTools.15.0.vsix" `

		Install-VSExtension ProductivityPowerPack2017
}


###############################################################################
### Windows Subsystem for Linux
###############################################################################

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux


# Wait for key press
Function WaitForKey {
	Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

Write-Output "`nInstall complete."

WaitForKey
