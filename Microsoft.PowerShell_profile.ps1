###############################################################################
### Profile for the Microsoft.Powershell Shell, only.                         #
### All Users, All Hosts (Not Visual Studio or other PoSh instances)          #
###############################################################################

Push-Location (Split-Path -parent $profile)
"Components-Shell" | Where-Object {Test-Path "$_.ps1"} | ForEach-Object -process {Invoke-Expression ". .\$_.ps1"}
Pop-Location

Function prompt {
    $lastCommandSucceed = $?
    $currentTime = $(Get-Date -format "HH:mm:ss")

    $myIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($myIdentity)

    $isAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[$($currentTime)] " -ForegroundColor Gray -NoNewline
    Write-Host "$($pwd.Path.Replace($env:USERPROFILE, '~')) " -ForegroundColor Green -NoNewline
    If ($lastCommandSucceed) {
        Write-Host "$(If ($isAdmin) { "#" } Else { "»" } )" -ForegroundColor Cyan -NoNewline
    }
    Else {
        Write-Host "🗴" -ForegroundColor Red -NoNewline
    }

    $host.UI.RawUI.WindowTitle = "$($currentTime) - $(If ($isAdmin) { "Admin: " })$($pwd.path)"
    " "
}
