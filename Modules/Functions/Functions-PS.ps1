###############################################################################
### PowerShell Functions                                                      #
###############################################################################

Function RemoteLogin ([string]$RHost){
  # For using New-PSRemote command to connect to other "untrusted" boxes. You don't need this unless you know you do.
  $PSSessionOption = New-PSSessionOption -SkipRevocationCheck -SkipCACheck -SkipCNCheck
  $Cred=Get-Credential

  Enter-PSSession -ComputerName $RHost -Credential $Cred -Authentication Basic
  #Enter-PSSession -ComputerName $RHost -Credential $Cred -Authentication Credssp
}

function Run-AsAdmin {

  # Get the ID and security principal of the current user account
  $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
  $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

  # Get the security principal for the Administrator role
  $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

  # Check to see if we are currently running "as Administrator"
  if ($myWindowsPrincipal.IsInRole($adminRole))
  {
    # We are running "as Administrator" - so change the title and background color to indicate this
    # $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
    $Host.UI.RawUI.BackgroundColor = "Black"
    clear-host
  }
  else
  {
    # We are not running "as Administrator" - so relaunch as administrator

    # Create a new process object that starts PowerShell
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";

    # Indicate that the process should be elevated
    $newProcess.Verb = "runas";

    # Start the new process
    [System.Diagnostics.Process]::Start($newProcess);

    # Exit from the current, unelevated, process
    exit
  }

}

function Out-Clipboard {
    [cmdletbinding()]
    param (
        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]$InputObject,
        [switch] $File
    )
    begin {
        $ps = [PowerShell]::Create()
        $rs = [RunSpaceFactory]::CreateRunspace()
        $rs.ApartmentState = "STA"
        $rs.ThreadOptions = "ReuseThread"
        $rs.Open()
        $data = @()
    }
    process {$data += $InputObject}
    end {
        $rs.SessionStateProxy.SetVariable("do_file_copy", $File)
        $rs.SessionStateProxy.SetVariable("data", $data)
        $ps.Runspace = $rs
        $ps.AddScript({
            Add-Type -AssemblyName 'System.Windows.Forms'
            if ($do_file_copy) {
                $file_list = New-Object -TypeName System.Collections.Specialized.StringCollection
                $data | % {
                    if ($_ -is [System.IO.FileInfo]) {[void]$file_list.Add($_.FullName)}
                    elseif ([IO.File]::Exists($_))    {[void]$file_list.Add($_)}
                }
                [System.Windows.Forms.Clipboard]::SetFileDropList($file_list)
            } else {
                $host_out = (($data | Out-String -Width 1000) -split "`n" | % {$_.TrimEnd()}) -join "`n"
                [System.Windows.Forms.Clipboard]::SetText($host_out)
            }
        }).Invoke()
    }
}
