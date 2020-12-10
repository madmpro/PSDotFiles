# https://github.com/neilpa/cmd-colors-solarized

#------------------------------------------------------------------------------
# Functions are imported only if Solarized theme is installed
#------------------------------------------------------------------------------

$ProfileDir = Split-Path -parent $Profile
$ThemeDir = $(Join-Path -Path $ProfileDir -ChildPath "Themes\Solarized")

if ( -not ( $ThemeDir ) ) { return; }

Function Update-Link
{
    param(
      [Parameter(Mandatory=$true)]
      [ValidateScript({Test-Path $_})]
      [string]$Path,

      [Parameter()]
      [ValidateSet('Light','Dark')]
      [string]$Theme = 'Dark'
  )

  $lnk = & ("$ThemeDir\Get-Link.ps1") $Path

  # Set Common Solarized Colors
  $lnk.ConsoleColors[0]="#002b36"
  $lnk.ConsoleColors[8]="#073642"
  $lnk.ConsoleColors[2]="#586e75"
  $lnk.ConsoleColors[6]="#657b83"
  $lnk.ConsoleColors[1]="#839496"
  $lnk.ConsoleColors[3]="#93a1a1"
  $lnk.ConsoleColors[7]="#eee8d5"
  $lnk.ConsoleColors[15]="#fdf6e3"
  $lnk.ConsoleColors[14]="#b58900"
  $lnk.ConsoleColors[4]="#cb4b16"
  $lnk.ConsoleColors[12]="#dc322f"
  $lnk.ConsoleColors[13]="#d33682"
  $lnk.ConsoleColors[5]="#6c71c4"
  $lnk.ConsoleColors[9]="#268bd2"
  $lnk.ConsoleColors[11]="#2aa198"
  $lnk.ConsoleColors[10]="#859900"

  # Set Light/Dark Theme-Specific Colors
  if ($Theme -eq "Dark") {
      $lnk.PopUpBackgroundColor=0xf
      $lnk.PopUpTextColor=0x6
      $lnk.ScreenBackgroundColor=0x0
      $lnk.ScreenTextColor=0x1
  } else {
      $lnk.PopUpBackgroundColor=0x0
      $lnk.PopUpTextColor=0x1
      $lnk.ScreenBackgroundColor=0xf
      $lnk.ScreenTextColor=0x6
  }

  $lnk.Save()

  Write-Host "Updated $Path to Solarized - $Theme"

}

Function Update-StartMenu
{

    param(
      [Parameter()]
      [ValidateSet('Light','Dark')]
      [string]$theme = 'Dark'
  )

  Write-Host "Updating PowerShell shortcuts on the Start Menu"

  $appdataFolder = $env:APPDATA
  $startFolder = resolve-path "$appdataFolder\Microsoft\Windows\Start Menu"
  $powerShellFolder = resolve-path "$startFolder\Programs\Windows PowerShell"

  Write-Host "Looking in $powerShellFolder"

  Write-Host
  $powerShellx86 = "$powerShellFolder\Windows PowerShell (x86).lnk"
  if (test-path $powerShellx86) {
      Write-Host "Updating $powerShellx86"
      .\Update-Link.ps1 $powerShellx86 $theme
  } else {
      Write-Warning "Didn't find $powerShellx86"
  }

  Write-Host
  $powerShell64 = "$powerShellFolder\Windows PowerShell.lnk"
  if (test-path $powerShell64) {
      Write-Host "Updating $powerShell64"
      .\Update-Link.ps1 $powerShell64 $theme
  } else {
      Write-Warning "Didn't find $powerShell64"
  }
}

Function Set-SolarizedDarkColorDefaults
{
  # Host Foreground
  $Host.PrivateData.ErrorForegroundColor = 'Red'
  $Host.PrivateData.WarningForegroundColor = 'Yellow'
  $Host.PrivateData.DebugForegroundColor = 'Green'
  $Host.PrivateData.VerboseForegroundColor = 'Blue'
  $Host.PrivateData.ProgressForegroundColor = 'Gray'

  # Host Background
  $Host.PrivateData.ErrorBackgroundColor = 'DarkGray'
  $Host.PrivateData.WarningBackgroundColor = 'DarkGray'
  $Host.PrivateData.DebugBackgroundColor = 'DarkGray'
  $Host.PrivateData.VerboseBackgroundColor = 'DarkGray'
  $Host.PrivateData.ProgressBackgroundColor = 'Cyan'

  # Check for PSReadline
  if (Get-Module -ListAvailable -Name "PSReadline") {
      $options = Get-PSReadlineOption

  	if ([System.Version](Get-Module PSReadline).Version -lt [System.Version]"2.0.0") {
  		# Foreground
  		$options.CommandForegroundColor = 'Yellow'
  		$options.ContinuationPromptForegroundColor = 'DarkBlue'
  		$options.DefaultTokenForegroundColor = 'DarkBlue'
  		$options.EmphasisForegroundColor = 'Cyan'
  		$options.ErrorForegroundColor = 'Red'
  		$options.KeywordForegroundColor = 'Green'
  		$options.MemberForegroundColor = 'DarkCyan'
  		$options.NumberForegroundColor = 'DarkCyan'
  		$options.OperatorForegroundColor = 'DarkGreen'
  		$options.ParameterForegroundColor = 'DarkGreen'
  		$options.StringForegroundColor = 'Blue'
  		$options.TypeForegroundColor = 'DarkYellow'
  		$options.VariableForegroundColor = 'Green'

  		# Background
  		$options.CommandBackgroundColor = 'Black'
  		$options.ContinuationPromptBackgroundColor = 'Black'
  		$options.DefaultTokenBackgroundColor = 'Black'
  		$options.EmphasisBackgroundColor = 'Black'
  		$options.ErrorBackgroundColor = 'Black'
  		$options.KeywordBackgroundColor = 'Black'
  		$options.MemberBackgroundColor = 'Black'
  		$options.NumberBackgroundColor = 'Black'
  		$options.OperatorBackgroundColor = 'Black'
  		$options.ParameterBackgroundColor = 'Black'
  		$options.StringBackgroundColor = 'Black'
  		$options.TypeBackgroundColor = 'Black'
  		$options.VariableBackgroundColor = 'Black'
  	} else {
  	    # New version of PSReadline renames Foreground colors and eliminates Background
  		$options.CommandColor = 'Yellow'
  		$options.ContinuationPromptColor = 'DarkBlue'
  		$options.DefaultTokenColor = 'DarkBlue'
  		$options.EmphasisColor = 'Cyan'
  		$options.ErrorColor = 'Red'
  		$options.KeywordColor = 'Green'
  		$options.MemberColor = 'DarkCyan'
  		$options.NumberColor = 'DarkCyan'
  		$options.OperatorColor = 'DarkGreen'
  		$options.ParameterColor = 'DarkGreen'
  		$options.StringColor = 'Blue'
  		$options.TypeColor = 'DarkYellow'
  		$options.VariableColor = 'Green'
  	}
  }

}
