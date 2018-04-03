###############################################################################
# Win10 / WinServer2016 Initial Setup Script
# Author: Disassembler <disassembler@dasm.cz>
# Version: v2.13, 2018-03-18
# Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script
###############################################################################

$ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

try {
    . ("$ScriptDirectory\Components\Console.ps1")
}
catch {
    Write-Host "Error while loading PowerShell Console Scripts..."
}

Remove-Variable ScriptDirectory

# Default preset
$tweaks = @(
	### Require administrator privileges ###
	"RequireAdmin",
	#"SetComputerName",
	### Privacy Tweaks ###
	"ConfigurePrivacySettings",
	"DisableTelemetry",             # "EnableTelemetry",
	"DisableWiFiSense",             # "EnableWiFiSense",
	"DisableSmartScreen",           # "EnableSmartScreen",
	"DisableWebSearch",             # "EnableWebSearch",
	"DisableAppSuggestions",        # "EnableAppSuggestions",
	"DisableBackgroundApps",        # "EnableBackgroundApps",
	"DisableLockScreenSpotlight",   # "EnableLockScreenSpotlight",
	"DisableLocationTracking",      # "EnableLocationTracking",
	"DisableMapUpdates",            # "EnableMapUpdates",
	"DisableFeedback",              # "EnableFeedback",
	"DisableAdvertisingID",         # "EnableAdvertisingID",
	"DisableCortana",               # "EnableCortana",
	"DisableErrorReporting",        # "EnableErrorReporting",
	"SetP2PUpdateLocal",            # "SetP2PUpdateInternet",
	"DisableAutoLogger",            # "EnableAutoLogger",
	"DisableDiagTrack",             # "EnableDiagTrack",
	"DisableWAPPush",               # "EnableWAPPush",
	"DisableSyncSettings",
	### Security Tweaks ###
	# "SetUACLow",                  # "SetUACHigh",
	# "EnableSharingMappedDrives",  # "DisableSharingMappedDrives",
	"DisableAdminShares",           # "EnableAdminShares",
	# "DisableSMB1",                # "EnableSMB1",
	"SetCurrentNetworkPrivate",     # "SetCurrentNetworkPublic",
	# "SetUnknownNetworksPrivate",  # "SetUnknownNetworksPublic",
	# "DisableNetDevicesAutoInst",  # "EnableNetDevicesAutoInst",
	# "EnableCtrldFolderAccess",    # "DisableCtrldFolderAccess",
	# "DisableFirewall",            # "EnableFirewall",
	# "DisableDefender",            # "EnableDefender",
	# "DisableDefenderCloud",       # "EnableDefenderCloud",
	"DisableDefenderReporting",
	"EnableF8BootMenu",             # "DisableF8BootMenu",
	"DisableStartupSounds",
	"SetDEPOptOut",                 # "SetDEPOptIn",
	"DisableScriptHost",            # "EnableScriptHost",
	# "EnableMeltdownCompatFlag"    # "DisableMeltdownCompatFlag",

	### Service Tweaks ###
	# "DisableUpdateMSRT",          # "EnableUpdateMSRT",
	# "DisableUpdateDriver",        # "EnableUpdateDriver",
	"DisableUpdateRestart",         # "EnableUpdateRestart",
	"DisableHomeGroups",            # "EnableHomeGroups",
	"DisableSharedExperiences",     # "EnableSharedExperiences",
	"DisableRemoteAssistance",      # "EnableRemoteAssistance",
	"EnableRemoteDesktop",          # "DisableRemoteDesktop",
	"DisableAutoplay",              # "EnableAutoplay",
	"DisableAutorun",               # "EnableAutorun",
	# "EnableStorageSense",         # "DisableStorageSense",
	# "DisableDefragmentation",     # "EnableDefragmentation",
	# "DisableSuperfetch",          # "EnableSuperfetch",
	# "DisableIndexing",            # "EnableIndexing",
	# "SetBIOSTimeUTC",             # "SetBIOSTimeLocal",
	# "EnableHibernationState",     # "DisableHibernationState",
	# "DisableSleepButton",         # "EnableSleepButton",
	# "DisableSleepTimeout",        # "EnableSleepTimeout",
	# "DisableFastStartup",         # "EnableFastStartup",

	"EnableAutomaticUpdates",				# "DisableAutomaticUpdates",

	### UI Tweaks ###
	"SetSysTray",
	"SetColorPrevalence",
	"HideStoreAppsOnTaskbar",
	"DisableActionCenter",          # "EnableActionCenter",
	"DisableLockScreen",            # "EnableLockScreen",
	# "DisableLockScreenRS1",       # "EnableLockScreenRS1",
	"ShowNetworkOnLockScreen",			#"HideNetworkFromLockScreen",
	"HideShutdownFromLockScreen",   # "ShowShutdownOnLockScreen",
  "SetLogonKeyboardLayout",
	"DisableStickyKeys",            # "EnableStickyKeys",
	"ShowTaskManagerDetails"        # "HideTaskManagerDetails",
	"ShowFileOperationsDetails",    # "HideFileOperationsDetails",
	# "EnableFileDeleteConfirm",    # "DisableFileDeleteConfirm",
	"HideTaskbarSearchBox",         # "ShowTaskbarSearchBox",
	"HideTaskView",                 # "ShowTaskView",
	"ShowSmallTaskbarIcons",        # "ShowLargeTaskbarIcons",
	"ShowTaskbarTitles",            # "HideTaskbarTitles",
	"HideTaskbarPeopleIcon",        # "ShowTaskbarPeopleIcon",
	"ShowTrayIcons",                # "HideTrayIcons",
	"DisableSearchAppInStore",      # "EnableSearchAppInStore",
	"DisableNewAppPrompt",          # "EnableNewAppPrompt",
	# "SetControlPanelViewIcons",   # "SetControlPanelViewCategories",
	"SetVisualFXPerformance",       # "SetVisualFXAppearance",
	# "AddENKeyboard",              # "RemoveENKeyboard",
	# "EnableNumlock",              # "DisableNumlock",

	### Explorer UI Tweaks ###
	"ShowKnownExtensions",          # "HideKnownExtensions",
	"ShowHiddenFiles",              # "HideHiddenFiles",
	"ShowPathInTitleBar",						# "HidePathInTitleBar",
	"HideSyncNotifications"         # "ShowSyncNotifications",
	"HideRecentShortcuts",          # "ShowRecentShortcuts",
	"SetExplorerThisPC",            # "SetExplorerQuickAccess",
	"ShowThisPCOnDesktop",          # "HideThisPCFromDesktop",
	# "ShowUserFolderOnDesktop",    # "HideUserFolderFromDesktop",
	"HideDesktopFromThisPC",        # "ShowDesktopInThisPC",
	# "HideDesktopFromExplorer",    # "ShowDesktopInExplorer",
	"HideDocumentsFromThisPC",      # "ShowDocumentsInThisPC",
	# "HideDocumentsFromExplorer",  # "ShowDocumentsInExplorer",
	"HideDownloadsFromThisPC",      # "ShowDownloadsInThisPC",
	# "HideDownloadsFromExplorer",  # "ShowDownloadsInExplorer",
	"HideMusicFromThisPC",          # "ShowMusicInThisPC",
	# "HideMusicFromExplorer",      # "ShowMusicInExplorer",
	"HidePicturesFromThisPC",       # "ShowPicturesInThisPC",
	# "HidePicturesFromExplorer",   # "ShowPicturesInExplorer",
	"HideVideosFromThisPC",         # "ShowVideosInThisPC",
	# "HideVideosFromExplorer",     # "ShowVideosInExplorer",
	"Hide3DObjectsFromThisPC",      # "Show3DObjectsInThisPC",
	# "Hide3DObjectsFromExplorer",  # "Show3DObjectsInExplorer",
	# "DisableThumbnails",          # "EnableThumbnails",
	"DisableThumbsDB",              # "EnableThumbsDB",
	"DisableConfirmDeleteRecycleBin",
	"EnableLoginCustomBackground",
	### Application Tweaks ###
	"DisableOneDrive",              # "EnableOneDrive",
	"UninstallOneDrive",            # "InstallOneDrive",
	"UninstallMsftBloat",           # "InstallMsftBloat",
	"UninstallThirdPartyBloat",     # "InstallThirdPartyBloat",
	"RemoveProvisionedBloat",
	# "UninstallWindowsStore",      # "InstallWindowsStore",
	"DisableXboxFeatures",          # "EnableXboxFeatures",
	"DisableAdobeFlash",            # "EnableAdobeFlash",
	# "UninstallMediaPlayer",       # "InstallMediaPlayer",
	# "UninstallWorkFolders",       # "InstallWorkFolders",
	# "InstallLinuxSubsystem",      # "UninstallLinuxSubsystem",
	# "InstallHyperV",              # "UninstallHyperV",
  "SetPowershellScriptAction",
	"SetPhotoViewerAssociation",    # "UnsetPhotoViewerAssociation",
	"AddPhotoViewerOpenWith",       # "RemovePhotoViewerOpenWith",
	# "UninstallPDFPrinter",        # "InstallPDFPrinter",
	#"UninstallXPSPrinter",          # "InstallXPSPrinter",
	"RemoveFaxPrinter",             # "AddFaxPrinter",
	"ConfigInternetExplorer",

	"ConfigAccessibility",
	### Server Specific Tweaks ###
	# "HideServerManagerOnLogin",   # "ShowServerManagerOnLogin",
	# "DisableShutdownTracker",     # "EnableShutdownTracker",
	# "DisablePasswordPolicy",      # "EnablePasswordPolicy",
	# "DisableCtrlAltDelLogin",     # "EnableCtrlAltDelLogin",
  # "DisableSMLogonStart",
	# "DisableIEEnhancedSecurity",  # "EnableIEEnhancedSecurity",

	#"DisableHibernation",						#	"EnableHibernation",
	### Unpinning ###
	# "UnpinStartMenuTiles",
	# "UnpinTaskbarIcons",
	"ConfigurePowershellConsole",
	"SetDiskCleanup",
  "SetUserTweaks",

	### Auxiliary Functions ###
	"WaitForKey",
	"Restart"
)

###############################################################################
### Identity                                                                  #
###############################################################################

# Set Computer Name
Function SetComputerName {
	Write-Output "Configuring System..."

	(Get-WmiObject Win32_ComputerSystem).Rename("MADMW001") | Out-Null

	## Set DisplayName for my account. Use only if you are not using a Microsoft Account
	#$myIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
	#$user = Get-WmiObject Win32_UserAccount | Where {$_.Caption -eq $myIdentity.Name}
	#$user.FullName = "Jay Harris
	#$user.Put() | Out-Null
	#Remove-Variable user
	#Remove-Variable myIdentity

	# Enable Developer Mode
	#SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" 1
	# Bash on Windows
	#Enable-WindowsOptionalFeature -Online -All -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null

}

###############################################################################
### Privacy Tweaks                                                            #
###############################################################################


Function ConfigurePrivacySettings {
  Write-Output "Configuring Privacy..."

  # General: Opt-out from websites from accessing language list: Opt-in: 0, Opt-out 1
  SetRegistryKey "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" "DWord" 1

  # General: Disable SmartGlass: Enable: 1, Disable: 0
  SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" "UserAuthPolicy" "DWord" 0

  # General: Disable SmartGlass over BlueTooth: Enable: 1, Disable: 0
  SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" "BluetoothPolicy" "DWord" 0

  # Camera: Don't let apps use camera: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" "Value" "String" "Deny"

  # Microphone: Don't let apps use microphone: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" "Value" "String" "Deny"

  # Notifications: Don't let apps access notifications: Allow, Deny
  # Build 1511
  # SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" "Value" "String" "Deny"
  # Build 1607, 1709

  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" "Value" "String" "Deny"

  # Account Info: Don't let apps access name, picture, and other account info: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" "Value" "String" "Deny"

  # Contacts: Don't let apps access contacts: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" "Value" "String" "Deny"

  # Calendar: Don't let apps access calendar: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" "Value" "String" "Deny"

  # Call History: Don't let apps access call history: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" "Value" "String" "Deny"

  # Email: Don't let apps read and send email: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" "Value" "String" "Deny"

  # Messaging: Don't let apps read or send messages (text or MMS): Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" "Value" "String" "Deny"

  # Radios: Don't let apps control radios (like Bluetooth): Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" "Value" "String" "Deny"

  # Other Devices: Don't let apps share and sync with non-explicitly-paired wireless devices over uPnP: Allow, Deny
  SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "String" "Deny"

}


# Disable Telemetry
# Note: This tweak may cause Enterprise edition to stop receiving Windows updates.
# Windows Update control panel will then show message "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going".
# In such case, enable telemetry, run Windows update and then disable telemetry again. See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57
Function DisableTelemetry {
	Write-Output "Disabling Telemetry..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "DWord" 0
	# Disable key logging & transmission to Microsoft: Enable: 1, Disable: 0
	# Disabled when Telemetry is set to Basic
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" "DWord" 0

	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

}

# Enable Telemetry
Function EnableTelemetry {
	Write-Output "Enabling Telemetry..."
	# Feedback: Telemetry: Send Diagnostic and usage data: Basic: 1, Enhanced: 2, Full: 3
  SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "DWord" 1

	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

# Disable automatically syncing settings with other Windows 10 devices
Function DisableSyncSettings {

	Write-Output "Disabling syncing settings..."

	# Theme
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" "Enabled" "DWord" 0
	# Internet Explorer
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" "Enabled" "DWord" 0
	# Passwords
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" "Enabled" "DWord" 0
	# Language
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" "Enabled" "DWord" 0
	# Accessibility / Ease of Access
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" "Enabled" "DWord" 0
	# Other Windows Settings
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" "Enabled" "DWord" 0

}

# Disable Wi-Fi Sense
Function DisableWiFiSense {
	Write-Output "Disabling Wi-Fi Sense..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "Value" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "WiFISenseAllowed" "DWord" 0
}

# Enable Wi-Fi Sense
Function EnableWiFiSense {
	Write-Output "Enabling Wi-Fi Sense..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "Value" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" "DWord" 1
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM"
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "WiFISenseAllowed"
}

# Disable SmartScreen Filter
Function DisableSmartScreen {
	Write-Output "Disabling SmartScreen Filter..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "String" "Off"
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" "DWord" 0
	$edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName

	SetRegistryKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" "EnabledV9" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" "PreventOverride" "DWord" 0
}

# Enable SmartScreen Filter
Function EnableSmartScreen {
	Write-Output "Enabling SmartScreen Filter..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "String" "RequireAdmin"
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation"
	$edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
	DeleteRegistryKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" "EnabledV9"
	DeleteRegistryKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" "PreventOverride"
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
	Write-Output "Disabling Bing Search in Start Menu..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" "DWord" 1
}

# Enable Web Search in Start Menu
Function EnableWebSearch {
	Write-Output "Enabling Bing Search in Start Menu..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled"
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch"
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
	Write-Output "Disabling Application suggestions..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "DWord" 1
}

# Enable Application suggestions and automatic installation
Function EnableAppSuggestions {
	Write-Output "Enabling Application suggestions..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "DWord" 1
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled"
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"
}

# Disable Background application access - ie. if apps can download or update when they aren't used - Cortana is excluded as its inclusion breaks start menu search
Function DisableBackgroundApps {
	Write-Output "Disabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		SetRegistryKey $_.PsPath "Disabled" "DWord" 1
		SetRegistryKey $_.PsPath "DisabledByUser" "DWord" 1
	}
}

# Enable Background application access
Function EnableBackgroundApps {
	Write-Output "Enabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach {
		DeleteRegistryKey $_.PsPath "Disabled"
		DeleteRegistryKey $_.PsPath "DisabledByUser"
	}
}

# Disable Lock screen Spotlight - New backgrounds, tips, advertisements etc.
Function DisableLockScreenSpotlight {
	Write-Output "Disabling Lock screen spotlight..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenEnabled" "DWord" 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenOverlayEnabled" "DWord" 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" "DWord" 0
}

# Enable Lock screen Spotlight
Function EnableLockScreenSpotlight {
	Write-Output "Disabling Lock screen spotlight..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenEnabled" "DWord" 1
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenOverlayEnabled" "DWord" 1
	DeleteRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled"
}

# Disable Location Tracking
Function DisableLocationTracking {
	Write-Output "Disabling Location Tracking..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "DWord" 0
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" "DWord" 0
}

# Enable Location Tracking
Function EnableLocationTracking {
	Write-Output "Enabling Location Tracking..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "DWord" 1
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" "DWord" 1
}

# Disable automatic Maps updates
Function DisableMapUpdates {
	Write-Output "Disabling automatic Maps updates..."
	SetRegistryKey "HKLM:\SYSTEM\Maps" "AutoUpdateEnabled" "DWord" 0
}

# Enable automatic Maps updates
Function EnableMapUpdates {
	Write-Output "Enable automatic Maps updates..."
	DeleteRegistryKey "HKLM:\SYSTEM\Maps" "AutoUpdateEnabled"
}

# Disable Feedback
Function DisableFeedback {
	Write-Output "Disabling Feedback..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" "DWord" 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" | Out-Null
}

# Enable Feedback
Function EnableFeedback {
	Write-Output "Enabling Feedback..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod"
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" | Out-Null
}

# Disable Advertising ID
Function DisableAdvertisingID {
	Write-Output "Disabling Advertising ID..."

	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" "DWord" 0
}

# Enable Advertising ID
Function EnableAdvertisingID {
	Write-Output "Enabling Advertising ID..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled"
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" "DWord" 2
}

# Disable Cortana
Function DisableCortana {
	Write-Output "Disabling Cortana..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" "DWord" 0
}

# Enable Cortana
Function EnableCortana {
	Write-Output "Enabling Cortana..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy"
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" "DWord" 0
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts"
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana"
}

# Disable Error reporting
Function DisableErrorReporting {
	Write-Output "Disabling Error reporting..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" "DWord" 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Enable Error reporting
Function EnableErrorReporting {
	Write-Output "Enabling Error reporting..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled"
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Remove AutoLogger file and restrict directory
Function DisableAutoLogger {
	Write-Output "Removing AutoLogger file and restricting directory..."
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item -Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl" -ErrorAction SilentlyContinue
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}

# Unrestrict AutoLogger directory
Function EnableAutoLogger {
	Write-Output "Unrestricting AutoLogger directory..."
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
}

# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
	Write-Output "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}

# Enable and start Diagnostics Tracking Service
Function EnableDiagTrack {
	Write-Output "Enabling and starting Diagnostics Tracking Service..."
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack" -WarningAction SilentlyContinue
}

# Stop and disable WAP Push Service
Function DisableWAPPush {
	Write-Output "Stopping and disabling WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}

# Enable and start WAP Push Service
Function EnableWAPPush {
	Write-Output "Enabling and starting WAP Push Service..."
	Set-Service "dmwappushservice" -StartupType Automatic
	Start-Service "dmwappushservice" -WarningAction SilentlyContinue
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" "DelayedAutoStart" "DWord" 1
}

###############################################################################
### Security Tweaks                                                           #
###############################################################################

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Output "Lowering UAC level..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "DWord" 0
}

# Raise UAC level
Function SetUACHigh {
	Write-Output "Raising UAC level..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "DWord" 5
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "DWord" 1
}

# Set Data Execution Prevention (DEP) policy to OptOut
Function SetDEPOptOut {
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptOut..."
	bcdedit /set `{current`} nx OptOut | Out-Null
}

# Set Data Execution Prevention (DEP) policy to OptIn
Function SetDEPOptIn {
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
	bcdedit /set `{current`} nx OptIn | Out-Null
}

# Disable Windows Script Host (execution of *.vbs scripts and alike)
Function DisableScriptHost {
	Write-Output "Disabling Windows Script Host..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled" "DWord" 0
}

# Enable Windows Script Host
Function EnableScriptHost {
	Write-Output "Enabling Windows Script Host..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled" "DWord" 1
}

# Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January 2018 and all subsequent Windows updates
# This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
# Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
# See https://support.microsoft.com/en-us/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software for details.
Function EnableMeltdownCompatFlag {
	Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" "cadca5fe-87d3-4b96-b7fb-a231484277cc" "DWord" 0
}

# Disable Meltdown (CVE-2017-5754) compatibility flag
Function DisableMeltdownCompatFlag {
	Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" "cadca5fe-87d3-4b96-b7fb-a231484277cc"
}

# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
	Write-Output "Enabling sharing mapped drives between users..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLinkedConnections" "DWord" 1
}

# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
	Write-Output "Disabling sharing mapped drives between users..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLinkedConnections"
}

# Disable implicit administrative shares
Function DisableAdminShares {
	Write-Output "Disabling implicit administrative shares..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks" "DWord" 0
}

# Enable implicit administrative shares
Function EnableAdminShares {
	Write-Output "Enabling implicit administrative shares..."
	DeleteRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks"
}

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
	Write-Output "Enabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
	Write-Output "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private
}

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public
}

# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
	Write-Output "Setting unknown networks profile to private..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" "Category" "DWord" 1
}

# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
	Write-Output "Setting unknown networks profile to public..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" "Category"
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
	Write-Output "Disabling automatic installation of network devices..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" "AutoSetup" "DWord" 0
}

# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst {
	Write-Output "Enabling automatic installation of network devices..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" "AutoSetup"
}

###############################################################################
### Windows Defender                                                          #
###############################################################################

# Enable Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function EnableCtrldFolderAccess {
	Write-Output "Enabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Enabled
}

# Disable Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function DisableCtrldFolderAccess {
	Write-Output "Disabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Disabled
}

# Enable Windows Defender
Function EnableDefender {
	Write-Output "Enabling Windows Defender..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware"
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "SecurityHealth" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
}

# Disable Windows Defender
Function DisableDefender {
	Write-Output "Disabling Windows Defender..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "DWord" 1
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "SecurityHealth"
}

# Disable Windows Defender Cloud
Function DisableDefenderCloud {
	Write-Output "Disabling Windows Defender Cloud..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" "DWord" 2
}

# Enable Windows Defender Cloud
Function EnableDefenderCloud {
	Write-Output "Enabling Windows Defender Cloud..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting"
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent"
}

Function DisableDefenderReporting {
	Write-Output "Disabling Windows Defender Reporting..."

	# Disable Cloud-Based Protection: Enabled Advanced: 2, Enabled Basic: 1, Disabled: 0
	Set-MpPreference -MAPSReporting 0

	# Disable automatic sample submission: Prompt: 0, Auto Send Safe: 1, Never: 2, Auto Send All: 3
	Set-MpPreference -SubmitSamplesConsent 2
}

###############################################################################
### Windows Firewall                                                          #
###############################################################################

# Disable Firewall
Function DisableFirewall {
	Write-Output "Disabling Firewall..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" "EnableFirewall" "DWord" 0
}

# Enable Firewall
Function EnableFirewall {
	Write-Output "Enabling Firewall..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" "EnableFirewall"
}

###############################################################################
### Devices, Power, and Startup                                               #
###############################################################################

# Enable F8 boot menu options
Function EnableF8BootMenu {
	Write-Output "Enabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
}

# Disable F8 boot menu options
Function DisableF8BootMenu {
	Write-Output "Disabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Standard | Out-Null
}

Function DisableStartupSounds {
	Write-Output "Disabling startup Sound..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableStartupSound" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" "DisableStartupSound" "DWord" 1

}

# Power: Disable Hibernation
Function DisableHibernation {

	Write-Output "Disabling startup Sound..."
	powercfg /hibernate off

}

# Power: Enable Hibernation
Function EnableHibernation {
	# Power: Disable Hibernation
	powercfg /hibernate on

}

###############################################################################
### Windows Update                                                            #
###############################################################################

# Enable Automatic Updates
Function EnableAutomaticUpdates {
	Write-Output "Enabling automated updates..."
	SetRegistryKey "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" "DWord" 0
	# Configure to Auto-Download but not Install: NotConfigured: 0, Disabled: 1, NotifyBeforeDownload: 2, NotifyBeforeInstall: 3, ScheduledInstall: 4
	SetRegistryKey "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" "DWord" 3
	# Include Recommended Updates
	SetRegistryKey "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "IncludeRecommendedUpdates" "DWord" 1
	# Opt-In to Microsoft Update
	$MU = New-Object -ComObject Microsoft.Update.ServiceManager -Strict
	$MU.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") | Out-Null
	Remove-Variable MU
}

# Disable Automatic Updates
Function DisableAutomaticUpdates {
	Write-Output "Disabling automated updates..."
	SetRegistryKey "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" "DWord" 1
}

# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
	Write-Output "Disabling Malicious Software Removal Tool offering..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\MRT" "DontOfferThroughWUAU" "DWord" 1
}

# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT {
	Write-Output "Enabling Malicious Software Removal Tool offering..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\MRT" "DontOfferThroughWUAU"
}

# Disable offering of drivers through Windows Update
Function DisableUpdateDriver {
	Write-Output "Disabling driver offering through Windows Update..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ExcludeWUDriversInQualityUpdate" "DWord" 1
}

# Enable offering of drivers through Windows Update
Function EnableUpdateDriver {
	Write-Output "Enabling driver offering through Windows Update..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" "DWord" 1
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ExcludeWUDriversInQualityUpdate"
}

# Disable Windows Update automatic restart
Function DisableUpdateRestart {
	Write-Output "Disabling Windows Update automatic restart..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUPowerManagement" "DWord" 0
}

# Enable Windows Update automatic restart
Function EnableUpdateRestart {
	Write-Output "Enabling Windows Update automatic restart..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers"
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUPowerManagement"
}


# Restrict Windows Update P2P only to local network
Function SetP2PUpdateLocal {
	Write-Output "Restricting Windows Update P2P only to local network..."
	# Delivery Optimization:
	# Download from 0: Http Only [Disable], 1: Peering on LAN, 2: Peering on AD / Domain, 3: Peering on Internet, 99: No peering, 100: Bypass & use BITS
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" "DWord" 1

	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" "SystemSettingsDownloadMode" "DWord" 3
}

# Unrestrict Windows Update P2P
Function SetP2PUpdateInternet {
	Write-Output "Unrestricting Windows Update P2P to internet..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode"
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" "SystemSettingsDownloadMode"
}

###############################################################################
### Service Tweaks                                                            #
###############################################################################

# Stop and disable Home Groups services - Not applicable to Server
Function DisableHomeGroups {
	Write-Output "Stopping and disabling Home Groups services..."
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled
}

# Enable and start Home Groups services - Not applicable to Server
Function EnableHomeGroups {
	Write-Output "Starting and enabling Home Groups services..."
	Set-Service "HomeGroupListener" -StartupType Manual
	Set-Service "HomeGroupProvider" -StartupType Manual
	Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
}

# Disable Shared Experiences - Not applicable to Server
Function DisableSharedExperiences {
	Write-Output "Disabling Shared Experiences..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" "RomeSdkChannelUserAuthzPolicy" "DWord" 0
}

# Enable Shared Experiences - Not applicable to Server
Function EnableSharedExperiences {
	Write-Output "Enabling Shared Experiences..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" "RomeSdkChannelUserAuthzPolicy" "DWord" 1
}

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
	Write-Output "Disabling Remote Assistance..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" "DWord" 0
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
	Write-Output "Enabling Remote Assistance..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" "DWord" 1
}

# Enable Remote Desktop w/o Network Level Authentication
Function EnableRemoteDesktop {
	Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "DWord" 0
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" "DWord" 0
}

# Disable Remote Desktop
Function DisableRemoteDesktop {
	Write-Output "Disabling Remote Desktop..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "DWord" 1
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" "DWord" 1
}

# Disable Autoplay
Function DisableAutoplay {
	Write-Output "Disabling Autoplay..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" "DisableAutoplay" "DWord" 1
}

# Enable Autoplay
Function EnableAutoplay {
	Write-Output "Enabling Autoplay..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" "DisableAutoplay" "DWord" 0
}

# Disable Autorun for all drives
Function DisableAutorun {
	Write-Output "Disabling Autorun for all drives..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" "DWord" 255
}

# Enable Autorun for removable drives
Function EnableAutorun {
	Write-Output "Enabling Autorun for all drives..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
}

# Enable Storage Sense - automatic disk cleanup - Not applicable to Server
Function EnableStorageSense {
	Write-Output "Enabling Storage Sense..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" "01" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" "04" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" "08" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" "32" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" "StoragePoliciesNotified" "DWord" 1
}

# Disable Storage Sense - Not applicable to Server
Function DisableStorageSense {
	Write-Output "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

# Disable scheduled defragmentation task
Function DisableDefragmentation {
	Write-Output "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Enable scheduled defragmentation task
Function EnableDefragmentation {
	Write-Output "Enabling scheduled defragmentation..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Stop and disable Superfetch service - Not applicable to Server
Function DisableSuperfetch {
	Write-Output "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}

# Start and enable Superfetch service - Not applicable to Server
Function EnableSuperfetch {
	Write-Output "Starting and enabling Superfetch service..."
	Set-Service "SysMain" -StartupType Automatic
	Start-Service "SysMain" -WarningAction SilentlyContinue
}

# Stop and disable Windows Search indexing service
Function DisableIndexing {
	Write-Output "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
}

# Start and enable Windows Search indexing service
Function EnableIndexing {
	Write-Output "Starting and enabling Windows Search indexing service..."
	Set-Service "WSearch" -StartupType Automatic
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" "DelayedAutoStart" "DWord" 1
	Start-Service "WSearch" -WarningAction SilentlyContinue
}

# Set BIOS time to UTC
Function SetBIOSTimeUTC {
	Write-Output "Setting BIOS time to UTC..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" "RealTimeIsUniversal" "DWord" 1
}

# Set BIOS time to local time
Function SetBIOSTimeLocal {
	Write-Output "Setting BIOS time to Local time..."
	DeleteRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" "RealTimeIsUniversal"
}

# Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
Function EnableHibernationState {
	Write-Output "Enabling Hibernation..."
	SetRegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" "HibernteEnabled" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowHibernateOption" "DWord" 1
}

# Disable Hibernation
Function DisableHibernationState {
	Write-Output "Disabling Hibernation..."
	SetRegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" "HibernteEnabled" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowHibernateOption" "DWord" 0
}

# Disable Sleep start menu and keyboard button
Function DisableSleepButton {
	Write-Output "Disabling Sleep start menu and keyboard button..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowSleepOption" "DWord" 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
}

# Enable Sleep start menu and keyboard button
Function EnableSleepButton {
	Write-Output "Enabling Sleep start menu and keyboard button..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowSleepOption" "DWord" 1
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
}

# Disable display and sleep mode timeouts
Function DisableSleepTimeout {
	Write-Output "Disabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
}

# Enable display and sleep mode timeouts
Function EnableSleepTimeout {
	Write-Output "Enabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 10
	powercfg /X monitor-timeout-dc 5
	powercfg /X standby-timeout-ac 30
	powercfg /X standby-timeout-dc 15
}

# Disable Fast Startup
Function DisableFastStartup {
	Write-Output "Disabling Fast Startup..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" "DWord" 0
}

# Enable Fast Startup
Function EnableFastStartup {
	Write-Output "Enabling Fast Startup..."
	SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" "DWord" 1
}


###############################################################################
### Explorer, Taskbar, and System Tray                                        #
###############################################################################

Function SetSysTray {
	Write-Output "Setting system tray..."
	# SysTray: Hide the Action Center, Network, and Volume icons
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "HideSCAHealth" "DWord" 1  # Action Center
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "HideSCANetwork" "DWord" 1 # Network
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "HideSCAVolume" "DWord" 1  # Volume
	#SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "HideSCAPower" "DWord" 1  # Power

}

Function SetColorPrevalence {
	Write-Output "Setting color prelevance..."
	# Titlebar: Disable theme colors on titlebar
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\DWM" "ColorPrevalence" "DWord" 0
	# Taskbar: Show colors on Taskbar, Start, and SysTray: Disabled: 0, Taskbar, Start, & SysTray: 1, Taskbar Only: 2
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "ColorPrevalence" "DWord" 1
}

Function HideStoreAppsOnTaskbar {
	# Taskbar: Don't show Windows Store Apps on Taskbar
	Write-Output "Hide store apps on taskbar..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "StoreAppsOnTaskbar" "DWord" 0
}

# Disable Action Center
Function DisableActionCenter {
	Write-Output "Disabling Action Center..."
	SetRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter" "DWord" 1
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled" "DWord" 0
}

# Enable Action Center
Function EnableActionCenter {
	Write-Output "Enabling Action Center..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter"
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled"
}

# Disable Sticky keys prompt
Function DisableStickyKeys {
	Write-Output "Disabling Sticky keys prompt..."
	SetRegistryKey "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "String" "506"
}

# Enable Sticky keys prompt
Function EnableStickyKeys {
	Write-Output "Enabling Sticky keys prompt..."
	SetRegistryKey "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "String" "510"
}

# Show Task Manager details
Function ShowTaskManagerDetails {
	Write-Output "Showing task manager details..."

	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" "Preferences"
	If (!($preferences)) {
		$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
		While (!($preferences)) {
			Start-Sleep -m 250
			$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" "Preferences"
		}
		Stop-Process $taskmgr -ErrorAction SilentlyContinue
	}
	$preferences.Preferences[28] = 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" "Preferences" "Binary" $preferences.Preferences
}

# Hide Task Manager details
Function HideTaskManagerDetails {
	Write-Output "Hiding task manager details..."
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" "Preferences"
	If ($preferences) {
		$preferences.Preferences[28] = 1
		SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" "Preferences" "Binary" $preferences.Preferences
	}
}

# Show file operations details
Function ShowFileOperationsDetails {
	Write-Output "Showing file operations details..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" "EnthusiastMode" "DWord" 1
}

# Hide file operations details
Function HideFileOperationsDetails {
	Write-Output "Hiding file operations details..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" "EnthusiastMode"
}

# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm {
	Write-Output "Enabling file delete confirmation dialog..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ConfirmFileDelete" "DWord" 1
}

# Disable file delete confirmation dialog
Function DisableFileDeleteConfirm {
	Write-Output "Disabling file delete confirmation dialog..."
	DeleteRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ConfirmFileDelete"
}

# Hide Taskbar Search button / box
Function HideTaskbarSearchBox {
	Write-Output "Hiding Taskbar Search box / button..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" "DWord" 0
}

# Show Taskbar Search button / box
Function ShowTaskbarSearchBox {
	Write-Output "Showing Taskbar Search box / button..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode"
}

# Hide Task View button
Function HideTaskView {
	Write-Output "Hiding Task View button..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowTaskViewButton" "DWord" 0
}

# Show Task View button
Function ShowTaskView {
	Write-Output "Showing Task View button..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowTaskViewButton"
}

# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
	Write-Output "Showing small icons in taskbar..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarSmallIcons" "DWord" 1
}

# Show large icons in taskbar
Function ShowLargeTaskbarIcons {
	Write-Output "Showing large icons in taskbar..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarSmallIcons"
}

# Show titles in taskbar
Function ShowTaskbarTitles {
	Write-Output "Showing titles in taskbar..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarGlomLevel" "DWord" 1
}

# Hide titles in taskbar
Function HideTaskbarTitles {
	Write-Output "Hiding titles in taskbar..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarGlomLevel"
}

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
	Write-Output "Hiding People icon..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" "DWord" 0
}

# Show Taskbar People icon
Function ShowTaskbarPeopleIcon {
	Write-Output "Showing People icon..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand"
}

# Show all tray icons
Function ShowTrayIcons {
	Write-Output "Showing all tray icons..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "EnableAutoTray" "DWord" 0
}

# Hide tray icons as needed
Function HideTrayIcons {
	Write-Output "Hiding tray icons..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "EnableAutoTray"
}

# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
	Write-Output "Disabling search for app in store for unknown extensions..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoUseStoreOpenWith" "DWord" 1
}

# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore {
	Write-Output "Enabling search for app in store for unknown extensions..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoUseStoreOpenWith"
}

# Disable 'How do you want to open this file?' prompt
Function DisableNewAppPrompt {
	Write-Output "Disabling 'How do you want to open this file?' prompt..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoNewAppAlert" "DWord" 1
}

# Enable 'How do you want to open this file?' prompt
Function EnableNewAppPrompt {
	Write-Output "Enabling 'How do you want to open this file?' prompt..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoNewAppAlert"
}

# Set Control Panel view to icons (Classic) - Note: May trigger antimalware
Function SetControlPanelViewIcons {
	Write-Output "Setting Control Panel view to icons..."
	SetRegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ForceClassicControlPanel" "DWord" 1
}

# Set Control Panel view to categories
Function SetControlPanelViewCategories {
	Write-Output "Setting Control Panel view to categories..."
	DeleteRegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ForceClassicControlPanel"
}

# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
	Write-Output "Adjusting visual effects for performance..."
	SetRegistryKey "HKCU:\Control Panel\Desktop" "DragFullWindows" "String" 0
	SetRegistryKey "HKCU:\Control Panel\Desktop" "MenuShowDelay" "String" 0
	SetRegistryKey "HKCU:\Control Panel\Desktop" "UserPreferencesMask" "Binary" ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
	SetRegistryKey "HKCU:\Control Panel\Desktop\WindowMetrics" "MinAnimate" "String" 0
	SetRegistryKey "HKCU:\Control Panel\Keyboard" "KeyboardDelay" "DWord" 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewAlphaSelect" "DWord" 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" "DWord" 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" "DWord" 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" "DWord" 3
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\DWM" "EnableAeroPeek" "DWord" 0
}

# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
	Write-Output "Adjusting visual effects for appearance..."
	SetRegistryKey "HKCU:\Control Panel\Desktop" "DragFullWindows" "String" 1
	SetRegistryKey "HKCU:\Control Panel\Desktop" "MenuShowDelay" "String" 400
	SetRegistryKey "HKCU:\Control Panel\Desktop" "UserPreferencesMask" -Type Binary -Value ([byte[]](0x9E,0x1E,0x07,0x80,0x12,0x00,0x00,0x00))
	SetRegistryKey "HKCU:\Control Panel\Desktop\WindowMetrics" "MinAnimate" "String" 1
	SetRegistryKey "HKCU:\Control Panel\Keyboard" "KeyboardDelay" "DWord" 1
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewAlphaSelect" "DWord" 1
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" "DWord" 1
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" "DWord" 1
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" "DWord" 3
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\DWM" "EnableAeroPeek" "DWord" 1
}

# Add secondary en-US keyboard
Function AddENKeyboard {
	Write-Output "Adding secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	$langs.Add("en-US")
	Set-WinUserLanguageList $langs -Force
}

# Remove secondary en-US keyboard
Function RemoveENKeyboard {
	Write-Output "Removing secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force
}

# Enable NumLock after startup
Function EnableNumlock {
	Write-Output "Enabling NumLock after startup..."
  If (!(Test-Path "HKU:")) {
    New-PSDrive -PSProvider Registry -Root Registry::HKEY_USERS -Name "HKU" | Out-Null
  }
	SetRegistryKey "HKU:\.DEFAULT\Control Panel\Keyboard" "InitialKeyboardIndicators" "DWord" 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

# Disable NumLock after startup
Function DisableNumlock {
	Write-Output "Disabling NumLock after startup..."
  If (!(Test-Path "HKU:")) {
    New-PSDrive -PSProvider Registry -Root Registry::HKEY_USERS -Name "HKU" | Out-Null
  }
	SetRegistryKey "HKU:\.DEFAULT\Control Panel\Keyboard" "InitialKeyboardIndicators" "DWord" 2147483648
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}


###############################################################################
# Explorer UI Tweaks
###############################################################################

# Show known file extensions
Function ShowKnownExtensions {
	Write-Output "Showing known file extensions..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" "DWord" 0
}

# Hide known file extensions
Function HideKnownExtensions {
	Write-Output "Hiding known file extensions..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" "DWord" 1
}

# Show hidden files
Function ShowHiddenFiles {
	Write-Output "Showing hidden files..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" "DWord" 1
}

# Hide hidden files
Function HideHiddenFiles {
	Write-Output "Hiding hidden files..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" "DWord" 2
}

# Explorer: Show path in title bar
Function ShowPathInTitleBar {
	Write-Output "Disabling Autorun for all drives..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" "FullPath" 1
}

# Explorer: Hide path in title bar
Function HidePathInTitleBar {
	Write-Output "Disabling Autorun for all drives..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" "FullPath" 0
}

# Hide sync provider notifications
Function HideSyncNotifications {
	Write-Output "Hiding sync provider notifications..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" "DWord" 0
}

# Hide sync provider notifications
Function HideSyncNotifications {
	Write-Output "Hiding sync provider notifications..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" "DWord" 0
}

# Show sync provider notifications
Function ShowSyncNotifications {
	Write-Output "Showing sync provider notifications..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" "DWord" 1
}

# Hide recently and frequently used item shortcuts in Explorer
Function HideRecentShortcuts {
	Write-Output "Hiding recent shortcuts..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "ShowRecent" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "ShowFrequent" "DWord" 0
}

# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
	Write-Output "Showing recent shortcuts..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "ShowRecent"
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "ShowFrequent"
}

# Change default Explorer view to This PC
Function SetExplorerThisPC {
	Write-Output "Changing default Explorer view to This PC..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" "DWord" 1
}

# Change default Explorer view to Quick Access
Function SetExplorerQuickAccess {
	Write-Output "Changing default Explorer view to Quick Access..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo"
}

# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
	Write-Output "Showing This PC shortcut on desktop..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" "DWord" 0
}

# Hide This PC shortcut from desktop
Function HideThisPCFromDesktop {
	Write-Output "Hiding This PC shortcut from desktop..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
}

# Show User Folder shortcut on desktop
Function ShowUserFolderOnDesktop {
	Write-Output "Showing User Folder shortcut on desktop..."
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" "DWord" 0
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" "DWord" 0
}

# Hide User Folder shortcut from desktop
Function HideUserFolderFromDesktop {
	Write-Output "Hiding User Folder shortcut from desktop..."
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" "{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
	DeleteRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" "{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
}

# Hide Desktop icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDesktopFromThisPC {
	Write-Output "Hiding Desktop icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
}

# Show Desktop icon in This PC
Function ShowDesktopInThisPC {
	Write-Output "Showing Desktop icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" | Out-Null
	}
}

# Hide Desktop icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDesktopFromExplorer {
	Write-Output "Hiding Desktop icon from Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" "ThisPCPolicy" "String" "Hide"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" "ThisPCPolicy" "String" "Hide"
}

# Show Desktop icon in Explorer namespace
Function ShowDesktopInExplorer {
	Write-Output "Showing Desktop icon in Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" "ThisPCPolicy" "String" "Show"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" "ThisPCPolicy" "String" "Show"
}

# Hide Documents icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDocumentsFromThisPC {
	Write-Output "Hiding Documents icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
}

# Show Documents icon in This PC
Function ShowDocumentsInThisPC {
	Write-Output "Showing Documents icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" | Out-Null
	}
}

# Hide Documents icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDocumentsFromExplorer {
	Write-Output "Hiding Documents icon from Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" "ThisPCPolicy" "String" "Hide"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" "ThisPCPolicy" "String" "Hide"
}

# Show Documents icon in Explorer namespace
Function ShowDocumentsInExplorer {
	Write-Output "Showing Documents icon in Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" "ThisPCPolicy" "String" "Show"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" "ThisPCPolicy" "String" "Show"
}

# Hide Downloads icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDownloadsFromThisPC {
	Write-Output "Hiding Downloads icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
}

# Show Downloads icon in This PC
Function ShowDownloadsInThisPC {
	Write-Output "Showing Downloads icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" | Out-Null
	}
}

# Hide Downloads icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDownloadsFromExplorer {
	Write-Output "Hiding Downloads icon from Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" "ThisPCPolicy" "String" "Hide"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" "ThisPCPolicy" "String" "Hide"
}

# Show Downloads icon in Explorer namespace
Function ShowDownloadsInExplorer {
	Write-Output "Showing Downloads icon in Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" "ThisPCPolicy" "String" "Show"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" "ThisPCPolicy" "String" "Show"
}

# Hide Music icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideMusicFromThisPC {
	Write-Output "Hiding Music icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
}

# Show Music icon in This PC
Function ShowMusicInThisPC {
	Write-Output "Showing Music icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" | Out-Null
	}
}

# Hide Music icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideMusicFromExplorer {
	Write-Output "Hiding Music icon from Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" "ThisPCPolicy" "String" "Hide"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" "ThisPCPolicy" "String" "Hide"
}

# Show Music icon in Explorer namespace
Function ShowMusicInExplorer {
	Write-Output "Showing Music icon in Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" "ThisPCPolicy" "String" "Show"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" "ThisPCPolicy" "String" "Show"
}

# Hide Pictures icon from This PC - The icon remains in personal folders and open/save dialogs
Function HidePicturesFromThisPC {
	Write-Output "Hiding Pictures icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
}

# Show Pictures icon in This PC
Function ShowPicturesInThisPC {
	Write-Output "Showing Pictures icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" | Out-Null
	}
}

# Hide Pictures icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HidePicturesFromExplorer {
	Write-Output "Hiding Pictures icon from Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" "ThisPCPolicy" "String" "Hide"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" "ThisPCPolicy" "String" "Hide"
}

# Show Pictures icon in Explorer namespace
Function ShowPicturesInExplorer {
	Write-Output "Showing Pictures icon in Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" "ThisPCPolicy" "String" "Show"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" "ThisPCPolicy" "String" "Show"
}

# Hide Videos icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideVideosFromThisPC {
	Write-Output "Hiding Videos icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
}

# Show Videos icon in This PC
Function ShowVideosInThisPC {
	Write-Output "Showing Videos icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" | Out-Null
	}
}

# Hide Videos icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideVideosFromExplorer {
	Write-Output "Hiding Videos icon from Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" "ThisPCPolicy" "String" "Hide"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" "ThisPCPolicy" "String" "Hide"
}

# Show Videos icon in Explorer namespace
Function ShowVideosInExplorer {
	Write-Output "Showing Videos icon in Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" "ThisPCPolicy" "String" "Show"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" "ThisPCPolicy" "String" "Show"
}

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
Function Hide3DObjectsFromThisPC {
	Write-Output "Hiding 3D Objects icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

# Show 3D Objects icon in This PC
Function Show3DObjectsInThisPC {
	Write-Output "Showing 3D Objects icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
	}
}

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function Hide3DObjectsFromExplorer {
	Write-Output "Hiding 3D Objects icon from Explorer namespace..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" "ThisPCPolicy" "String" "Hide"
	SetRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" "ThisPCPolicy" "String" "Hide"
}

# Show 3D Objects icon in Explorer namespace
Function Show3DObjectsInExplorer {
	Write-Output "Showing 3D Objects icon in Explorer namespace..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" "ThisPCPolicy"
	DeleteRegistryKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" "ThisPCPolicy"
}

# Disable thumbnails, show only file extension icons
Function DisableThumbnails {
	Write-Output "Disabling thumbnails..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "IconsOnly" "DWord" 1
}

# Enable thumbnails
Function EnableThumbnails {
	Write-Output "Enabling thumbnails..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "IconsOnly" "DWord" 0
}


# Disable creation of Thumbs.db thumbnail cache files
Function DisableThumbsDB {
	Write-Output "Disabling creation of Thumbs.db..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbnailCache" "DWord" 1
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbsDBOnNetworkFolders" "DWord" 1
}

# Enable creation of Thumbs.db thumbnail cache files
Function EnableThumbsDB {
	Write-Output "Enable creation of Thumbs.db..."
	DeleteRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbnailCache"
	DeleteRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbsDBOnNetworkFolders"
}

# Recycle Bin: Disable Delete Confirmation Dialog
Function DisableConfirmDeleteRecycleBin {
	Write-Output "Disabling Recycle Bin confirmation dialog..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ConfirmFileDelete" "DWord" 0
}

###############################################################################
### Lock Screen                                                               #
###############################################################################

# Enable Custom Background on the Login / Lock Screen
Function EnableLoginCustomBackground{
	## Background file: C:\someDirectory\someImage.jpg
	## File Size Limit: 256Kb
	# SetRegistryKey "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "LockScreenImage" "C:\someDirectory\someImage.jpg"
}


# Disable Lock screen
Function DisableLockScreen {
	Write-Output "Disabling Lock screen..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreen" "DWord" 1
}

# Enable Lock screen
Function EnableLockScreen {
	Write-Output "Enabling Lock screen..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreen"
}

# Disable Lock screen (Anniversary Update workaround) - Applicable to 1607 or newer
Function DisableLockScreenRS1 {
	Write-Output "Disabling Lock screen using scheduler workaround..."
	$service = New-Object -com Schedule.Service
	$service.Connect()
	$task = $service.NewTask(0)
	$task.Settings.DisallowStartIfOnBatteries = $false
	$trigger = $task.Triggers.Create(9)
	$trigger = $task.Triggers.Create(11)
	$trigger.StateChange = 8
	$action = $task.Actions.Create(0)
	$action.Path = "reg.exe"
	$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
	$service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}

# Enable Lock screen (Anniversary Update workaround) - Applicable to 1607 or newer
Function EnableLockScreenRS1 {
	Write-Output "Enabling Lock screen (removing scheduler workaround)..."
	Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false
}

# Hide network options from Lock Screen
Function HideNetworkFromLockScreen {
	Write-Output "Hiding network options from Lock Screen..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" "DWord" 1
}

# Show network options on lock screen
Function ShowNetworkOnLockScreen {
	Write-Output "Showing network options on Lock Screen..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI"
}

# Hide shutdown options from Lock Screen
Function HideShutdownFromLockScreen {
	Write-Output "Hiding shutdown options from Lock Screen..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon" "DWord" 0
}

# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen {
	Write-Output "Showing shutdown options on Lock Screen..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon" "DWord" 1
}

Function SetLogonKeyboardLayout {
  Write-Output "Setting logon keyboard layout to EN-US..."
  If (!(Test-Path "HKU:")) {
    New-PSDrive -PSProvider Registry -Root Registry::HKEY_USERS -Name "HKU" | Out-Null
  }
  #English (United States)
  SetRegistryKey "HKU:\.DEFAULT\Keyboard Layout\Preload" "1" "String" "00000409"
  SetRegistryKey "HKCU:\Keyboard Layout\Preload" "1" "String" "00000409"
  #Russian
  SetRegistryKey "HKU:\.DEFAULT\Keyboard Layout\Preload" "2" "String" "00000419"
  SetRegistryKey "HKCU:\Keyboard Layout\Preload" "2" "String" "00000419"
  Set-WinUserLanguageList -LanguageList en-US, ru-RU -Force
}

###############################################################################
### Application Tweaks                                                        #
###############################################################################

# Disable OneDrive
Function DisableOneDrive {
	Write-Output "Disabling OneDrive..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "DWord" 1
}

# Enable OneDrive
Function EnableOneDrive {
	Write-Output "Enabling OneDrive..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC"
}

# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
	Write-Output "Uninstalling OneDrive..."
	Stop-Process -name OneDrive -ErrorAction SilentlyContinue
	Start-Sleep -s 3
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 3
	Stop-Process -name explorer -ErrorAction SilentlyContinue
	Start-Sleep -s 3
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}

# Install OneDrive - Not applicable to Server
Function InstallOneDrive {
	Write-Output "Installing OneDrive..."
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive -NoNewWindow
}

# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash {
	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	SetRegistryKey "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" "FlashPlayerEnabled" "DWord" 0
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" "Flags" "DWord" 1
}

# Enable built-in Adobe Flash in IE and Edge
Function EnableAdobeFlash {
	Write-Output "Enabling built-in Adobe Flash in IE and Edge..."
	DeleteRegistryKey "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" "FlashPlayerEnabled"
	DeleteRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" "Flags"
}

# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Output "Uninstalling Windows Media Player..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Windows Media Player
Function InstallMediaPlayer {
	Write-Output "Installing Windows Media Player..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
	Write-Output "Uninstalling Work Folders Client..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Work Folders Client - Not applicable to Server
Function InstallWorkFolders {
	Write-Output "Installing Work Folders Client..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Linux Subsystem - Applicable to 1607 or newer, not applicable to Server yet
Function InstallLinuxSubsystem {
	Write-Output "Installing Linux Subsystem..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowAllTrustedApps" "DWord" 1
	Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Linux Subsystem - Applicable to 1607 or newer, not applicable to Server yet
Function UninstallLinuxSubsystem {
	Write-Output "Uninstalling Linux Subsystem..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowAllTrustedApps" "DWord" 0
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
	Write-Output "Installing Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Install-WindowsFeature "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	} Else {
		Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall Hyper-V - Not applicable to Home
Function UninstallHyperV {
	Write-Output "Uninstalling Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Uninstall-WindowsFeature "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	} Else {
		Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

###############################################################################
### File Association                                                          #
###############################################################################

# Run powershell script by double clicking .ps1 file
Function SetPowershellScriptAction {
  If (!(Test-Path "HKCR:")) {
    New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
  }
  # 0: Run by double-clicking, Edit: Open in ISE, Open: Open in Notepad (default value)
  SetRegistryKey "HKCR:\Microsoft.PowerShellScript.1\Shell" "(Default)" "String" 0

}

# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
	Write-Output "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
		New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
		New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
		SetRegistryKey $("HKCR:\$type\shell\open") "MuiVerb" "ExpandString" "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		SetRegistryKey $("HKCR:\$type\shell\open\command") "(Default)" "ExpandString" "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}
}

# Unset Photo Viewer association for bmp, gif, jpg, png and tif
Function UnsetPhotoViewerAssociation {
	Write-Output "Unsetting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse -ErrorAction SilentlyContinue
	DeleteRegistryKey "HKCR:\giffile\shell\open" "MuiVerb"
	SetRegistryKey "HKCR:\giffile\shell\open" "CommandId" "String" "IE.File"
	SetRegistryKey "HKCR:\giffile\shell\open\command" "(Default)" "String" "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
	SetRegistryKey "HKCR:\giffile\shell\open\command" "DelegateExecute" "String" "{17FE9752-0B5A-4665-84CD-569794602F5C}"
	Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse -ErrorAction SilentlyContinue
}

# Add Photo Viewer to "Open with..."
Function AddPhotoViewerOpenWith {
	Write-Output "Adding Photo Viewer to `"Open with...`""
	If (!(Test-Path "HKCR:")) {
		New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
	SetRegistryKey "HKCR:\Applications\photoviewer.dll\shell\open" "MuiVerb" "String" "@photoviewer.dll,-3043"
	SetRegistryKey "HKCR:\Applications\photoviewer.dll\shell\open\command" "(Default)" "ExpandString" "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	SetRegistryKey "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" "Clsid" "String" "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
}

# Remove Photo Viewer from "Open with..."
Function RemovePhotoViewerOpenWith {
	Write-Output "Removing Photo Viewer from `"Open with...`""
	If (!(Test-Path "HKCR:")) {
		New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse -ErrorAction SilentlyContinue
}

###############################################################################
### Printers                                                                  #
###############################################################################


# Uninstall Microsoft Print to PDF
Function UninstallPDFPrinter {
	Write-Output "Uninstalling Microsoft Print to PDF..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft Print to PDF
Function InstallPDFPrinter {
	Write-Output "Installing Microsoft Print to PDF..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Microsoft XPS Document Writer
Function UninstallXPSPrinter {
	Write-Output "Uninstalling Microsoft XPS Document Writer..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft XPS Document Writer
Function InstallXPSPrinter {
	Write-Output "Installing Microsoft XPS Document Writer..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Remove Default Fax Printer
Function RemoveFaxPrinter {
	Write-Output "Removing Default Fax Printer..."
	Remove-Printer "Fax" -ErrorAction SilentlyContinue
}

# Add Default Fax Printer
Function AddFaxPrinter {
	Write-Output "Adding Default Fax Printer..."
	Add-Printer "Fax" -DriverName "Microsoft Shared Fax Driver" -PortName "SHRFAX:"
}


###############################################################################
### Bloat software                                                            #
###############################################################################

# Uninstall default Microsoft applications
Function UninstallMsftBloat {
	Write-Output "Uninstalling default Microsoft applications..."
	Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
	Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
}

# Install default Microsoft applications
Function InstallMsftBloat {
	Write-Output "Installing default Microsoft applications..."
	Get-AppxPackage -AllUsers "Microsoft.3DBuilder" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingFinance" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingNews" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingSports" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingWeather" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Getstarted" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Office.OneNote" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.People" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.SkypeApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Windows.Photos" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsAlarms" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsCamera" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.windowscommunicationsapps" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsMaps" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsPhone" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsSoundRecorder" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.ZuneMusic" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.ZuneVideo" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.AppConnector" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Office.Sway" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Messaging" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.CommsPhone" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftStickyNotes" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.OneConnect" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MinecraftUWP" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MSPaint" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.RemoteDesktop" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Print3D" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.GetHelp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Wallet" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse

# Uninstall default third party applications
function UninstallThirdPartyBloat {
	Write-Output "Uninstalling default third party applications..."
	Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
	Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
	Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
	Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
	Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
	Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
	Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
	Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
	Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
	Get-AppxPackage "2FE3CB00.PicsArt-PhotoStudio" | Remove-AppxPackage
	Get-AppxPackage "*.SlingTV" -AllUsers | Remove-AppxPackage
}

function RemoveProvisionedBloat {

 	Write-Output "Removing bloat software..."

	# Microsoft bloat
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.3DBuilder" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.BingFinance" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.BingNews" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.BingSports" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.BingWeather" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.GetStarted" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.MicrosoftOfficeHub" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.Office.OneNote" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.People" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.SkypeApp" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.Windows.Photos" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.WindowsAlarms" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.WindowsCamera" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.WindowsCommunicationsApps" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.WindowsMaps" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.WindowsPhone" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.WindowsSoundRecorder" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.ZuneMusic" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.ZuneVideo" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.AppConnector" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.ConnectivityStore" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.Office.Sway" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.Messaging" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.CommsPhone" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.MicrosoftStickyNotes" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.OneConnect" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.WindowsFeedbackHub" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.MinecraftUWP" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.NetworkSpeedTest" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.MSPaint" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.Microsoft3DViewer" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.RemoteDesktop" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.Print3D" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.GetHelp" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.Wallet" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Microsoft.XboxApp" | Remove-AppxProvisionedPackage -Online

	# Third party bloat
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.Twitter" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "king.com.CandyCrushSodaSaga" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "4DF9E0F8.Netflix" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Drawboard.DrawboardPDF" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.FarmVille2CountryEscape" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.Asphalt8Airborne" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.RoyalRevolt2" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.Duolingo-LearnLanguagesforFree" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "Facebook.Facebook" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.EclipseManager" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.MarchofEmpires" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "KeeperSecurityInc.Keeper" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "king.com.BubbleWitch3Saga" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.AutodeskSketchBook" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "CAF9E577.Plex" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.DisneyMagicKingdoms" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.HiddenCityMysteryofShadows" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.WinZipUniversal" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "SpotifyAB.SpotifyMusic" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*PandoraMediaInc.29680B314EFC2" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "2414FC7A.Viber" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "64885BlueEdge.OneCalendar" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.ACGMediaPlayer" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "DolbyLaboratories.DolbyAccess" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "2FE3CB00.PicsArt-PhotoStudio" | Remove-AppxProvisionedPackage -Online
	Get-AppXProvisionedPackage -Online | Where DisplayNam -like "*.SlingTV" | Remove-AppxProvisionedPackage -Online

}

# Install default third party applications
Function InstallThirdPartyBloat {
	Write-Output "Installing default third party applications..."
	Get-AppxPackage -AllUsers "9E2F88E3.Twitter" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "king.com.CandyCrushSodaSaga" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "4DF9E0F8.Netflix" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Drawboard.DrawboardPDF" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "D52A8D61.FarmVille2CountryEscape" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "flaregamesGmbH.RoyalRevolt2" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "AdobeSystemsIncorporated.AdobePhotoshopExpress" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "ActiproSoftwareLLC.562882FEEB491" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "D5EA27B7.Duolingo-LearnLanguagesforFree" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Facebook.Facebook" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "46928bounde.EclipseManager" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "A278AB0D.MarchofEmpires" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "KeeperSecurityInc.Keeper" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "king.com.BubbleWitch3Saga" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "89006A2E.AutodeskSketchBook" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "CAF9E577.Plex" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "A278AB0D.DisneyMagicKingdoms" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "828B5831.HiddenCityMysteryofShadows" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "WinZipComputing.WinZipUniversal" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "SpotifyAB.SpotifyMusic" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "PandoraMediaInc.29680B314EFC2" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "2414FC7A.Viber" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "64885BlueEdge.OneCalendar" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "41038Axilesoft.ACGMediaPlayer" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "DolbyLaboratories.DolbyAccess" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}

}

# Uninstall Windows Store
Function UninstallWindowsStore {
	Write-Output "Uninstalling Windows Store..."
	Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}

# Install Windows Store
Function InstallWindowsStore {
	Write-Output "Installing Windows Store..."
	Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}

# Disable Xbox features
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	SetRegistryKey "HKCU:\System\GameConfigStore" "GameDVR_Enabled" "DWord" 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "DWord" 0
}

# Enable Xbox features
Function EnableXboxFeatures {
	Write-Output "Enabling Xbox features..."
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	SetRegistryKey "HKCU:\System\GameConfigStore" "GameDVR_Enabled" "DWord" 1
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR"
}


###############################################################################
### Server specific Tweaks                                                    #
###############################################################################

# Hide Server Manager after login
Function HideServerManagerOnLogin {
	Write-Output "Hiding Server Manager after login..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" "DoNotOpenAtLogon" "DWord" 1
}

# Hide Server Manager after login
Function ShowServerManagerOnLogin {
	Write-Output "Showing Server Manager after login..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" "DoNotOpenAtLogon"
}

# Disable Shutdown Event Tracker
Function DisableShutdownTracker {
	Write-Output "Disabling Shutdown Event Tracker..."
	SetRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" "ShutdownReasonOn" "DWord" 0
}

# Enable Shutdown Event Tracker
Function EnableShutdownTracker {
	Write-Output "Enabling Shutdown Event Tracker..."
	DeleteRegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" "ShutdownReasonOn"
}

# Disable password complexity and maximum age requirements
Function DisablePasswordPolicy {
	Write-Output "Disabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile -ErrorAction SilentlyContinue
}

# Enable password complexity and maximum age requirements
Function EnablePasswordPolicy {
	Write-Output "Enabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile -ErrorAction SilentlyContinue
}

# Disable Ctrl+Alt+Del requirement before login
Function DisableCtrlAltDelLogin {
	Write-Output "Disabling Ctrl+Alt+Del requirement before login..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" "DWord" 1
}

# Enable Ctrl+Alt+Del requirement before login
Function EnableCtrlAltDelLogin {
	Write-Output "Enabling Ctrl+Alt+Del requirement before login..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" "DWord" 0
}

#Set server manager not to start
Function DisableSMLogonStart {
	Write-Output "Set server manager not to start..."
  SetRegistryKey "HKCU:\Software\Microsoft\ServerManager" "DoNotOpenServerManagerAtLogon" "DWord" “0x1”
}


###############################################################################
### Internet Explorer                                                         #
###############################################################################

# Disable Internet Explorer Enhanced Security Configuration (IE ESC)
Function DisableIEEnhancedSecurity {
	Write-Output "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" "IsInstalled" "DWord" 0
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" "IsInstalled" "DWord" 0
}

# Enable Internet Explorer Enhanced Security Configuration (IE ESC)
Function EnableIEEnhancedSecurity {
	Write-Output "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" "IsInstalled" "DWord" 1
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" "IsInstalled" "DWord" 1
}

Function ConfigInternetExplorer {
	Write-Output "Configuring Internet Explorer..."

	# Set home page to `about:blank` for faster loading
	SetRegistryKey "HKCU:\Software\Microsoft\Internet Explorer\Main" "Start Page" "String" "about:blank"

	# Disable 'Default Browser' check: "yes" or "no"
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" "Check_Associations" "String" "no"

	# Disable Password Caching [Disable Remember Password]
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "DisablePasswordCaching" "DWord" 1

}

###############################################################################
### Accessibility and Ease of Use                                             #
###############################################################################

Function ConfigAccessibility{
	Write-Host "Configuring Accessibility..."

	# Turn Off Windows Narrator
	SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe" "Debugger" "String" "%1"

	# Disable "Window Snap" Automatic Window Arrangement
	SetRegistryKey "HKCU:\Control Panel\Desktop" "WindowArrangementActive" "DWord" 0

	# Disable automatic fill to space on Window Snap
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapFill" "DWord" 0

	# Disable showing what can be snapped next to a window
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapAssist" "DWord" 0

	# Disable automatic resize of adjacent windows on snap
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "JointResize" "DWord" 0

	# Disable auto-correct
	SetRegistryKey "HKCU:\SOFTWARE\Microsoft\TabletTip\1.7" "EnableAutocorrection" "DWord" 0

}

###############################################################################
### Unpinning Shortcuts                                                       #
###############################################################################

# Unpin all Start Menu tiles - Not applicable to Server - Note: This function has no counterpart. You have to pin the tiles back manually.
Function UnpinStartMenuTiles {
	Write-Output "Unpinning all Start Menu tiles..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
		$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" "Data").Data -Join ","
		$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
		SetRegistryKey "$($_.PsPath)\Current" "Data" "Binary" $data.Split(",")
	}
}

# Unpin all Taskbar icons - Note: This function has no counterpart. You have to pin the icons back manually.
Function UnpinTaskbarIcons {
	Write-Output "Unpinning all Taskbar icons..."
	SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" "Favorites" "Binary" ([byte[]](0xFF))
	DeleteRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" "FavoritesResolve"
}


###############################################################################
### Disk Cleanup (CleanMgr.exe)                                               #
###############################################################################

Function SetDiskCleanup {
	Write-Output "Configuring Disk Cleanup..."

	$diskCleanupRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"

	# Cleanup Files by Group: 0=Disabled, 2=Enabled
	SetRegistryKey $(Join-Path $diskCleanupRegPath "BranchCache"                                  ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Downloaded Program Files"                     ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Internet Cache Files"                         ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Offline Pages Files"                          ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Old ChkDsk Files"                             ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Previous Installations"                       ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Recycle Bin"                                  ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "RetailDemo Offline Content"                   ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Service Pack Cleanup"                         ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Setup Log Files"                              ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "System error memory dump files"               ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "System error minidump files"                  ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Temporary Files"                              ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Temporary Setup Files"                        ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Thumbnail Cache"                              ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Update Cleanup"                               ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Upgrade Discarded Files"                      ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "User file versions"                           ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows Defender"                             ) "StateFlags6174" "DWord" 2
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows Error Reporting Archive Files"        ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows Error Reporting Queue Files"          ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows Error Reporting System Archive Files" ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows Error Reporting System Queue Files"   ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows Error Reporting Temp Files"           ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows ESD installation files"               ) "StateFlags6174" "DWord" 0
	SetRegistryKey $(Join-Path $diskCleanupRegPath "Windows Upgrade Log Files"                    ) "StateFlags6174" "DWord" 0

	Remove-Variable diskCleanupRegPath

}


###############################################################################
### PowerShell Console                                                        #
###############################################################################
Function ConfigurePowershellConsole {
  Write-Output "Configuring PowerShell Console..."

  # Make 'Source Code Pro' an available Console font
  SetRegistryKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\TrueTypeFont" "000" "String" "Source Code Pro"

  # PSReadLine: Normal syntax color. vim Normal group. (Default: Foreground)
  SetRegistryKey "HKCU:\Console\PSReadLine" "NormalForeground" "DWord" 0xF

  # PSReadLine: Comment Token syntax color. vim Comment group. (Default: 0x2)
  SetRegistryKey "HKCU:\Console\PSReadLine" "CommentForeground" "DWord" 0x7

  # PSReadLine: Keyword Token syntax color. vim Statement group. (Default: 0xA)
  SetRegistryKey "HKCU:\Console\PSReadLine" "KeywordForeground" "DWord" 0x1

  # PSReadLine: String Token syntax color. vim String [or Constant] group. (Default: 0x3)
  SetRegistryKey "HKCU:\Console\PSReadLine" "StringForeground"  "DWord" 0xA

  # PSReadLine: Operator Token syntax color. vim Operator [or Statement] group. (Default: 0x8)
  SetRegistryKey "HKCU:\Console\PSReadLine" "OperatorForeground" "DWord" 0xB

  # PSReadLine: Variable Token syntax color. vim Identifier group. (Default: 0xA)
  SetRegistryKey "HKCU:\Console\PSReadLine" "VariableForeground" "DWord" 0xB

  # PSReadLine: Command Token syntax color. vim Function [or Identifier] group. (Default: 0xE)
  SetRegistryKey "HKCU:\Console\PSReadLine" "CommandForeground" "DWord" 0x1

  # PSReadLine: Parameter Token syntax color. vim Normal group. (Default: 0x8)
  SetRegistryKey "HKCU:\Console\PSReadLine" "ParameterForeground" "DWord" 0xF

  # PSReadLine: Type Token syntax color. vim Type group. (Default: 0x7)
  SetRegistryKey "HKCU:\Console\PSReadLine" "TypeForeground" "DWord" 0xE

  # PSReadLine: Number Token syntax color. vim Number [or Constant] group. (Default: 0xF)
  SetRegistryKey "HKCU:\Console\PSReadLine" "NumberForeground" "DWord" 0xC

  # PSReadLine: Member Token syntax color. vim Function [or Identifier] group. (Default: 0x7)
  SetRegistryKey "HKCU:\Console\PSReadLine" "MemberForeground" "DWord" 0xE

  # PSReadLine: Emphasis syntax color. vim Search group. (Default: 0xB)
  SetRegistryKey "HKCU:\Console\PSReadLine" "EmphasisForeground" "DWord" 0xD

  # PSReadLine: Error syntax color. vim Error group. (Default: 0xC)
  SetRegistryKey "HKCU:\Console\PSReadLine" "ErrorForeground" "DWord" 0x4

  @(`
  "HKCU:\Console\%SystemRoot%_System32_bash.exe",`
  "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe",`
  "HKCU:\Console\%SystemRoot%_SysWOW64_WindowsPowerShell_v1.0_powershell.exe",`
  "HKCU:\Console\Windows PowerShell (x86)",`
  "HKCU:\Console\Windows PowerShell",`
  "HKCU:\Console"`
  ) | ForEach {
    If (!(Test-Path $_)) {
        New-Item -path $_ -ItemType Folder | Out-Null
    }

    # Dimensions of window, in characters: 8-byte; 4b height, 4b width. Max: 0x7FFF7FFF (32767h x 32767w)
    SetRegistryKey $_ "WindowSize"           "DWord" 0x002D0078 # 45h x 120w
    # Dimensions of screen buffer in memory, in characters: 8-byte; 4b height, 4b width. Max: 0x7FFF7FFF (32767h x 32767w)
    SetRegistryKey $_ "ScreenBufferSize"     "DWord" 0x0BB80078 # 3000h x 120w
    # Percentage of Character Space for Cursor: 25: Small, 50: Medium, 100: Large
    SetRegistryKey $_ "CursorSize"           "DWord" 100
    # Name of display font
    SetRegistryKey $_ "FaceName"             "String" "Source Code Pro"
    # Font Family: Raster: 0, TrueType: 54
    SetRegistryKey $_ "FontFamily"           "DWord" 54
    # Dimensions of font character in pixels, not Points: 8-byte; 4b height, 4b width. 0: Auto
    SetRegistryKey $_ "FontSize"             "DWord" 0x00110000 # 17px height x auto width
    # Boldness of font: Raster=(Normal: 0, Bold: 1), TrueType=(100-900, Normal: 400)
    SetRegistryKey $_ "FontWeight"           "DWord" 400
    # Number of commands in history buffer
    SetRegistryKey $_ "HistoryBufferSize"    "DWord" 50
    # Discard duplicate commands
    SetRegistryKey $_ "HistoryNoDup"         "DWord" 1
    # Typing Mode: Overtype: 0, Insert: 1
    SetRegistryKey $_ "InsertMode"           "DWord" 1
    # Enable Copy/Paste using Mouse
    SetRegistryKey $_ "QuickEdit"            "DWord" 1
    # Adjust opacity between 30% and 100%: 0x4C to 0xFF -or- 76 to 255
    SetRegistryKey $_ "WindowAlpha"          "DWord" 0xF2


    # The 16 colors in the Console color well (Persisted values are in BGR).
    # Theme: Solarized
    #
    #| SOLARIZED | HEX     | ANSI      | TERMCOL   | cmd.exe     | PowerShell  | ColorTable | DWORD    |
    #|-----------|---------|-----------|-----------|-------------|-------------|------------|----------|
    #| base03    | #002b36 | ESC[0;30m | brblack   | Black       | Black       | 00         | 00362b00 |
    #| base02    | #073642 | ESC[1;30m | black     | Gray        | DarkGray    | 08         | 00423607 |
    #| base01    | #586e75 | ESC[0;32m | brgreen   | Green       | DarkGreen   | 02         | 00756e58 |
    #| base00    | #657b83 | ESC[0;33m | bryellow  | Yellow      | DarkYellow  | 06         | 00837b65 |
    #| base0     | #839496 | ESC[0;34m | brblue    | Blue        | DarkBlue    | 01         | 00969483 |
    #| base1     | #93a1a1 | ESC[0;36m | brcyan    | Aqua        | DarkCyan    | 03         | 00a1a193 |
    #| base2     | #eee8d5 | ESC[0;37m | white     | White       | Gray        | 07         | 00d5e8ee |
    #| base3     | #fdf6e3 | ESC[1;37m | brwhite   | BrightWhite | White       | 15         | 00e3f6fd |
    #| yellow    | #b58900 | ESC[1;33m | yellow    | LightYellow | Yellow      | 14         | 000089b5 |
    #| orange    | #cb4b16 | ESC[0;31m | brred     | Red         | DarkRed     | 04         | 00164bcb |
    #| red       | #dc322f | ESC[1;31m | red       | LightRed    | Red         | 12         | 002f32dc |
    #| magenta   | #d33682 | ESC[1;35m | magenta   | LightPurple | Magenta     | 13         | 008236d3 |
    #| violet    | #6c71c4 | ESC[0;35m | brmagenta | Purple      | DarkMagenta | 05         | 00c4716c |
    #| blue      | #268bd2 | ESC[1;34m | blue      | LightBlue   | Blue        | 09         | 00d28b26 |
    #| cyan      | #2aa198 | ESC[1;36m | cyan      | LightAqua   | Cyan        | 11         | 0098a12a |
    #| green     | #859900 | ESC[1;32m | green     | LightGreen  | Green       | 10         | 00009985 |
    #

 
    SetRegistryKey $_ "ColorTable00" "DWord" "0x00362b00" # Black (0)
    SetRegistryKey $_ "ColorTable01" "DWord" " 0x0 0 4 2 3 6 0 7 " # DarkBlue (1)
    SetRegistryKey $_ "ColorTable02" "DWord" "0x00756e58" # DarkGreen (2)
    SetRegistryKey $_ "ColorTable03" "DWord" " 0x0 0 8 3 7 b 6 5 " # DarkCyan (3)
    SetRegistryKey $_ "ColorTable04" "DWord" " 0x0 0 2 f 3 2 d c " # DarkRed (4)
    SetRegistryKey $_ "ColorTable05" "DWord" " 0x0 0 c 4 7 1 6 c " # DarkMagenta (5)
    SetRegistryKey $_ "ColorTable06" "DWord" " 0x0 0 1 6 4 b c b " # DarkYellow (6)
    SetRegistryKey $_ "ColorTable07" "DWord" "0x00d5e8ee" # Gray (7)
    SetRegistryKey $_ "ColorTable08" "DWord" " 0x0 0 a 1 a 1 9 3 " # DarkGray (8)
    SetRegistryKey $_ "ColorTable09" "DWord" "0x00d28b26" # Blue (9)
    SetRegistryKey $_ "ColorTable10" "DWord" "0x00009985" # Green (A)
    SetRegistryKey $_ "ColorTable11" "DWord" "0x0098a12a" # Cyan (B)
    SetRegistryKey $_ "ColorTable12" "DWord" " 0x0 0 9 6 9 4 8 3 " # Red (C)
    SetRegistryKey $_ "ColorTable13" "DWord" "0x008236d3" # Magenta (D)
    SetRegistryKey $_ "ColorTable14" "DWord" "0x000089b5" # Yellow (E)
    SetRegistryKey $_ "ColorTable15" "DWord" "0x00e3f6fd" # White (F)
    # Background and Foreground Colors for Window: 2-byte; 1b background, 1b foreground; Color: 0-F
    SetRegistryKey $_ "ScreenColors" "DWord" "00000001"
    # Background and Foreground Colors for Popup Window: 2-byte; 1b background, 1b foreground; Color: 0-F
    SetRegistryKey $_ "PopupColors" "DWord" "000000f6"
  }

  # Remove property overrides from PowerShell and Bash shortcuts
  Reset-AllPowerShellShortcuts
  Reset-AllBashShortcuts
}

###############################################################################
### Logs                                                                      #
###############################################################################

Function EnableSRPLogs {
  SetRegistryKey "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" "LogFileName" "String" "c:\Logs\SRPLog.txt"
}

Function DisableSRPLogs {

  DeleteRegistryKey "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" "LogFileName"

}

###############################################################################
### Usability Tweaks                                                          #
###############################################################################

Function SetUserTweaks {

  If (!(Test-Path "HKCR:")) {
    New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
  }

  # Adds "Copy To" and "Move To" options in files and folders context menu
  SetRegistryKey "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" "(Default)" "String" "{C2FBB630-2971-11D1-A18C-00C04FD75D13}"
  SetRegistryKey "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" "(Default)" "String" "{C2FBB631-2971-11D1-A18C-00C04FD75D13}"
  # Forces Windows to automatically end user services when the user logs off or shuts down the computer.
  # It'll prevent the "Closing apps and shutting down, This app is preventing shutdown" screen from appearing.
  SetRegistryKey "HKCU:\Control Panel\Desktop" "AutoEndTasks" "String" 1
  # Reduces system waiting time before killing user processes when the user clicks on "End Task" button in Task Manager.
  SetRegistryKey "HKCU:\Control Panel\Desktop" "HungAppTimeout" "String" "1000"
  # Decreases menus show delay time, it'll make the menus show faster upon clicking.
  SetRegistryKey "HKCU:\Control Panel\Desktop" "MenuShowDelay" "String" 8
  # Reduces system waiting time before killing user processes when the user logs off or shuts down the computer.
  SetRegistryKey "HKCU:\Control Panel\Desktop" "WaitToKillAppTimeout" "String" "2000"
  # Reduces system waiting time before killing not responding services.
  SetRegistryKey "HKCU:\Control Panel\Desktop" "LowLevelHooksTimeout" "String" "1000"
  # Reduces popup delay time to show popup description faster when you move mouse cursor over an item.
  SetRegistryKey "HKCU:\Control Panel\Mouse" "MouseHoverTime" "String" "8"

  # Prevents Windows from wasting time in searching for a program which no longer exists in your system when you try to open its shortcut.
  SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "LinkResolveIgnoreLinkInfo" "Dword" "00000001"
  # Prevents Windows from searching for the disk drive to resolve a shortcut.
  SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoResolveSearch" "Dword" "00000001"
  # Prevents Windows from using NTFS file system's tracking feature to resolve a shortcut.
  SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoResolveTrack" "Dword" "00000001"
  # Disables "Search on Internet" prompt in "Open with" window so that you can directly see available programs list.
  SetRegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInternetOpenWith" "Dword" "00000001"
  # Reduces system waiting time before stopping services when the services are notified about shut down process.
  SetRegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control" "WaitToKillServiceTimeout" "String" "2000"

}

###############################################################################
### Auxiliary Functions                                                       #
###############################################################################

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

# Wait for key press
Function WaitForKey {
	Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}

###############################################################################
### Parse parameters and apply tweaks                                         #
###############################################################################

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }
