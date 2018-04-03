# By default, the Registry provider creates two registry drives.
# To find all of the drives that are exposed by the Registry provider, use the Get-PSDrive cmdlet.
# These drives are shown here.
# PS C:\> Get-PSDrive -PSProvider registry | select name, root
# Name                                       Root
# ----                                       ----
# HKCU                                       HKEY_CURRENT_USER
# HKLM                                       HKEY_LOCAL_MACHINE
# Additional registry drives are created by using the New-PSDrive cmdlet.
# For example, it is common to create a registry drive for the HKEY_CLASSES_ROOT registry hive.
# The code to do this is shown here.
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
