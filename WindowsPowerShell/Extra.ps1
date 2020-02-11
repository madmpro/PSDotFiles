###############################################################################
# Git credentials
###############################################################################

# Git credentials
Set-Environment "EMAIL" "Igor Frunze <madm.pro@gmail.com>"
Set-Environment "GIT_AUTHOR_NAME" "Igor Frunze","User"
Set-Environment "GIT_COMMITTER_NAME" $env:GIT_AUTHOR_NAME
git config --global user.name $env:GIT_AUTHOR_NAME
Set-Environment "GIT_AUTHOR_EMAIL" "madm.pro@gmail.com"
Set-Environment "GIT_COMMITTER_EMAIL" $env:GIT_AUTHOR_EMAIL
git config --global user.email $env:GIT_AUTHOR_EMAIL

###############################################################################
### PowerShell drives                                                         #
###############################################################################

#
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
$projects = $home + "\Projects"
