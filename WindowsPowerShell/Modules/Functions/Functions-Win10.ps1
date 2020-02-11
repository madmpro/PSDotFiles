###############################################################################
## Windows 10 only
###############################################################################

Function Get-RemoveBloatware {
  Get-AppxPackage -allusers | Remove-AppxPackage
}
