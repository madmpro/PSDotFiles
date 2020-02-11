###############################################################################
### Domain Controller Functions                                               #
###############################################################################

Function Check-IsDomainController
{
    [int]$gCIMi = ((Get-CimInstance -ClassName 'Win32_ComputerSystem' -Property 'DomainRole' -ErrorAction SilentlyContinue).DomainRole)
    If (($gCIMi -eq 4) -or ($gCIMi -eq 5)) { Return $true }
    Return $false
}


Function Remove-DeletedADObject
{
Get-ADObject -filter {sAMAccountName -eq "$args[0]\$"} -includeDeletedObjects -property * | Remove-ADObject

}
