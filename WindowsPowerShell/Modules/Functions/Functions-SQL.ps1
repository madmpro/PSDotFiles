###############################################################################
### SQL Server Functions                                                      #
###############################################################################


Function Execute-Sql($sql, $username, $password, $file) {
	Write-Host -ForegroundColor Cyan "Executing $file on $sql with user $username"
	& sqlcmd -S $sql -U $username -P $password -i $file
}

Function Execute-SqlDir($sql, $username, $password, $dir) {
	Get-ChildItem $dir | Select-Object FullName | foreach {
		Write-Host -ForegroundColor Cyan "Executing $_.FullName on $sql with user $username"
		Execute-Sql $sql $username $password $_.FullName
	}
}
