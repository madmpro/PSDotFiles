# Poershell Tips

## Console History

``` ps1
Get-Content $(Join-Path $env:appdata\Microsoft\Windows\PowerShell\PSReadline "ConsoleHost_history.txt")
```
