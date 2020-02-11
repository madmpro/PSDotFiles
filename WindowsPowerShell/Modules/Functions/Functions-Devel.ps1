###############################################################################
### Development Functions                                                     #
###############################################################################

Function Show-DevToolsVersions {
    $cpus = Get-CimInstance -ClassName Win32_processor | Select systemname, Name, DeviceID, NumberOfCores, NumberOfLogicalProcessors, Addresswidth
    $ram = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB), 2))}

    Write-Host "Hostname: $($cpus.systemname)"
    Write-Host "Cores: $($cpus.Name)"
    Write-Host "Physical: $($cpus.NumberOfCores) || Logical: $($cpus.NumberOfLogicalProcessors)"
    Write-Host "RAM: $($ram)"
    Write-Host "Windows: $([System.Environment]::OSVersion.Version) x$($cpus.Addresswidth)"
    Write-Host "PS: $($PSVersionTable.PSVersion)" -ForegroundColor Blue
    if ((which vagrant) -ne $null) {
      Write-Host "Vagrant: $(vagrant --version)" -ForegroundColor Blue
    }
    if ((which docker) -ne $null) {
      Write-Host "Docker: $(docker -v)" -ForegroundColor Cyan
    }
    if ((which docker-compose) -ne $null) {
      Write-Host "Docker-Compose: $(docker-compose -v)" -ForegroundColor Cyan
    }
    if ((which node) -ne $null) {
      Write-Host "Node: $(node -v)" -ForegroundColor Green
    }
    if ((which npm) -ne $null) {
      Write-Host "NPM: $(npm -v)" -ForegroundColor Red
    }
    if ((which dotnet) -ne $null) {
      Write-Host "DotNet Core: $(dotnet --version)" -ForegroundColor Magenta
    }
    if ((which bash) -ne $null) {
      $ubuntuVersion = $([regex] '^(Description\:\t)').Split($(bash -c 'lsb_release -d'))[2]
      Write-Host "Ubuntu (WSL): $($ubuntuVersion)" -ForegroundColor Yellow
    }

}
