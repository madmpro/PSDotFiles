###############################################################################
### IIS Functions                                                             #
###############################################################################

function Test-WebAppPool($Name) {
	return Test-Path "IIS:\AppPools\$Name"
}

function Get-WebAppPool($Name) {
	return Get-Item "IIS:\AppPools\$Name"
}

function Add-WebAppPool($Name, $Identity = "NetworkService", $RuntimeVersion = "v4.0", $PipelineMode = "Integrated") {
	if (Test-WebAppPool $Name) {
		Write-Host -ForegroundColor Cyan "Application pool $Name already exists"
	}
	else {
		Write-Host -ForegroundColor Green "Creating application poool $Name"

		$appPool = New-WebAppPool -Name $Name
		$appPool.managedRuntimeVersion = $RuntimeVersion
		$appPool.managedPipelineMode = $PipelineMode
		$appPool.processModel.identityType = $Identity

		$appPool | Set-Item
	}
}

function Test-Website($Name) {
	return Test-Path "IIS:\Sites\$Name"
}

function Get-Website($Name) {
	return Get-Item "IIS:\Sites\$Name"
}

function Add-Website($Name, $PhysicalPath, $ApplicationPool = "DefaultAppPool", $Port = 80) {
	if (Test-Website $Name) {
		$webSite = Write-Host -ForegroundColor Cyan "Web site $Name already exists"
	}
	else {
		Write-Host -ForegroundColor Green "Creating web site $Name"

		$webSite = New-Website -Name $Name -PhysicalPath $PhysicalPath -ApplicationPool $ApplicationPool -Port $Port
		$webSite.serverAutoStart = $true

		$webSite | Set-Item
	}
}

function Test-WebApplication($Site, $Name) {
	return Test-Path "IIS:\Sites\$Site\$Name"
}

function Get-WebApplication($Site, $Name) {
	return Get-Item "IIS:\Sites\$Site\$Name"
}

function Add-WebApplication($Site, $Name, $PhysicalPath, $ApplicationPool = "DefaultAppPool") {
	if (Test-WebApplication $Site $Name) {
		Write-Host -ForegroundColor Cyan "Web application $Name already exists"
	}
	else {
		Write-Host -ForegroundColor Green "Creating web application $Name"
		$webApp = New-WebApplication -Site $Site -Name $Name -PhysicalPath $PhysicalPath -ApplicationPool $ApplicationPool
	}
}

function Test-WebVirtualDirectory($Site, $Name) {
	return Test-Path "IIS:\Sites\$Site\$Name"
}

function Get-WebVirtualDirectory($Site, $Name) {
	return Get-Item "IIS:\Sites\$Site\$Name"
}

function Add-WebVirtualDirectory($Site, $Name, $PhysicalPath, $Application = $null) {
	if (Test-WebVirtualDirectory $Site $Name) {
		Write-Host -ForegroundColor Cyan "Web virtual directory $Name already exists"
	}
	else {
		Write-Host -ForegroundColor Green "Creating web virtual directory $Name"
		$webDir = New-WebVirtualDirectory -Site $Site -Name $Name -PhysicalPath $PhysicalPath -Application $Application
	}
}
