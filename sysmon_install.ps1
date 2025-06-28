# Check for Administrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator. Exiting."
    Exit
}

# Variables
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$env:TEMP\\Sysmon.zip"
$sysmonFolder = "$env:TEMP\\Sysmon"
$sysmonExePath = "$sysmonFolder\\Sysmon64.exe"

# Create folder if not exists
If (-Not (Test-Path $sysmonFolder)) {
    New-Item -ItemType Directory -Path $sysmonFolder | Out-Null
}

# Download Sysmon
Write-Host "Downloading Sysmon..."
Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip

# Extract Sysmon
Write-Host "Extracting Sysmon..."
Expand-Archive -Path $sysmonZip -DestinationPath $sysmonFolder -Force

# Prompt user for Sysmon config
Write-Host "Please select your Sysmon config XML file."
$configPath = (Get-Item (Read-Host "Enter full path to your Sysmon config XML")).FullName

If (-Not (Test-Path $configPath)) {
    Write-Error "Sysmon configuration file not found. Exiting."
    Exit
}

# Install Sysmon with config
Write-Host "Installing Sysmon with the selected configuration..."
& $sysmonExePath -accepteula -i $configPath

Write-Host "Sysmon installed successfully and configured with your file."
