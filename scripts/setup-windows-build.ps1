# Windows Build Setup Script for ptp-trace
# This script sets up the Windows build environment for libpcap/Npcap

param(
    [string]$NpcapVersion = "1.79",
    [string]$NpcapSdkVersion = "1.13",
    [string]$InstallPath = "C:\npcap-sdk"
)

Write-Host "Setting up Windows build environment for ptp-trace..." -ForegroundColor Green

# Create installation directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "Created directory: $InstallPath" -ForegroundColor Blue
}

# Download and install Npcap runtime (if not already installed)
$npcapInstaller = "npcap-$NpcapVersion.exe"
$npcapUrl = "https://npcap.com/dist/$npcapInstaller"

if (!(Get-Service -Name npcap -ErrorAction SilentlyContinue)) {
    Write-Host "Downloading Npcap runtime..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller -UseBasicParsing
        Write-Host "Installing Npcap runtime (requires admin privileges)..." -ForegroundColor Yellow
        Start-Process -FilePath ".\$npcapInstaller" -ArgumentList "/S" -Wait -Verb RunAs
        Remove-Item $npcapInstaller -Force
        Write-Host "Npcap runtime installed successfully" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to download/install Npcap runtime: $($_.Exception.Message)"
        Write-Host "Please manually download and install Npcap from: https://npcap.com/" -ForegroundColor Red
    }
} else {
    Write-Host "Npcap runtime is already installed" -ForegroundColor Green
}

# Download and extract Npcap SDK
$npcapSdk = "npcap-sdk-$NpcapSdkVersion.zip"
$npcapSdkUrl = "https://npcap.com/dist/$npcapSdk"

Write-Host "Downloading Npcap SDK..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $npcapSdkUrl -OutFile $npcapSdk -UseBasicParsing
    Write-Host "Extracting Npcap SDK to $InstallPath..." -ForegroundColor Yellow
    Expand-Archive -Path $npcapSdk -DestinationPath $InstallPath -Force
    Remove-Item $npcapSdk -Force
    Write-Host "Npcap SDK installed successfully" -ForegroundColor Green
} catch {
    Write-Warning "Failed to download/extract Npcap SDK: $($_.Exception.Message)"
    Write-Host "Please manually download the SDK from: https://npcap.com/" -ForegroundColor Red
    exit 1
}

# Set up environment variables for the current session
$libPath = "$InstallPath\Lib\x64"
if (Test-Path $libPath) {
    $env:LIB = "$libPath;$env:LIB"
    $env:LIBPCAP_LIBDIR = $libPath
    Write-Host "Environment variables set:" -ForegroundColor Green
    Write-Host "  LIB = $env:LIB" -ForegroundColor Blue
    Write-Host "  LIBPCAP_LIBDIR = $env:LIBPCAP_LIBDIR" -ForegroundColor Blue
} else {
    Write-Warning "Library path not found: $libPath"
}

# Verify installation
Write-Host "`nVerifying installation..." -ForegroundColor Yellow
$wpcapLib = Get-ChildItem -Path $InstallPath -Recurse -Name "wpcap.lib" -ErrorAction SilentlyContinue
$packetLib = Get-ChildItem -Path $InstallPath -Recurse -Name "Packet.lib" -ErrorAction SilentlyContinue

if ($wpcapLib -and $packetLib) {
    Write-Host "✓ Found required libraries:" -ForegroundColor Green
    Write-Host "  - wpcap.lib" -ForegroundColor Blue
    Write-Host "  - Packet.lib" -ForegroundColor Blue
} else {
    Write-Warning "Some required libraries may be missing"
}

Write-Host "`nBuild environment setup complete!" -ForegroundColor Green
Write-Host "You can now build ptp-trace with: cargo build --release" -ForegroundColor Blue

# Instructions for permanent environment variables
Write-Host "`nTo make environment variables permanent, run:" -ForegroundColor Yellow
Write-Host "setx LIB `"$libPath;%LIB%`"" -ForegroundColor Cyan
Write-Host "setx LIBPCAP_LIBDIR `"$libPath`"" -ForegroundColor Cyan
