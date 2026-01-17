$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Clean up extracted files
Remove-Item "$toolsDir\newrelic-cli.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "$toolsDir\LICENSE" -Force -ErrorAction SilentlyContinue
Remove-Item "$toolsDir\README.md" -Force -ErrorAction SilentlyContinue
Remove-Item "$toolsDir\LICENSE.ignore" -Force -ErrorAction SilentlyContinue
Remove-Item "$toolsDir\README.md.ignore" -Force -ErrorAction SilentlyContinue

Write-Host "newrelic-cli has been uninstalled."
