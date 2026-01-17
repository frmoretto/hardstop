$dest = Join-Path $env:USERPROFILE '.claude\plugins\hardstop-plugin'
Write-Host "Installing to: $dest"
if (-not (Test-Path $dest)) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
}
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item -Path "$source\*" -Destination $dest -Recurse -Force -Exclude '.venv','.git','.pytest_cache','install.ps1'
Write-Host "Hardstop plugin installed successfully!"
