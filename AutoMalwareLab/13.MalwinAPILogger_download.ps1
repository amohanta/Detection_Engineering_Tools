# =====================================================================
# OPTIMIZED: MalwinAPILogger Download
# - Parallel downloads using WebClient
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# ===================== Configuration =====================
$destDir = "C:\tools\malWinAPILogger"

$files = @(
    @{ Name = "APIHook_x64.dll"; Url = "https://raw.githubusercontent.com/amohanta/Detection_Engineering_Tools/refs/heads/main/Mal_Win_API_Logger/APIHook_x64.dll"; Path = "$destDir\APIHook_x64.dll" }
    @{ Name = "APIHook_x86.dll"; Url = "https://raw.githubusercontent.com/amohanta/Detection_Engineering_Tools/refs/heads/main/Mal_Win_API_Logger/APIHook_x86.dll"; Path = "$destDir\APIHook_x86.dll" }
    @{ Name = "Mal_Win_API_Logger_x64.exe"; Url = "https://raw.githubusercontent.com/amohanta/Detection_Engineering_Tools/refs/heads/main/Mal_Win_API_Logger/Mal_Win_API_Logger_x64.exe"; Path = "$destDir\Mal_Win_API_Logger_x64.exe" }
    @{ Name = "Mal_Win_API_Logger_x86.exe"; Url = "https://raw.githubusercontent.com/amohanta/Detection_Engineering_Tools/refs/heads/main/Mal_Win_API_Logger/Mal_Win_API_Logger_x86.exe"; Path = "$destDir\Mal_Win_API_Logger_x86.exe" }
)

# ===================== Main Script =====================
$timer = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " MalwinAPILogger Download (Optimized)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Create directory
New-Item -Path $destDir -ItemType Directory -Force | Out-Null

# Parallel downloads
Write-Host "`n[DOWNLOAD] Starting $($files.Count) parallel downloads..." -ForegroundColor Cyan

$jobs = @()
foreach ($file in $files) {
    $jobs += Start-Job -ScriptBlock {
        param($url, $path)
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($url, $path)
            return @{ Success = $true; Name = (Split-Path $path -Leaf) }
        } catch {
            return @{ Success = $false; Name = (Split-Path $path -Leaf); Error = $_.Exception.Message }
        }
    } -ArgumentList $file.Url, $file.Path
    Write-Host "  Started: $($file.Name)" -ForegroundColor Gray
}

# Wait for all downloads
while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
    $completed = ($jobs | Where-Object { $_.State -eq 'Completed' }).Count
    Write-Host "`r  Progress: $completed/$($jobs.Count) complete    " -NoNewline -ForegroundColor Yellow
    Start-Sleep -Milliseconds 200
}
Write-Host ""

# Get results
$results = $jobs | Receive-Job -Wait
$jobs | Remove-Job -Force

foreach ($result in $results) {
    if ($result.Success) {
        Write-Host "  OK: $($result.Name)" -ForegroundColor Green
    } else {
        Write-Host "  FAILED: $($result.Name)" -ForegroundColor Red
    }
}

# Summary
$timer.Stop()

Write-Host "`n=============================================" -ForegroundColor Green
Write-Host " Complete! Time: $([math]::Round($timer.Elapsed.TotalSeconds, 1))s" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  Files downloaded to: $destDir"
