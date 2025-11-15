# Base folder for tools
$basePath = "C:\tools\NirsoftTools"

# Create folder if missing
if (!(Test-Path $basePath)) {
    New-Item -ItemType Directory -Path $basePath | Out-Null
}

# List of Nirsoft Tool URLs (ZIP direct download links)
$nirsoftTools = @{
    "OpenedFilesView"     = "https://www.nirsoft.net/utils/ofview-x64-187.zip"
    "FileActivityWatch"   = "https://www.nirsoft.net/utils/fileactivitywatch.zip"
    "FolderChangesView"   = "https://www.nirsoft.net/utils/folderchangesview.zip"
    "RecentFilesView"     = "https://www.nirsoft.net/utils/recentfilesview.zip"
    "UserAssistView"      = "https://www.nirsoft.net/utils/userassistview.zip"
    "WinPrefetchView"     = "https://www.nirsoft.net/utils/winprefetchview.zip"
}

# Malzilla URL
$malzillaUrl = "https://excellmedia.dl.sourceforge.net/project/malzilla/Malzilla%20Win32%20Binary%20package/Malzilla%201.2.0/malzilla_1.2.0.zip?viasf=1"
$malzillaZip = "$basePath\malzilla.zip"

Write-Host "`nDownloading Nirsoft tools..." -ForegroundColor Cyan

foreach ($tool in $nirsoftTools.GetEnumerator()) {
    $zipFile = "$basePath\$($tool.Key).zip"
    Write-Host "Downloading $($tool.Key)..."
    try {
        Invoke-WebRequest -Uri $tool.Value -OutFile $zipFile -UseBasicParsing -ErrorAction Stop
        Write-Host "Extracting $($tool.Key)..."
        Expand-Archive -Path $zipFile -DestinationPath "$basePath\$($tool.Key)" -Force
        Remove-Item $zipFile
    } catch {
        Write-Host "❌ Failed to download $($tool.Key) from $($tool.Value)" -ForegroundColor Red
    }
}

Write-Host "`nDownloading Malzilla..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $malzillaUrl -OutFile $malzillaZip -UseBasicParsing
Write-Host "Extracting Malzilla..."
Expand-Archive -Path $malzillaZip -DestinationPath "$basePath\Malzilla" -Force
Remove-Item $malzillaZip

Write-Host "`n✔ All tools downloaded and extracted successfully!" -ForegroundColor Green
Write-Host "📂 Folder: C:\tools\NirsoftTools"
