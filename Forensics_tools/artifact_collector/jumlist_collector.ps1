# Define paths - create folder in current directory
$sourcePath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
$destFolderName = "jumplist_artifact"
$currentDir = Get-Location
$destPath = Join-Path -Path $currentDir -ChildPath $destFolderName

# Create destination folder if it doesn't exist
if (-not (Test-Path $destPath)) {
    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
    Write-Host "Created destination folder: $destPath" -ForegroundColor Green
} else {
    Write-Host "Using existing folder: $destPath" -ForegroundColor Yellow
}

# Embedded CSV data directly in the script
$csvData = @"
Application IDs,12dc1ea8e34b5a6,Microsoft Paint 6.1
Application IDs,17d3eb086439f0d7,TrueCrypt 7.0a
Application IDs,18434d518c3a61eb,Minitab 17
Application IDs,1b4dd67f29cb1962,Windows Explorer Pinned and Recent.
Application IDs,1bc392b8e104a00e,Remote Desktop
Application IDs,23646679aaccfae0,Adobe Reader 9.
Application IDs,23646679aaccfae0,Adobe Reader 9 x64
Application IDs,26717493b25aa6e1,Adobe Dreamweaver CS5 (32-bit)
Application IDs,271e609288e1210a,Microsoft Office Access 2010 x86
Application IDs,28c8b86deab549a1,Internet Explorer 8 / 9 / 10 (32-bit)
Application IDs,290532160612e071,WinRar x64
Application IDs,2b53c4ddf69195fc,Zune x64
Application IDs,3094cdb43bf5e9c2,Microsoft Office OneNote 2010 x86
Application IDs,315e29a36e961336,Roboform 7.8
Application IDs,40f2aca05d8a33f2,Minitab 16
Application IDs,431a5b43435cc60b,Python (.pyc)
Application IDs,43578521d78096c6,Windows Media Player Classic Home Cinema 1.3 (32-bit)
Application IDs,44a3621b32122d64,Microsoft Office Word 2010 x64
Application IDs,44a398496acc926d,Adobe Premiere Pro CS5 (64-bit)
Application IDs,469e4a7982cea4d4,? (.job)
Application IDs,469e4a7982cea4d4,Windows Wordpad
Application IDs,500b8c1d5302fc9c,Python (.pyw)
Application IDs,50620fe75ee0093,VMware Player 3.1.4
Application IDs,550abc1cb58eb92c,VeraCrypt 1.16 / 1.19 64-bit
Application IDs,590aee7bdd69b59b,Powershell Windows 10
Application IDs,5c450709f7ae4396,Firefox 3.6.13 (32-bit)
Application IDs,5d6f13ed567aa2da,Microsoft Office Outlook 2010 x64
Application IDs,5da8f997fd5f9428,Internet Explorer x64
Application IDs,5f6e7bc0fb699772,Microsoft Office PowerPoint 2010 x64
Application IDs,65009083bfa6a094,(app launched via XPMode)
Application IDs,6728dd69a3088f97,Windows Command Processor - cmd.exe (64-bit)
Application IDs,6d2bac8f1edf6668,Microsoft Office Outlook 365
Application IDs,6e855c85de07bc6a,Microsoft Office Excel 2010 x64
Application IDs,74d7f43c1561fc1e,Windows Media Player 12 (32-bit)
Application IDs,7e4dca80246863e3,Control Panel (?)
Application IDs,83b03b46dcd30a0e,iTunes 10
Application IDs,84f066768a22cc4f,Adobe Photoshop CS5 (64-bit)
Application IDs,89b0d939f117f75c,Adobe Acrobat 9 Pro Extended (32-bit)
Application IDs,8eafbd04ec8631ce,VMware Workstation 9 x64
Application IDs,918e0ecb43d17e23,Notepad (32-bit)
Application IDs,954ea5f70258b502,Windows Script Host - wscript.exe (32-bit)
Application IDs,9839aec31243a928,Microsoft Office Excel 2010 x86
Application IDs,9b9cdc69c1c24e2b,Notepad (64-bit)
Application IDs,9c7cc110ff56d1bd,Microsoft Office PowerPoint 2010 x86
Application IDs,9f5c7755804b850a,Windows Script Host - wscript.exe (64-bit)
Application IDs,a18df73203b0340e,Microsoft Word 2016
Application IDs,a4a5324453625195,Microsoft Office Word 2013 x86
Application IDs,a7bd71699cd38d1c,Microsoft Office Word 2010 x86
Application IDs,a8c43ef36da523b1,Microsoft Office Word 2003 Pinned and Recent.
Application IDs,adecfb853d77462a,Microsoft Office Word 2007 Pinned and Recent.
Application IDs,b0459de4674aab56,(.vmcx)
Application IDs,b0459de4674aab56,Windows Virtual PC - vmwindow.exe (32- and 64-bit)
Application IDs,b74736c2bd8cc8a5,WinZip
Application IDs,b8ab77100df80ab2,Microsoft Office Excel x64
Application IDs,b8c29862d9f95832,Microsoft Office InfoPath 2010 x86
Application IDs,b91050d8b077a4e8,Windows Media Center x64
Application IDs,bc03160ee1a59fc1,Foxit PDF Reader 5.4.5
Application IDs,be71009ff8bb02a2,Microsoft Office Outlook x86
Application IDs,c71ef2c372d322d7,PGP Desktop 10
Application IDs,c765823d986857ba,Adobe Illustrator CS5 (32-bit)
Application IDs,c7a4093872176c74,Paint Shop Pro Pinned and Recent.
Application IDs,cdf30b95c55fd785,Microsoft Office Excel 2007
Application IDs,d00655d2aa12ff6d,Microsoft Office PowerPoint x64
Application IDs,d38adec6953449ba,Microsoft Office OneNote 2010 x64
Application IDs,d4a589cab4f573f7,Microsoft Project 2010 x86
Application IDs,d5c3931caad5f793,Adobe Soundbooth CS5 (32-bit)
Application IDs,d64d36b238c843a3,Microsoft Office InfoPath 2010 x86
Application IDs,d7528034b5bd6f28,Windows Live Mail Pinned and Recent.
Application IDs,e2a593822e01aed3,Adobe Flash CS5 (32-bit)
Application IDs,e36bfc8972e5ab1d,XPS Viewer
Application IDs,e70d383b15687e37,Notepad++ 5.6.8 (32-bit)
Application IDs,f01b4d95cf55d32a,Windows Explorer Windows 8.1.
Application IDs,f0275e8685d95486,Microsoft Office Excel 2013 x86
Application IDs,f5ac5390b9115fdb,Microsoft Office PowerPoint 2007
Application IDs,fb3b0dbfee58fac8,Microsoft Office Word 365 x86
File Sharing/P2P,135df2a440abe9bb,SoulSeek 156c
File Sharing/P2P,1434d6d62d64857d,BitLord 1.2.0-66
File Sharing/P2P,223bf0f360c6fea5,I2P 0.8.8 (restartable)
File Sharing/P2P,23f08dab0f6aaf30,SoMud 1.3.3
File Sharing/P2P,2437d4d14b056114,EiskaltDC++ 2.2.3
File Sharing/P2P,2d61cccb4338dfc8,BitTorrent 5.0.0 / 6.0.0 / 7.2.1 (Build 25548)
File Sharing/P2P,2db8e25112ab4453,Deluge 1.3.3
File Sharing/P2P,2ff9dc8fb7e11f39,I2P 0.8.8 (no window)
File Sharing/P2P,3cf13d83b0bd3867,RevConnect 0.674p (based on DC++)
File Sharing/P2P,490c000889535727,WinMX 4.9.3.0
File Sharing/P2P,4a7e4f6a181d3d08,broolzShare
File Sharing/P2P,4aa2a5710da3efe0,DCSharpHub 2.0.0
File Sharing/P2P,4dd48f858b1a6ba7,Free Download Manager 3.0 (Build 852)
File Sharing/P2P,558c5bd9f906860a,BearShare Lite 5.2.5.1
File Sharing/P2P,560d789a6a42ad5a,DC++ 0.261 / 0.698 / 0.782 (r2402.1)
File Sharing/P2P,5b186fc4a0b40504,Dtella 1.2.5 (Purdue network only)
File Sharing/P2P,5d7b4175afdcc260,Shareaza 2.0.0.0
File Sharing/P2P,5e01ecaf82f7d8e,Scour Exchange 0.0.0.228
File Sharing/P2P,5ea2a50c7979fbdc,TrustyFiles 3.1.0.22
File Sharing/P2P,73ce3745a843c0a4,FrostWire 5.1.4
File Sharing/P2P,76f6f1bd18c19698,aMule 2.2.6
File Sharing/P2P,784182360de0c5b6,Kazaa Lite 1.7.1
File Sharing/P2P,792699a1373f1386,Piolet 3.1.1
File Sharing/P2P,7b7f65aaeca20a8c,Dropbox App 5.4.24
File Sharing/P2P,96252daff039437a,Lphant 7.0.0.112351
File Sharing/P2P,977a5d147aa093f4,Lphant 3.51
File Sharing/P2P,98b0ef1c84088,fulDC 6.78
File Sharing/P2P,99c15cf3e6d52b61,mldonkey 3.1.0
File Sharing/P2P,9ad1ec169bf2da7f,FlylinkDC++ r405 (Build 7358)
File Sharing/P2P,a31ec95fdd5f350f,BitComet 0.49 / 0.59 / 0.69 / 0.79 / 0.89 / 0.99 / 1.07 / 1.28
File Sharing/P2P,a746f9625f7695e8,HeXHub 5.07
File Sharing/P2P,a75b276f6e72cf2a,Kazaa Lite Tools K++ 2.7.0
File Sharing/P2P,a75b276f6e72cf2a,WinMX 3.53
File Sharing/P2P,a8df13a46d66f6b5,Kommute (Calypso) 0.24
File Sharing/P2P,ac3a63b839ac9d3a,Vuze 4.6.0.4
File Sharing/P2P,accca100973ef8dc,Azureus 2.0.8.4
File Sharing/P2P,b3016b8da2077262,eMule 0.50a
File Sharing/P2P,b48ce76eda60b97,Shareaza 8.0.0.112300
File Sharing/P2P,ba132e702c0147ef,KCeasy 0.19-rc1
File Sharing/P2P,ba3a45f7fd2583e1,Blubster 3.1.1
File Sharing/P2P,bcd7ba75303acbcf,BitLord 1.1
File Sharing/P2P,bfc1d76f16fa778f,Ares (Galaxy) 1.8.4 / 1.9.8 / 2.1.0 / 2.1.7.3041
File Sharing/P2P,c5ef839d8d1c76f4,LimeWire 5.2.13
"@

# Parse the embedded CSV data
$map = @{}
$stats = @{
    TotalLines = 0
    MappedLines = 0
    DuplicateGUIDs = 0
}

# Split CSV data by lines and process each line
$csvData -split "`n" | ForEach-Object {
    $stats.TotalLines++
    $line = $_.Trim()
    if ($line -match '^([^,]+),([^,]+),([^,]+)$') {
        $appName = $matches[3].Trim()
        $guid = $matches[2].Trim()
        
        # Add to mapping dictionary (use GUID as key, app name as value)
        if (-not $map.ContainsKey($guid)) {
            $map[$guid] = $appName
            $stats.MappedLines++
        } else {
            $stats.DuplicateGUIDs++
            # Note: Some GUIDs map to multiple app names in the CSV
            # We're keeping the first occurrence
        }
    }
}

Write-Host "Loaded $($stats.MappedLines) unique GUID mappings from embedded CSV data." -ForegroundColor Green
Write-Host "Note: $($stats.DuplicateGUIDs) duplicate GUIDs were found in the data." -ForegroundColor Cyan

# Get all jumplist files
$jumplistFiles = Get-ChildItem -Path $sourcePath -Filter "*.automaticDestinations-ms" -ErrorAction SilentlyContinue

if (-not $jumplistFiles) {
    Write-Host "No jumplist files found at $sourcePath" -ForegroundColor Red
    Write-Host "Destination folder: $destPath" -ForegroundColor Yellow
    exit
}

Write-Host "Found $($jumplistFiles.Count) jumplist files." -ForegroundColor Green

$copyStats = @{
    Total = 0
    Mapped = 0
    Unmapped = 0
    Failed = 0
}

# Copy and rename each file
foreach ($file in $jumplistFiles) {
    $copyStats.Total++
    
    # Extract GUID from filename (the part before the extension)
    $guid = $file.BaseName
    
    # Get app name from mapping, or use "Unknown" if not found
    if ($map.ContainsKey($guid)) {
        $appName = $map[$guid]
        $copyStats.Mapped++
    } else {
        $appName = "UnknownApp"
        $copyStats.Unmapped++
    }
    
    # Clean app name for filename (remove invalid characters AND replace spaces with underscores)
    $cleanAppName = $appName -replace '[\\/:*?"<>|]', '_' -replace '\s+', '_'
    
    # Create new filename
    $newFileName = "${cleanAppName}_${guid}_automaticDestinations-ms"
    $destFile = Join-Path -Path $destPath -ChildPath $newFileName
    
    # Copy the file
    try {
        Copy-Item -Path $file.FullName -Destination $destFile -Force
        Write-Host "Copied: $($file.Name) -> $newFileName" -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to copy $($file.Name): $_" -ForegroundColor Red
        $copyStats.Failed++
    }
}

# Display summary
Write-Host "`n" + ("="*50) -ForegroundColor Green
Write-Host "PROCESS COMPLETED" -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Green
Write-Host "Destination folder: $destPath" -ForegroundColor Yellow
Write-Host "Total files processed: $($copyStats.Total)" -ForegroundColor Cyan
Write-Host "  - Successfully mapped: $($copyStats.Mapped)" -ForegroundColor Green
Write-Host "  - Unmapped (UnknownApp): $($copyStats.Unmapped)" -ForegroundColor Yellow
Write-Host "  - Failed to copy: $($copyStats.Failed)" -ForegroundColor Red
Write-Host "`nEmbedded CSV contains $($stats.MappedLines) unique application mappings." -ForegroundColor Cyan

# Show some examples of unmapped files if any
if ($copyStats.Unmapped -gt 0) {
    Write-Host "`nNote: Some GUIDs were not found in the mapping data." -ForegroundColor Yellow
    Write-Host "These will be named with 'UnknownApp' prefix." -ForegroundColor Yellow
}
