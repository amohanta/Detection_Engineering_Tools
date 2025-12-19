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
Application IDs,560d789a6a42ad5a,DC++ 0.261 / 0.698 / 0.782 (r2402.1)
Application IDs,bcc705f705d8132b,Instan-t 5.2 (Build 2824)
Application IDs,1d12f965b876dc87,Snagit 2021
Application IDs,4700ff5ae80a6713,PDFCreator 2.2
Application IDs,4a49906d074a3ad3,Media Go 1.8 (Build 121)
Application IDs,6824f4a902c78fbd,Firefox 64.0
Application IDs,fe9e0f7260000a12,RealVNC Server 5.3.0 64-bit (Connect+File Transfer)
Application IDs,a2c73c383525f1bb,RealVNC Viewer 5.3.0 64-bit
Application IDs,d3530c5294441522,HydraIRC 0.3.165
Application IDs,b37a182b9a7a8098,SAPIEN.Packager
Application IDs,ee0c103672a7a2b9,ManyCam 6.7.0
Application IDs,a1d19afe5a80f80,FileZilla 2.2.32
Application IDs,fdbd48d45512dffc,Photoshop 7
Application IDs,989d7545c2b2e7b2,IMVU 465.8.0.0
Application IDs,497f749b9f1a5d16,Microsoft.GamingApp
Application IDs,1eb796d87c32eff9,Firefox 5.0
Application IDs,36801066f71b73c5,Binbot 2.0
Application IDs,cfb56c56fa0f0a54,Mozilla 0.9.9
Application IDs,50c5e019818564e3,Microsoft Excel Viewer 12.0.6219.1000
Application IDs,5f218922e0901ebf,MusicBee
Application IDs,9f5c7755804b850a,Windows Script Host - wscript.exe (64-bit)
Application IDs,23709f6439b9f03d,Hex Editor Neo 5.14(CHANGED)
Application IDs,436eb6eb1bd9f03f,Microsoft Visio 15
Application IDs,33a00252c0fa56de,Mozilla Firefox x32
Application IDs,accca100973ef8dc,Azureus 2.0.8.4
Application IDs,d33ecf70f0b74a77,Picasa 2.2.0 (Build 28.08, 0)
Application IDs,a8df13a46d66f6b5,Kommute (Calypso) 0.24
Application IDs,186b5ccada1d986b,NewsGrabber 3.0.36
Application IDs,99c15cf3e6d52b61,mldonkey 3.1.0
Application IDs,fd1ad55e472f20e0,Google Earth Pro 7.3.2.5491
Application IDs,8f4ae1df7d39f816,X-Ways WinHex x64
Application IDs,62dba7fb39bb0adc,Yahoo Messenger 7.5.0.647 / 8.1.0.421 / 9.0.0.2162 / 10.0.0.1270
Application IDs,466d339d8f21cfbf,Microsoft Snip & Sketch
Application IDs,3917dd550d7df9a8,Konvertor 4.06 (Build 10)
Application IDs,8a1c1c7c389a5320,Safari 3.2.3 (525.29)
Application IDs,be4875bb3e0c158f,CrossFTP 1.75a
Application IDs,9e312f4adee9107,Opera Browser
Application IDs,f674c3a77cfe39d0,Winamp 2.95 / 5.1 / 5.621 / 5.666
Application IDs,f7699cf2eed599ac,Microsoft.SecHealthUI
Application IDs,d788e8bc973b89e9,PKWARE PKZIP for Windows 14
Application IDs,884fd37e05659f3a,VZOchat 6.3.5
Application IDs,1b29f0dc90366bb,AIM 5.9.3857
Application IDs,cbbe886eca4bfc2d,ExoSee 1.0.0
Application IDs,36c36598b08891bf,Vovox 2.5.3.4250
Application IDs,607258d66273ff4d,Microsoft Edge
Application IDs,adecfb853d77462a,Microsoft Office Word 2007 Pinned and Recent.
Application IDs,19e6043495a5b4da,Edit Pad Pro
Application IDs,d460280b17628695,Java Binary
Application IDs,d1cc3f047e70a200,SAPIEN SnippetEditor
Application IDs,fe57f5df17b45fe,Wireshark 2.6.3
Application IDs,22cefa022402327d,Meca Messenger 5.3.0.52 (CHANGED)
Application IDs,92a0e470eecc63d3,RegistryExplorer
Application IDs,74d7f43c1561fc1e,Windows Media Player 12.0.7601.17514
Application IDs,0ef606b196796ebb,HP MediaSmart Photo
Application IDs,cb996a858d7f15c,PDF Architect 4.0.09.25450 64-bit
Application IDs,e76a4ef13fbf2bb1,Manolito 3.1.1
Application IDs,ea83017cdd24374d,IrfanView Thumbnails
Application IDs,d014c0be50851f63,MusicBee 3.4.2.0 x86
Application IDs,bc03160ee1a59fc1,Foxit PDF Reader 5.4.5
Application IDs,c8aa3eaee3d4343d,Trillian 0.74 / 3.1 / 4.2.0.25 / 5.0.0.35 (JL support)
Application IDs,27da120d7e75cf1f,pbFTPClient 6.1
Application IDs,966fa7c312d9b10,Eraser 6.2.0.2970
Application IDs,c45108aa42339506,PowerPoint Show 8
Application IDs,b06bc47edd036329,SAPIEN PowerShell Studio
Application IDs,337ed59af273c758,Sticky Notes (Windows 10)
Application IDs,2519133d6d830f7e,IMatch 3.6.0.113
Application IDs,7904145af324576e,Total Commander 7.56a (Build 16.12.2010) / 8.52a 32-bit
Application IDs,4b5f45de9912de53,Microsoft.Office.Desktop.Access_16xxx
Application IDs,f6fd5d99e2b6e178,LibreOffice 5.1.0.3 Draw
Application IDs,bba8a4896f0d26f,Ares Chat Client (3.1.9.4045)
Application IDs,7ff0b18f1611daa4,Opera Browser
Application IDs,4cb9c5750d51c07f,Microsoft Movies & TV (Build 10.19031.11411.0)
Application IDs,7593af37134fd767,RealPlayer 6.0.6.99 / 7 / 8 / 10.5
Application IDs,780732558f827a42,AutoPix 5.3.3
Application IDs,da7e8de5b8273a0f,Yahoo Messenger 5.0.0.1226 / 6.0.0.1922
Application IDs,73c6a317412687c2,Google Talk 1.0.0.104
Application IDs,f039446000b1b829,SweetScape 010 Editor
Application IDs,6e855c85de07bc6a,Microsoft Office Excel 2010 x64
Application IDs,47592b67dd97a119,Windows Notepad x32 (Notepad.exe)
Application IDs,20ef367747c22564,Bullet Proof FTP 2010.75.0.75
Application IDs,a7bd71699cd38d1c,Microsoft Office Word 2010 x86
Application IDs,431a5b43435cc60b,Python (.pyc)
Application IDs,cdb6f0c373f2da0f,stunnel 5.31
Application IDs,e107946bb682ce47,Filezilla 3.5.1 / 3.16
Application IDs,e26f61afb0824f2e,Photoshop CC 2015
Application IDs,b8ab77100df80ab2,Microsoft Office Excel x64
Application IDs,447e6aa2bbdfbc8a,Slack 4.11.3
Application IDs,f92e607f9de02413,RealPlayer 14.0.6.666
Application IDs,7c8adb9f2028b7d4,SAPIEN Packager
Application IDs,8904a5fd2d98b546,IceChat 7.70 20101031
Application IDs,4cdf7858c6673f4b,Bullet Proof FTP 1.26
Application IDs,7a4ba998575ff2a4,FreeCommander XE 2016 Build 715 32-bit
Application IDs,4acae695c73a28c7,VLC 0.3.0 / 0.4.6
Application IDs,83b03b46dcd30a0e,iTunes 9.0.0.70 / 9.2.1.5 / 10.4.1.10 (begin custom 'Tasks' JL capability) / 12.3.2.35 64-bit
Application IDs,1c30573bdfce4155,Zenmap GUI 6.49BETA4
Application IDs,7e4dca80246863e3,Control Panel - Settings
Application IDs,9027fe24326910d2,Thunderbird 38.6.0
Application IDs,18ae7cda503d746e,Advanced System Optimizer 3
Application IDs,2db8e25112ab4453,Deluge 1.3.3
Application IDs,d4e1769e47ffde26,Cyberlink PhotoDirector 9
Application IDs,46e77b87767b92,Opera Browser 75
Application IDs,b223c3ffbc0a7a42,Bersirc 2.2.14
Application IDs,265142389b98fcb1,DVDFab 9 x86
Application IDs,d1d9b843a81139c6,KeePass
Application IDs,1ced32d74a95c7bc,Microsoft Visual Studio Code
Application IDs,f5ac5390b9115fdb,Microsoft Office PowerPoint 2007
Application IDs,21982dade69f78d8,Opera Browser
Application IDs,ebd8c95d87f25154,Carrier 2.5.5
Application IDs,10f5a20c21466e85,FTP Voyager 15.2.0.17
Application IDs,ecd21b58c2f65a2f,StealthNet 0.8.7.9
Application IDs,d00655d2aa12ff6d,Microsoft PowerPoint 2016 64-bit
Application IDs,9b9cdc69c1c24e2b,Notepad 64-bit
Application IDs,7494a606a9eef18e,Crystal Player 1.98
Application IDs,135df2a440abe9bb,SoulSeek 156c
Application IDs,b06a975b62567622,Windows Live Messenger 8.5.1235.0517 BETA
Application IDs,78f0afb5bd4bb278,Microsoft Lync 2016 64-bit (Skype for Business)
Application IDs,f82607a219af2999,Cyberduck 4.1.2 (Build 8999)
Application IDs,cb1d97aca3fb7e6b,Newz Crawler 1.9.0 (Build 4100)
Application IDs,e6ef42224b845020,ALFTP 5.20.0.4
Application IDs,cb984e3bc7faf234,NewsRover 17.0 (Rev.0)
Application IDs,f920768fe275f7f4,Grabit 1.5.3 Beta (Build 909) / 1.6.2 (Build 940) / 1.7.2 Beta 4 (Build 997)
Application IDs,40371339ad31a7e6,Mozilla Firefox x64
Application IDs,e0532b20aa26a0c9,QQ International 1.1 (2042)
Application IDs,a75b276f6e72cf2a,WinMX 3.53
Application IDs,98b0ef1c84088,fulDC 6.78
Application IDs,d2d0fc95675fb2c8,Microsoft Built-in Print Management (Win10)
Application IDs,baea31eacd87186b,BinaryBoy 1.97 (Build 55)
Application IDs,6fee01bd55a634fe,Smuxi 0.8.0.0
Application IDs,d356105fac5527ef,Steam 1/22/2021
Application IDs,23ef200ca6364eff,Oracle VM VirtualBox 5.0.16
Application IDs,3c355482cb54f75b,Microsoft.GetHelp
Application IDs,122c907c4dc5911f,Mozilla Firefox x32
Application IDs,8bd5c6433ca967e9,ACDSee Photo Manager 2009 (v11.0 Build 113)
Application IDs,43929ae4535c8dea,Microsoft.SkypeApp 15 x86
Application IDs,cc4b36fbfb69a757,gtk-gnutella 0.97
Application IDs,d4a589cab4f573f7,Microsoft Project 2010 x86
Application IDs,971cc6ad207f36cb,PaintShopPro (X9)
Application IDs,0a1d19afe5a80f80,FileZilla 2.2.32
Application IDs,cd40ead0b1eb15ab,NNTPGrab 0.6.2
Application IDs,2a64b26bd99f0d16,Shareaza
Application IDs,9c32e2313792e6e8,Microsoft Built-in Disk Cleanup (Win10)
Application IDs,f784591ff7f60f76,Microsoft Built-in Defragment and Optimize Drives (Win10)
Application IDs,c312e260e424ae76,Mail.Ru Agent 5.8 (JL support)
Application IDs,2a5a615382a84729,X-Chat 2 2.8.6-2
Application IDs,3c93a049a30e25e6,J. River Media Center 16.0.149
Application IDs,cc76755e0f925ce6,AllPicturez 1.2
Application IDs,497b42680f564128,Zoner PhotoStudio 13 (Build 7)
Application IDs,d8081f151f4bd8a5,CuteFTP 8.3 Lite (Build 8.3.4.0007)
Application IDs,44a3621b32122d64,Microsoft Office Word 2010 x64
Application IDs,1c7a9be1b15a03ba,Microsoft Snip & Sketch
Application IDs,efbb2bf3c1d06466,Auslogics Disk Defrag 6.2.1.0
Application IDs,f91fd0c57c4fe449,ExpanDrive 2.1.0
Application IDs,bf483b423ebbd327,Binary Vortex 5.0
Application IDs,4a7e4f6a181d3d08,broolzShare
Application IDs,9d91276b0be3e46b,Windows Help and Support (Built-in) Win7
Application IDs,7937df3c65790919,FTP Explorer 10.5.19 (Build 001)
Application IDs,4fd44f9938892caa,CDBurnerXP
Application IDs,1bc9bbbe61f14501,OneNote
Application IDs,6f647f9488d7a,AIM 7.5.11.9 (custom AppID + JL support)
Application IDs,b50ee40805bd280f,QuickTime Alternative 1.9.5 (Media Player Classic 6.4.9.1)
Application IDs,06059df4b02360af,Kadu 0.10.0 / 0.6.5.5
Application IDs,b7173093b23b9a6a,Beyond Compare 4
Application IDs,cbeb786f0132005d,VLC 0.7.2
Application IDs,e0246018261a9ccc,qutIM 0.2.80.0
Application IDs,65f7dd884b016ab2,LimeChat 2.39
Application IDs,22c4d315e96389e0,FastCopy 3.12
Application IDs,3ed70ef3495535f7,Gravity 3.0.4
Application IDs,65009083bfa6a094,(app launched via XPMode)
Application IDs,d64d36b238c843a3,Microsoft Office InfoPath 2010 x86
Application IDs,8a461f82e9eb4102,Foxit Reader 7.2.0.722
Application IDs,c88c76a215679365,Axialis IconWorkshop 6
Application IDs,e4ea035065b5789a,Maël Hörz HxD Hex Editor 2.5
Application IDs,50620fe75ee0093,VMware Player 3.1.4
Application IDs,f1a4c04eebef2906,[i2p] Robert 0.0.29 Preferences
Application IDs,b0236d03c0627ac4,ICQ 5.1 / ICQLite Build 1068
Application IDs,aedd2de3901a77f4,Pidgin 2.10.11
Application IDs,5e01ecaf82f7d8e,Scour Exchange 0.0.0.228
Application IDs,0b3f13480c2785ae,Paint 6.1 (build 7601: SP1)
Application IDs,319f01bf9fe00f2d,Microsoft Access 2016 64-bit
Application IDs,30d23723bdd5d908,Digsby (Build 30140) (JL support)
Application IDs,76f6f1bd18c19698,aMule 2.2.6
Application IDs,c5c24a503b1727df,XnView 1.98.2 Small / 1.98.2 Standard / 2.35
Application IDs,a8c43ef36da523b1,Microsoft Office Word 2003 Pinned and Recent.
Application IDs,b8c13a5dd8c455a2,Titan FTP Server 8.40 (Build 1338)
Application IDs,03d877ec11607fe4,Thunderbird 6.0.2
Application IDs,56c5204009d2b915,uTorrent 3.5.5
Application IDs,69d97cdc8d4d5043,Microsoft.windowscommunicationsapps
Application IDs,8172865a9d5185cb,Binreader 1.0 (Beta 1)
Application IDs,fbb3e7490ba71a30,SQLite Expert
Application IDs,a79a7ce3c45d781,CuteFTP 7.1 (Build 06.06.2005.1)
Application IDs,92f1d5db021cd876,NewsLeecher 4.0 / 5.0 Beta 6
Application IDs,8dcca8b24a5e822e,CDBurnerXP 4.5.7.6623
Application IDs,fb230a9fe81e71a8,Yahoo Messenger 11.0.0.2014-us
Application IDs,7fa8bdd163836f0c,WinRAR
Application IDs,4b632cf2ceceac35,Robo-FTP Server 3.2.5
Application IDs,d7d647c92cd5d1e6,uTalk 2.6.4 r47692
Application IDs,d7666c416cba240c,NewsMan Pro 3.0.5.2
Application IDs,7b7f65aaeca20a8c,Dropbox App 5.4.24
Application IDs,ea64ce14e5470c33,Microsoft.PowerShell_7.2.1.0 x64
Application IDs,5b72f67adcce9045,UltraVNC 1.2.1.0 Settings
Application IDs,e6ee34ac9913c0a9,VLC 0.6.2
Application IDs,3edf100b207e2199,digiKam 1.7.0 (KDE 4.4.4)
Application IDs,44a50e6c87bc012,Classic FTP Plus 2.15
Application IDs,f0275e8685d95486,Microsoft Office Excel 2013 x86
Application IDs,d53b52fb65bde78c,Android Newsgroup Downloader 6.2
Application IDs,d93f411851d7c929,Windows Powershell 5.0 32-bit
Application IDs,3461e4d1eb393c9c,WTW 0.8.18.2852 / 0.8.19.2940
Application IDs,4c58cf9096ef3efd,Kindle for PC 1.24.3
Application IDs,31b6ebfff794ef0d,Opera Browser (Opera.exe)
Application IDs,6059df4b02360af,Kadu 0.10.0 / 0.6.5.5
Application IDs,2ff9dc8fb7e11f39,I2P 0.8.8 (no window)
Application IDs,f2d2624b34821c85,Opera Browser (Opera.exe)
Application IDs,c98ab5ccf25dda79,NewsShark 2.0
Application IDs,b8a48bfb1f2f0c8d,NordVPN
Application IDs,d22ad6d9d20e6857,ALLPlayer 4.7
Application IDs,a4def57ee99d77

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
