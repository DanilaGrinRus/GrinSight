; GrinSight Windows installer (Inno Setup 6). Built by make_app.ps1:
;   ISCC.exe /DAppVersion=0.2.0 /DSourceDir=<runner\Release> /DOutDir=<dist> /DIconFile=<app_icon.ico> installer\grinsight.iss
; Per-user install (no administrator rights), Start menu entry, optional desktop
; icon, normal uninstall. Wallet data stays in %APPDATA%\GrinSight and is NOT
; removed on uninstall (it holds the encrypted wallets).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{35C4ABE8-FA93-4694-8216-5EFFE0F8E85C}
AppName=GrinSight
AppVersion={#AppVersion}
AppVerName=GrinSight {#AppVersion}
AppPublisher=GrinSight
AppPublisherURL=https://github.com/DanilaGrinRus/GrinSight
AppSupportURL=https://github.com/DanilaGrinRus/GrinSight/issues
DefaultDirName={localappdata}\Programs\GrinSight
DefaultGroupName=GrinSight
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=GrinSight-setup
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\grinsight.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\GrinSight"; Filename: "{app}\grinsight.exe"
Name: "{autodesktop}\GrinSight"; Filename: "{app}\grinsight.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\grinsight.exe"; Description: "{cm:LaunchProgram,GrinSight}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; The wallet service and Tor must not keep files of {app} open.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM grinsight-service.exe"; Flags: runhidden; RunOnceId: "StopService"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM grinsight-tor.exe"; Flags: runhidden; RunOnceId: "StopTor"
