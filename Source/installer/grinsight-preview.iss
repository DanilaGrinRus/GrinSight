; GrinSight Windows installer (Inno Setup 6). Built by make_app.ps1:
;   ISCC.exe /DAppVersion=0.2.0 /DSourceDir=<runner\Release> /DOutDir=<dist> /DIconFile=<app_icon.ico> installer\grinsight.iss
; Per-user install (no administrator rights), Start menu entry, optional desktop
; icon, normal uninstall. Build Flutter with GS_PREVIEW_ISOLATED=true.
; Preview data stays in %APPDATA%\GrinSight-Preview and is not uninstalled.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{9B246F6F-C90D-4570-B867-6F8EDE1B2552}
AppName=GrinSight Preview
AppVersion={#AppVersion}
AppVerName=GrinSight Preview {#AppVersion}
AppPublisher=GrinSight
AppPublisherURL=https://github.com/DanilaGrinRus/GrinSight
AppSupportURL=https://github.com/DanilaGrinRus/GrinSight/issues
DefaultDirName={localappdata}\Programs\GrinSight-Preview
DefaultGroupName=GrinSight Preview
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=GrinSight-Preview-setup
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
Name: "{group}\GrinSight Preview"; Filename: "{app}\grinsight.exe"
Name: "{autodesktop}\GrinSight Preview"; Filename: "{app}\grinsight.exe"; Tasks: desktopicon

