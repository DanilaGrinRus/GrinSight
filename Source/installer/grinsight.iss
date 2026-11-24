; GrinSight: the Windows installer (Inno Setup 6). Built by run-installer.ps1:
;   ISCC.exe /DAppVersion=<the version from ui\app\src\lib.rs> /DSourceDir=<portable folder> /DExtraDir=<folder with README.txt and installed.txt>
;            /DOutDir=<folder> /DOutName=<file name without .exe> installer\grinsight.iss
; For one user, without administrator rights. The programs go to
; %LOCALAPPDATA%\Programs\GrinSightLight; the wallet is kept apart from them, in
; %LOCALAPPDATA%\GrinSightLight\data, and is never touched by installing,
; replacing or removing the program (the file installed.txt next to the
; program tells it so). No signature: the file is checked by its SHA-256.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{5C098D7D-3200-4C3C-8D58-419A276DC6CF}
AppName=GrinSight Light
AppVersion={#AppVersion}
AppVerName=GrinSight Light {#AppVersion}
AppPublisher=GrinSight
DefaultDirName={localappdata}\Programs\GrinSightLight
DefaultGroupName=GrinSight Light
DisableProgramGroupPage=yes
AllowNoIcons=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename={#OutName}
; the project's own mark: on the installer itself, on the shortcuts and in the
; list of installed programs (GrinSight.exe carries no icon of its own)
SetupIconFile=grinsight.ico
UninstallDisplayIcon={app}\grinsight.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\GrinSight.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\bin\fly-paycore-host.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\bin\fly-chain.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\bin\fly-mailbox.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\bin\fly-onion.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\bin\lyrebird.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE-lyrebird.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE-GPL-3.0.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ExtraDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ExtraDir}\SHA256SUMS.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ExtraDir}\installed.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "stop-own.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "grinsight.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\GrinSight Light"; Filename: "{app}\GrinSight.exe"; IconFilename: "{app}\grinsight.ico"
Name: "{autodesktop}\GrinSight Light"; Filename: "{app}\GrinSight.exe"; IconFilename: "{app}\grinsight.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\GrinSight.exe"; Description: "{cm:LaunchProgram,GrinSight}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; The window, the wallet process and its helpers must not keep files of {app}
; open. Only processes that run from this very folder are stopped: another
; copy of the program (a portable one, say) is not touched. The wallet's
; journal is written so that a stopped process loses nothing.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\stop-own.ps1"""; Flags: runhidden; RunOnceId: "StopOwnProcesses"
