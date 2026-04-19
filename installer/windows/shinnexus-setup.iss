[Setup]
AppName=ShinNexus
AppVersion=1.5.0
AppPublisher=Shinpai-AI
DefaultDirName={autopf}\ShinNexus
DefaultGroupName=ShinNexus
OutputBaseFilename=ShinNexus-Setup-v1.5.0
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "installer-build\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\ShinNexus"; Filename: "{app}\shinnexus-tray.pyw"
Name: "{commondesktop}\ShinNexus"; Filename: "{app}\shinnexus-tray.pyw"

[Run]
Filename: "{app}\shinnexus-tray.pyw"; Description: "ShinNexus starten"; Flags: nowait postinstall skipifsilent
