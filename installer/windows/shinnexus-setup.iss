[Setup]
AppName=ShinNexus
AppVersion=1.5.1
AppPublisher=Shinpai-AI
AppPublisherURL=https://github.com/Shinpai-AI/ShinNexus
DefaultDirName={commonappdata}\ShinNexus
DefaultGroupName=ShinNexus
OutputBaseFilename=ShinNexus-Setup
Compression=lzma
SolidCompression=yes
SetupIconFile=installer-build\shinnexus.ico
WizardStyle=modern
PrivilegesRequired=admin
UninstallDisplayIcon={app}\shinnexus.ico

[Files]
Source: "installer-build\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Dirs]
Name: "{app}"; Permissions: users-modify

[Icons]
Name: "{group}\ShinNexus"; Filename: "{app}\python\pythonw.exe"; Parameters: """{app}\shinnexus-tray.py"""; IconFilename: "{app}\shinnexus.ico"; WorkingDir: "{app}"
Name: "{commondesktop}\ShinNexus"; Filename: "{app}\python\pythonw.exe"; Parameters: """{app}\shinnexus-tray.py"""; IconFilename: "{app}\shinnexus.ico"; WorkingDir: "{app}"

[Run]
; Firewall-Regeln
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""ShinNexus-python"" dir=in action=allow program=""{app}\python\python.exe"" enable=yes profile=private,public"; Flags: runhidden waituntilterminated; StatusMsg: "Firewall-Regel wird angelegt..."
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""ShinNexus-pythonw"" dir=in action=allow program=""{app}\python\pythonw.exe"" enable=yes profile=private,public"; Flags: runhidden waituntilterminated
; Server einmal initialisieren
Filename: "{app}\python\python.exe"; Parameters: "-c ""import subprocess,time,sys,os; os.environ['PYTHONIOENCODING']='utf-8'; p=subprocess.Popen([sys.executable, 'ShinNexus.py'], cwd=r'{app}', env=os.environ); time.sleep(8); p.terminate()"""; Flags: runhidden waituntilterminated; StatusMsg: "Server wird initialisiert..."; WorkingDir: "{app}"
; Programm starten
Filename: "{app}\python\pythonw.exe"; Parameters: """{app}\shinnexus-tray.py"""; Description: "ShinNexus starten"; Flags: nowait postinstall skipifsilent; WorkingDir: "{app}"

[UninstallRun]
Filename: "taskkill"; Parameters: "/F /IM pythonw.exe"; Flags: runhidden waituntilterminated
Filename: "taskkill"; Parameters: "/F /IM python.exe"; Flags: runhidden waituntilterminated
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""ShinNexus-python"""; Flags: runhidden waituntilterminated
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""ShinNexus-pythonw"""; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
