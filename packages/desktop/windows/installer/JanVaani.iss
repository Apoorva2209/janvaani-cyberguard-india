; Inno Setup script for the JanVaani Windows installer (JanVaani-Setup.exe).
; Build with:  ISCC.exe /DPackageDir=<folder with .msix, .cer, Dependencies> /DOutDir=<output folder> JanVaani.iss

#ifndef PackageDir
  #error PackageDir must be defined, for example /DPackageDir=C:\build\package
#endif
#ifndef OutDir
  #define OutDir "."
#endif
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{8F6B2C1D-4A5E-4F7B-9C3D-2E1A0B9C7D54}
AppName=JanVaani
AppVersion={#AppVersion}
AppPublisher=Apoorva SV
DefaultDirName={autopf}\JanVaani Setup Files
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible arm64
ArchitecturesInstallIn64BitMode=x64compatible arm64
MinVersion=10.0.17763
OutputDir={#OutDir}
OutputBaseFilename=JanVaani-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=JanVaani

[Files]
Source: "{#PackageDir}\*"; DestDir: "{app}\package"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "install.ps1"; DestDir: "{app}\package"; Flags: ignoreversion

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\package\install.ps1"""; Flags: runhidden waituntilterminated; StatusMsg: "Installing JanVaani..."

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Get-AppxPackage -Name 'ApoorvaSV.JanVaani' | Remove-AppxPackage"""; Flags: runhidden waituntilterminated
