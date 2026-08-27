@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo vswhere.exe not found. Install Visual Studio with "Desktop development with C++".
  exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (
  echo Visual Studio C++ x64 tools not found.
  exit /b 1
)

call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1

set "OUT=%~dp0build"
if not exist "%OUT%" mkdir "%OUT%"

copy /Y "%~dp0data\keychain.bin" "%OUT%\keychain.bin" >nul
if errorlevel 1 (
  echo missing data\keychain.bin
  exit /b 1
)

cl /nologo /O2 /W4 /utf-8 /D_CRT_SECURE_NO_WARNINGS /Fo"%OUT%\\" ^
  src\ostara.c src\tlv.c src\combat.c src\pw_decrypt.c ^
  /Fe:"%OUT%\pw-decrypt.exe"
if errorlevel 1 exit /b 1

cl /nologo /O2 /W4 /utf-8 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /Fo"%OUT%\\" ^
  src\ostara.c src\tlv.c src\combat.c src\pcap_dyn.c src\ingest.c src\skill_names.c src\PwOverlay.c ^
  /Fe:"%OUT%\PlayCabalWire.exe" ^
  /link /SUBSYSTEM:WINDOWS /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" ^
  user32.lib gdi32.lib iphlpapi.lib ws2_32.lib
if errorlevel 1 exit /b 1

echo Built %OUT%\pw-decrypt.exe
echo Built %OUT%\PlayCabalWire.exe
exit /b 0
