@echo off
:: BridgeIt DSC Helper — Windows service installer
:: Requires admin. Run from the Inno Setup custom action or manually as Administrator.

SET INSTALL_DIR=C:\Program Files\BridgeIt Helper
SET NSSM="%INSTALL_DIR%\nssm.exe"
SET BINARY="%INSTALL_DIR%\bridgeit-helper.exe"

echo Installing BridgeIt DSC Helper service...

:: Stop existing service if running
net stop BridgeItHelper 2>nul
%NSSM% remove BridgeItHelper confirm 2>nul

:: Register the service via NSSM
%NSSM% install BridgeItHelper %BINARY%
%NSSM% set BridgeItHelper DisplayName "BridgeIt DSC Helper"
%NSSM% set BridgeItHelper Description "Localhost HTTPS bridge for DSC token signing (PAdES)"
%NSSM% set BridgeItHelper Start SERVICE_AUTO_START
%NSSM% set BridgeItHelper AppStdout "%INSTALL_DIR%\helper.log"
%NSSM% set BridgeItHelper AppStderr "%INSTALL_DIR%\helper.log"
%NSSM% set BridgeItHelper AppRotateFiles 1
%NSSM% set BridgeItHelper AppRotateBytes 5242880

:: Start immediately
net start BridgeItHelper

echo.
echo BridgeIt DSC Helper is running.
echo Next: visit https://127.0.0.1:7777/version in your browser and trust the certificate.
pause
