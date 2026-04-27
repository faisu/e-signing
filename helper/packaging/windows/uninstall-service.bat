@echo off
:: BridgeIt DSC Helper — Windows service uninstaller
:: Requires admin.

SET INSTALL_DIR=C:\Program Files\BridgeIt Helper
SET NSSM="%INSTALL_DIR%\nssm.exe"

echo Stopping and removing BridgeIt DSC Helper service...

net stop BridgeItHelper 2>nul
%NSSM% remove BridgeItHelper confirm

echo Service removed.
pause
