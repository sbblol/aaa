@echo on
:: Simple AMA Installer for Intune
:: Bypasses PowerShell/MDE restrictions

set LOGfile="C:\Windows\Temp\AMA_Install_BAT.log"
echo Starting Installation > %LOGfile%

:: ------------------------------------------
:: STEP 1: KILL & DISABLE (The "Nuclear" fix)
:: ------------------------------------------
echo Stopping old services... >> %LOGfile%

:: Disable service to prevent auto-restart
sc config AzureMonitorAgent start= disabled >> %LOGfile% 2>&1

:: Kill the process tree forcefully (Run twice to be sure)
taskkill /F /IM AzureMonitorAgentService.exe /T >> %LOGfile% 2>&1
timeout /t 2 /nobreak > NUL
taskkill /F /IM AzureMonitorAgentService.exe /T >> %LOGfile% 2>&1

:: ------------------------------------------
:: STEP 2: INSTALLATION
:: ------------------------------------------
echo Installing MSI... >> %LOGfile%

:: 'start /wait' is CRITICAL here so Intune waits for it to finish
start /wait msiexec.exe /i "%~dp0AzureMonitorAgentClientSetup.msi" /qn /norestart /l*v "C:\Windows\Temp\AMA_MSI_Verbose.log"

:: ------------------------------------------
:: STEP 3: RESTORE & START
:: ------------------------------------------
echo Restoring service... >> %LOGfile%

:: Set back to Auto
sc config AzureMonitorAgent start= auto >> %LOGfile% 2>&1

:: Start the service
sc start AzureMonitorAgent >> %LOGfile% 2>&1

echo Done. >> %LOGfile%
exit /b 0