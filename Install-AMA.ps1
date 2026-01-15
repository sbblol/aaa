# Install-AMA.ps1
# powershell.exe -ExecutionPolicy Bypass -File ".\Install-AMA.ps1"
# Install behavior: System
# Detection Rule: File - C:\Program Files\Azure Monitor Agent\Service\AzureMonitorAgentService.exe
# Requirements: 64-bit 10.0.17134
# cmd /c "msiexec /x {B32E8D9A-28B1-43BF-A7A9-A28A6E1B3FB8} /qn"

$Rand = Get-Random -Minimum 1000 -Maximum 9999
$LogPath = "C:\Windows\Temp\AMA_Intune_Install_$Rand.log"
$MSILogPath = "C:\Windows\Temp\AMA_MSI_Verbose_$Rand.log"
$ServiceName = "AzureMonitorAgent"
$ProcessName = "AzureMonitorAgentService" 

# Try to start logging, continue silently if it fails
try { Start-Transcript -Path $LogPath -Force -ErrorAction SilentlyContinue } catch {}

Write-Output "--- Starting Azure Monitor Agent Installation (Final) ---"
Write-Output "Logs located at: $LogPath"

# --- FUNCTION: NUKE SERVICE ---
function Nuke-Service ($Name, $ProcName) {
    Write-Output "Step 1: Disabling Service '$Name' to prevent respawn..."
    # Critical: Set to Disabled so SCM doesn't auto-restart it when we kill the process
    Set-Service -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue
    sc.exe config $Name start= disabled | Out-Null 

    Write-Output "Step 2: Force killing process '$ProcName'..."
    # Kill the process repeatedly until it stays dead
    $maxRetries = 5
    for ($i=0; $i -lt $maxRetries; $i++) {
        $proc = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Output "Found PID $($proc.Id). Killing..."
            Stop-Process -Name $ProcName -Force -ErrorAction SilentlyContinue
            taskkill /F /IM "$ProcName.exe" /T | Out-Null
            Start-Sleep -Seconds 2
        } else {
            Write-Output "Process is gone."
            break
        }
    }
    
    Write-Output "Step 3: Ensuring Service is STOPPED..."
    try {
        $svc = Get-Service $Name -ErrorAction SilentlyContinue
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}
# ------------------------------

# 1. PRE-CLEANUP
$InstallDir = "C:\Program Files\Azure Monitor Agent"
if (Test-Path $InstallDir) {
    Nuke-Service $ServiceName $ProcessName
}

# 2. INSTALLATION
Write-Output "Launching msiexec..."
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$PSScriptRoot\AzureMonitorAgentClientSetup.msi`" /qn /norestart /l*v `"$MSILogPath`"" -Wait -PassThru

$ExitCode = $process.ExitCode
Write-Output "MSI finished with Exit Code: $ExitCode"

# 3. RESTORE AND START
Write-Output "Restoring Service Configuration..."
Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction SilentlyContinue
sc.exe config $ServiceName start= auto | Out-Null

# 4. VALIDATION
$AMAService = Get-Service $ServiceName -ErrorAction SilentlyContinue

if ($ExitCode -eq 0 -or $ExitCode -eq 3010) {
    if ($AMAService) {
        Write-Output "SUCCESS: Service present. Attempting to start..."
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        try { Stop-Transcript } catch {}
        Exit 0
    } else {
        Write-Error "FAILURE: Service missing after install."
        try { Stop-Transcript } catch {}
        Exit 1
    }
} else {
    Write-Error "Installation Failed with code $ExitCode."
    try { Stop-Transcript } catch {}
    Exit $ExitCode
}