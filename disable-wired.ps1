# Windows 11 Compatible Wired Adapter Disable Script
# Validated against Microsoft Documentation
# Deploy as SYSTEM via Intune Device Script or Win32 App

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

try {
    # Configuration
    $WorkDir = 'C:\ProgramData\Corp'
    $ScriptPath = Join-Path $WorkDir 'DisableWired.ps1'
    $TaskName = 'DisableWiredAdapters'
    $TaskPath = '\Microsoft\Windows\Corp'

    # Create working directory
    if (-not (Test-Path $WorkDir)) {
        New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    }

    # Write the enforcement script
    $enforcementScript = @'
#Requires -Version 5.1
# Wired Adapter Enforcement Script

# Check for technician bypass
$BypassFlag = "C:\ProgramData\Corp\BypassEthernet.lock"
if (Test-Path -Path $BypassFlag) { 
    Write-Output "Bypass flag detected, exiting"
    exit 0
}

# Get physical wired adapters (exclude wireless/virtual)
$adapters = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter  -Property * | Where-Object { 
$_.InterfaceType -eq 6 -and
$_.Status -ne 'Disabled' -and
$_.InterfaceDescription -notmatch 'Wireless|Wi-?Fi|WLAN|802\.11|WWAN|Mobile Broadband|Bluetooth|Virtual|Hyper-V|VPN|TAP|WAN Miniport|Teredo|isatap|Microsoft'
}  

# Disable each wired adapter
foreach ($adapter in $adapters) {
    try { 
        Write-Output "Disabling adapter: $($adapter.Name) [$($adapter.InterfaceDescription)]"
        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
    } catch {
        Write-Warning "Failed to disable adapter $($adapter.Name): $_"
    }
}
'@

    Set-Content -Path $ScriptPath -Value $enforcementScript -Encoding UTF8 -Force

    # Create scheduled task XML with proper Windows 11 compatibility
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date>
    <Author>NT AUTHORITY\SYSTEM</Author>
    <Description>Disables wired Ethernet adapters on schedule and when devices are enabled</Description>
    <URI>\Microsoft\Windows\Corp\DisableWiredAdapters</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <CalendarTrigger>
      <StartBoundary>$(Get-Date -Format 'yyyy-MM-dd')T03:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription><![CDATA[<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and Task = 13316 and (band(Keywords,13510798882111488)) and (EventID=6422 or EventID=6421)]]</Select></Query></QueryList>]]></Subscription>
      <ValueQueries>
        <Value name="DeviceName">Event/EventData/Data[@Name='DeviceName']</Value>
      </ValueQueries>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$ScriptPath"</Arguments>
      <WorkingDirectory>$WorkDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

    # Register the scheduled task (creates the path if needed)
    try {
        # Check if task exists and remove it first
        $existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        }
        
        # Register new task
        Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $taskXml -Force | Out-Null
        Write-Output "Scheduled task registered successfully"
    } catch {
        Write-Error "Failed to register scheduled task: $_"
        throw
    }

    # Run immediately to disable adapters now
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    Write-Output "Wired adapter enforcement configured and started successfully"
    
} catch {
    Write-Error "Script failed: $_"
    exit 1
}

exit 0