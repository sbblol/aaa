#Requires -Modules Az.Accounts, Az.Monitor

<#
.SYNOPSIS
    Updates Azure Data Collection Rule for Process Creation and Security Event Monitoring
.DESCRIPTION
    This script configures a Data Collection Rule to collect process creation events,
    security events, and related threat detection events for Azure Monitor/Sentinel
.NOTES
    Author: Security Architect
    Focus: Process Creation Events (Event ID 4688) and related security monitoring
    Requires: Contributor or higher permissions on the resource group
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName = "Sentinel",
    
    [Parameter(Mandatory = $true)]
    [string]$DcrName = "windowsClientOS_eventVwr",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSysmon = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeVerboseLogging = $false
)

# Function to connect to Azure with error handling
function Connect-ToAzure {
    param($SubscriptionId)
    
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        
        if ($SubscriptionId) {
            Connect-AzAccount -SubscriptionId $SubscriptionId
        } else {
            Connect-AzAccount
        }
        
        $context = Get-AzContext
        Write-Host "Connected to subscription: $($context.Subscription.Name)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
        return $false
    }
}

# Build XPath queries for security and process monitoring
function Get-ProcessCreationXPathQueries {
    param(
        [bool]$IncludeSysmon,
        [bool]$IncludeVerbose
    )
    
    # Core process creation and security events based on audit configuration
    $coreQueries = @(
        # === DETAILED TRACKING EVENTS ===
        # Process Creation Events (Primary focus) - Audit Process Creation
        "Security!*[System[(EventID=4688)]]",  # A new process has been created
        "Security!*[System[(EventID=4689)]]",  # A process has exited
        
        # RPC Events - Audit RPC Events  
        "Security!*[System[(EventID=5712)]]",  # RPC call attempted
        "Security!*[System[(EventID=5888)]]",  # COM+ object was modified
        
        # === LOGON/LOGOFF EVENTS ===
        # Account Logon - Audit Logon/Logoff
        "Security!*[System[(EventID=4624)]]",  # An account was successfully logged on
        "Security!*[System[(EventID=4634)]]",  # An account was logged off
        "Security!*[System[(EventID=4625)]]",  # An account failed to log on
        
        # Special Logon - Audit Special Logon
        "Security!*[System[(EventID=4672)]]",  # Special privileges assigned to new logon
        
        # Other Logon/Logoff Events - Audit Other Logon Logoff Events
        "Security!*[System[(EventID=4647)]]",  # User initiated logoff
        "Security!*[System[(EventID=4648)]]",  # A logon was attempted using explicit credentials
        "Security!*[System[(EventID=4649)]]",  # A replay attack was detected
        "Security!*[System[(EventID=4778)]]",  # A session was reconnected to a Window Station
        "Security!*[System[(EventID=4779)]]",  # A session was disconnected from a Window Station
        "Security!*[System[(EventID=4800)]]",  # The workstation was locked
        "Security!*[System[(EventID=4801)]]",  # The workstation was unlocked
        "Security!*[System[(EventID=4802)]]",  # The screen saver was invoked
        "Security!*[System[(EventID=4803)]]",  # The screen saver was dismissed
        
        # === ACCOUNT LOGON EVENTS ===
        # Credential Validation - Audit Credential Validation
        "Security!*[System[(EventID=4774)]]",  # An account was mapped for logon
        "Security!*[System[(EventID=4775)]]",  # An account could not be mapped for logon
        "Security!*[System[(EventID=4776)]]",  # Computer attempted to validate credentials
        "Security!*[System[(EventID=4777)]]",  # Domain controller failed to validate credentials
        "Security!*[System[(EventID=4820)]]",  # A Kerberos Ticket-granting-ticket (TGT) was denied
        "Security!*[System[(EventID=4821)]]",  # A Kerberos service ticket was denied
        
        # Kerberos Authentication - Audit Kerberos Authentication Service
        "Security!*[System[(EventID=4768)]]",  # A Kerberos authentication ticket (TGT) was requested
        "Security!*[System[(EventID=4769)]]",  # A Kerberos service ticket was requested
        "Security!*[System[(EventID=4770)]]",  # A Kerberos service ticket was renewed
        "Security!*[System[(EventID=4771)]]",  # Kerberos pre-authentication failed
        "Security!*[System[(EventID=4772)]]",  # A Kerberos authentication ticket request failed
        "Security!*[System[(EventID=4773)]]",  # A Kerberos service ticket request failed
        
        # === PRIVILEGE USE EVENTS ===
        # Sensitive Privilege Use - Audit Sensitive Privilege Use
        "Security!*[System[(EventID=4673)]]",  # A privileged service was called
        "Security!*[System[(EventID=4674)]]",  # An operation was attempted on a privileged object
        
        # === ACCOUNT MANAGEMENT EVENTS ===
        # User Account Management - Audit User Account Management
        "Security!*[System[(EventID=4720)]]",  # A user account was created
        "Security!*[System[(EventID=4722)]]",  # A user account was enabled
        "Security!*[System[(EventID=4723)]]",  # An attempt was made to change an account's password
        "Security!*[System[(EventID=4724)]]",  # An attempt was made to reset an account's password
        "Security!*[System[(EventID=4725)]]",  # A user account was disabled
        "Security!*[System[(EventID=4726)]]",  # A user account was deleted
        "Security!*[System[(EventID=4738)]]",  # A user account was changed
        "Security!*[System[(EventID=4740)]]",  # A user account was locked out
        "Security!*[System[(EventID=4767)]]",  # A user account was unlocked
        "Security!*[System[(EventID=4781)]]",  # The name of an account was changed
        
        # Security Group Management - Audit Security Group Management
        "Security!*[System[(EventID=4727)]]",  # A security-enabled global group was created
        "Security!*[System[(EventID=4728)]]",  # A member was added to a security-enabled global group
        "Security!*[System[(EventID=4729)]]",  # A member was removed from a security-enabled global group
        "Security!*[System[(EventID=4730)]]",  # A security-enabled global group was deleted
        "Security!*[System[(EventID=4731)]]",  # A security-enabled local group was created
        "Security!*[System[(EventID=4732)]]",  # A member was added to a security-enabled local group
        "Security!*[System[(EventID=4733)]]",  # A member was removed from a security-enabled local group
        "Security!*[System[(EventID=4734)]]",  # A security-enabled local group was deleted
        "Security!*[System[(EventID=4735)]]",  # A security-enabled local group was changed
        "Security!*[System[(EventID=4737)]]",  # A security-enabled global group was changed
        "Security!*[System[(EventID=4754)]]",  # A security-enabled universal group was created
        "Security!*[System[(EventID=4755)]]",  # A security-enabled universal group was changed
        "Security!*[System[(EventID=4756)]]",  # A member was added to a security-enabled universal group
        "Security!*[System[(EventID=4757)]]",  # A member was removed from a security-enabled universal group
        "Security!*[System[(EventID=4758)]]",  # A security-enabled universal group was deleted
        "Security!*[System[(EventID=4764)]]",  # A group's type was changed
        
        # === SYSTEM EVENTS ===
        # Security State Change - Audit Security State Change
        "Security!*[System[(EventID=4608)]]",  # Windows is starting up
        "Security!*[System[(EventID=4609)]]",  # Windows is shutting down
        "Security!*[System[(EventID=4616)]]",  # The system time was changed
        "Security!*[System[(EventID=4621)]]",  # Administrator recovered system from CrashOnAuditFail
        
        # System Integrity - Audit System Integrity
        "Security!*[System[(EventID=4612)]]",  # Internal resources allocated for the queuing of audit messages have been exhausted
        "Security!*[System[(EventID=4615)]]",  # Invalid use of LPC port
        "Security!*[System[(EventID=4618)]]",  # A monitored security event pattern has occurred
        "Security!*[System[(EventID=4816)]]",  # RPC detected an integrity violation while decrypting an incoming message
        
        # Other System Events - Audit Other System Events  
        "Security!*[System[(EventID=5024)]]",  # The Windows Firewall Service has started successfully
        "Security!*[System[(EventID=5025)]]",  # The Windows Firewall Service has been stopped
        "Security!*[System[(EventID=5027)]]",  # The Windows Firewall Service was unable to retrieve the security policy
        "Security!*[System[(EventID=5028)]]",  # The Windows Firewall Service was unable to parse the new security policy
        "Security!*[System[(EventID=5029)]]",  # The Windows Firewall Service failed to initialize the driver
        "Security!*[System[(EventID=5030)]]",  # The Windows Firewall Service failed to start
        "Security!*[System[(EventID=5032)]]",  # Windows Firewall was unable to notify the user
        "Security!*[System[(EventID=5033)]]",  # The Windows Firewall Driver has started successfully
        "Security!*[System[(EventID=5034)]]",  # The Windows Firewall Driver has been stopped
        "Security!*[System[(EventID=5035)]]",  # The Windows Firewall Driver failed to start
        
        # === POLICY CHANGE EVENTS ===
        # Audit Policy Change - Audit Changes to Audit Policy
        "Security!*[System[(EventID=4715)]]",  # The audit policy (SACL) on an object was changed
        "Security!*[System[(EventID=4719)]]",  # System audit policy was changed
        "Security!*[System[(EventID=4817)]]",  # Auditing settings on object were changed
        "Security!*[System[(EventID=4902)]]",  # The Per-user audit policy table was created
        "Security!*[System[(EventID=4904)]]",  # An attempt was made to register a security event source
        "Security!*[System[(EventID=4905)]]",  # An attempt was made to unregister a security event source
        "Security!*[System[(EventID=4906)]]",  # The CrashOnAuditFail value has changed
        "Security!*[System[(EventID=4907)]]",  # Auditing settings on object were changed
        "Security!*[System[(EventID=4908)]]",  # Special Groups Logon table modified
        "Security!*[System[(EventID=4912)]]",  # Per User Audit Policy was changed
        
        # Authentication Policy Change - Audit Authentication Policy Change
        "Security!*[System[(EventID=4706)]]",  # A new trust was created to a domain
        "Security!*[System[(EventID=4707)]]",  # A trust to a domain was removed
        "Security!*[System[(EventID=4713)]]",  # Kerberos policy was changed
        "Security!*[System[(EventID=4716)]]",  # Trusted domain information was modified
        "Security!*[System[(EventID=4717)]]",  # System security access was granted to an account
        "Security!*[System[(EventID=4718)]]",  # System security access was removed from an account
        
        # Authorization Policy Change - Audit Authorization Policy Change
        "Security!*[System[(EventID=4703)]]",  # A user right was adjusted
        "Security!*[System[(EventID=4704)]]",  # A user right was assigned
        "Security!*[System[(EventID=4705)]]",  # A user right was removed
        "Security!*[System[(EventID=4714)]]",  # Encrypted data recovery policy was changed
        
        # === OBJECT ACCESS EVENTS ===
        # Kernel Object - Audit Kernel Object
        "Security!*[System[(EventID=4656)]]",  # A handle to an object was requested
        "Security!*[System[(EventID=4658)]]",  # The handle to an object was closed
        "Security!*[System[(EventID=4660)]]",  # An object was deleted
        "Security!*[System[(EventID=4663)]]",  # An attempt was made to access an object
        
        # === SYSTEM EVENTS (Non-Security Log) ===
        "System!*[System[(EventID=7034)]]",    # Service crashed unexpectedly
        "System!*[System[(EventID=7045)]]",    # New service installed
        "System!*[System[(EventID=7040)]]",    # Service start type changed
        
        # === APPLICATION-SPECIFIC EVENTS ===
        # PowerShell execution monitoring
        "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4103)]]",  # Module logging
        "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]",  # Script block logging
        "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4105)]]",  # Script block logging start
        "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4106)]]",  # Script block logging stop
        
        # Windows Defender detections
        "Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116)]]",  # Malware detected
        "Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1117)]]",  # Action taken
        "Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1118)]]",  # Action failed
        "Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1119)]]",  # Critical error
        
        # AppLocker events
        "Microsoft-Windows-AppLocker/EXE and DLL!*[System[(EventID=8002)]]",    # Allowed
        "Microsoft-Windows-AppLocker/EXE and DLL!*[System[(EventID=8003)]]",    # Blocked
        "Microsoft-Windows-AppLocker/EXE and DLL!*[System[(EventID=8004)]]"     # Audited
    
        # PNP Activity Events
        "Security!*[System[(EventID=6416)]]",  # A new external device was recognized
        "Security!*[System[(EventID=6419)]]",  # A request was made to disable a device
        "Security!*[System[(EventID=6420)]]",  # A device was disabled
        "Security!*[System[(EventID=6421)]]",  # A request was made to enable a device

        # Security System Extension Events  
        "Security!*[System[(EventID=4610)]]",  # An authentication package has been loaded
        "Security!*[System[(EventID=4611)]]",  # A trusted logon process has been registered
        "Security!*[System[(EventID=4614)]]",  # A notification package has been loaded
        "Security!*[System[(EventID=4622)]]",  # A security package has been loaded

        # Application Generated Events
        "Security!*[System[(EventID=4665)]]",  # An attempt was made to create an application client context
        "Security!*[System[(EventID=4666)]]",  # An application attempted an operation
        "Security!*[System[(EventID=4667)]]",  # An application client context was deleted
        "Security!*[System[(EventID=4668)]]",  # An application was initialized
    
        # Certificate Services Events (if CA is deployed)
        "Security!*[System[(EventID=4868)]]",  # Certificate manager denied a pending certificate request
        "Security!*[System[(EventID=4869)]]",  # Certificate Services received a resubmitted certificate request
        "Security!*[System[(EventID=4870)]]",  # Certificate Services revoked a certificate
        "Security!*[System[(EventID=4871)]]",  # Certificate Services received a request to publish the certificate revocation list
        "Security!*[System[(EventID=4872)]]",  # Certificate Services published the certificate revocation list
        "Security!*[System[(EventID=4873)]]",  # A certificate request extension changed
        "Security!*[System[(EventID=4874)]]",  # One or more certificate request attributes changed
        "Security!*[System[(EventID=4875)]]",  # Certificate Services received a request to shut down
        "Security!*[System[(EventID=4876)]]",  # Certificate Services backup started
        "Security!*[System[(EventID=4877)]]",  # Certificate Services backup completed
        "Security!*[System[(EventID=4878)]]",  # Certificate Services restore started
        "Security!*[System[(EventID=4879)]]",  # Certificate Services restore completed
        "Security!*[System[(EventID=4880)]]",  # Certificate Services started
        "Security!*[System[(EventID=4881)]]",  # Certificate Services stopped
        "Security!*[System[(EventID=4882)]]",  # The security permissions for Certificate Services changed
        "Security!*[System[(EventID=4883)]]",  # Certificate Services retrieved an archived key
        "Security!*[System[(EventID=4884)]]",  # Certificate Services imported a certificate into its database
        "Security!*[System[(EventID=4885)]]",  # The audit filter for Certificate Services changed
        "Security!*[System[(EventID=4886)]]",  # Certificate Services received a certificate request
        "Security!*[System[(EventID=4887)]]",  # Certificate Services approved a certificate request and issued a certificate
        "Security!*[System[(EventID=4888)]]",  # Certificate Services denied a certificate request
        "Security!*[System[(EventID=4889)]]",  # Certificate Services set the status of a certificate request to pending
        "Security!*[System[(EventID=4890)]]",  # The certificate manager settings for Certificate Services changed
        "Security!*[System[(EventID=4891)]]",  # A configuration entry changed in Certificate Services
        "Security!*[System[(EventID=4892)]]",  # A property of Certificate Services changed
        "Security!*[System[(EventID=4893)]]",  # Certificate Services archived a key
        "Security!*[System[(EventID=4894)]]",  # Certificate Services imported and archived a key
        "Security!*[System[(EventID=4895)]]",  # Certificate Services published the CA certificate to Active Directory
        "Security!*[System[(EventID=4896)]]",  # One or more rows have been deleted from the certificate database
        "Security!*[System[(EventID=4897)]]",  # Role separation enabled
        "Security!*[System[(EventID=4898)]]"   # Certificate Services loaded a template
        )
    
    # Add Sysmon events if requested
    if ($IncludeSysmon) {
        $sysmonQueries = @(
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1)]]",   # Process creation
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=3)]]",   # Network connection
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=5)]]",   # Process terminated
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=7)]]",   # Image loaded
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=8)]]",   # CreateRemoteThread
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=10)]]",  # ProcessAccess
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=11)]]",  # FileCreate
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=12)]]",  # RegistryEvent (Object create and delete)
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=13)]]",  # RegistryEvent (Value Set)
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=17)]]",  # PipeEvent (Pipe Created)
            "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=18)]]"   # PipeEvent (Pipe Connected)
        )
        $coreQueries += $sysmonQueries
    }
    
    # Add verbose logging if requested
    if ($IncludeVerbose) {
        $verboseQueries = @(
            # Additional audit events
            "Security!*[System[(EventID=4657)]]",  # Registry value modified
            "Security!*[System[(EventID=4658)]]",  # Handle to object closed
            "Security!*[System[(EventID=4660)]]",  # Object deleted
            "Security!*[System[(EventID=4661)]]",  # Handle requested to object
            "Security!*[System[(EventID=4662)]]",  # Operation performed on object
            
            # Task Scheduler events
            "Microsoft-Windows-TaskScheduler/Operational!*[System[(EventID=106)]]",  # Task registered
            "Microsoft-Windows-TaskScheduler/Operational!*[System[(EventID=140)]]",  # Task updated
            "Microsoft-Windows-TaskScheduler/Operational!*[System[(EventID=141)]]",  # Task deleted
            "Microsoft-Windows-TaskScheduler/Operational!*[System[(EventID=200)]]",  # Task executed
            "Microsoft-Windows-TaskScheduler/Operational!*[System[(EventID=201)]]",  # Task completed
            
            # WMI events
            "Microsoft-Windows-WMI-Activity/Operational!*[System[(EventID=5857)]]",  # WMI provider
            "Microsoft-Windows-WMI-Activity/Operational!*[System[(EventID=5858)]]",  # WMI provider error
            "Microsoft-Windows-WMI-Activity/Operational!*[System[(EventID=5859)]]",  # WMI provider started
            "Microsoft-Windows-WMI-Activity/Operational!*[System[(EventID=5860)]]",  # WMI provider stopped
            "Microsoft-Windows-WMI-Activity/Operational!*[System[(EventID=5861)]]"   # WMI provider failed
        )
        $coreQueries += $verboseQueries
    }
    
    return $coreQueries
}

# Main execution
try {
    Write-Host "Starting Azure Monitor DCR Configuration for Process Creation Events" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    # Connect to Azure
    if (!(Connect-ToAzure -SubscriptionId $SubscriptionId)) {
        throw "Failed to connect to Azure"
    }
    
    # Get XPath queries based on parameters
    Write-Host "Building XPath queries for process creation monitoring..." -ForegroundColor Yellow
    $xpathQueries = Get-ProcessCreationXPathQueries -IncludeSysmon:$IncludeSysmon -IncludeVerbose:$IncludeVerboseLogging
    
    Write-Host "Total XPath queries configured: $($xpathQueries.Count)" -ForegroundColor White
    
    if ($IncludeSysmon) {
        Write-Host "✓ Sysmon events included" -ForegroundColor Green
    }
    
    if ($IncludeVerboseLogging) {
        Write-Host "✓ Verbose logging enabled" -ForegroundColor Green
    }
    
    # Build the data source object
    Write-Host "Creating Windows Event Log data source..." -ForegroundColor Yellow
    $eventLogDataSource = New-AzWindowsEventLogDataSourceObject `
        -Name "ProcessCreationDataSource" `
        -Stream @("Microsoft-Event") `
        -XPathQuery $xpathQueries
    
    # Update the Data Collection Rule
    Write-Host "Updating Data Collection Rule '$DcrName'..." -ForegroundColor Yellow
    Update-AzDataCollectionRule `
        -Name $DcrName `
        -ResourceGroupName $ResourceGroupName `
        -DataSourceWindowsEventLog @($eventLogDataSource)
    
    Write-Host "✓ Data Collection Rule updated successfully!" -ForegroundColor Green
    
    # Display summary
    Write-Host "`nConfiguration Summary:" -ForegroundColor Cyan
    Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
    Write-Host "DCR Name: $DcrName" -ForegroundColor White
    Write-Host "Data Source: ProcessCreationDataSource" -ForegroundColor White
    Write-Host "Primary Focus: Process Creation Events (Event ID 4688)" -ForegroundColor White
    Write-Host "Stream: Microsoft-Event" -ForegroundColor White
    
    Write-Host "`nKey Events Being Collected:" -ForegroundColor Yellow
    Write-Host "• Security 4688 - Process Creation" -ForegroundColor White
    Write-Host "• Security 4689 - Process Termination" -ForegroundColor White
    Write-Host "• Security 4624/4634 - Logon/Logoff Events" -ForegroundColor White
    Write-Host "• Security 4672 - Special Privileges Assigned" -ForegroundColor White
    Write-Host "• Security 4697 - Service Installation" -ForegroundColor White
    Write-Host "• PowerShell Operational Events" -ForegroundColor White
    Write-Host "• Windows Defender Events" -ForegroundColor White
    Write-Host "• AppLocker Events" -ForegroundColor White
    
    if ($IncludeSysmon) {
        Write-Host "• Sysmon Process and Network Events" -ForegroundColor White
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Yellow
    Write-Host "1. Associate this DCR with your target machines" -ForegroundColor White
    Write-Host "2. Configure Log Analytics workspace destination" -ForegroundColor White
    Write-Host "3. Set up Sentinel analytics rules for process creation monitoring" -ForegroundColor White
    Write-Host "4. Create custom KQL queries for threat hunting" -ForegroundColor White
    Write-Host "5. Test the configuration with a pilot group" -ForegroundColor White
    
    Write-Host "`nSample KQL Query for Process Creation:" -ForegroundColor Cyan
    Write-Host @"
SecurityEvent
| where EventID == 4688
| where TimeGenerated >= ago(1h)
| extend ProcessName = tostring(split(NewProcessName, '\')[-1])
| project TimeGenerated, Computer, Account, ProcessName, NewProcessName, CommandLine
| order by TimeGenerated desc
"@ -ForegroundColor Gray

}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    
    # Additional troubleshooting information
    Write-Host "`nTroubleshooting Tips:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have Contributor permissions on the resource group" -ForegroundColor White
    Write-Host "2. Verify the DCR name and resource group exist" -ForegroundColor White
    Write-Host "3. Check if the Azure Monitor module is installed: Install-Module Az.Monitor" -ForegroundColor White
    Write-Host "4. Validate your Azure connection and subscription context" -ForegroundColor White
    
    exit 1
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green