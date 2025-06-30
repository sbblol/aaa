<#
.SYNOPSIS
    Retrieves LAPS password leveraging Entra ID joined device identity (NO SECRETS REQUIRED).

.DESCRIPTION
    This script leverages the device's Entra ID join status and Primary Refresh Token (PRT)
    to authenticate seamlessly without storing any credentials in the script.

    Key Features:
    - Uses Web Account Manager (WAM) for device-based authentication
    - Leverages Primary Refresh Token from Entra ID joined device
    - Provides seamless SSO when user is logged in with work account
    - NO certificates, secrets, or stored credentials required
    - Perfect for Entra ID joined devices

    Prerequisites:
    - Device must be Entra ID joined
    - User must be logged in with work account (for SSO)
    - User must have appropriate Entra ID role for LAPS access

.PARAMETER DeviceName
    The display name of the device in Entra ID for LAPS password retrieval.

.EXAMPLE
    .\Get-LapsPassword-EntraDevice.ps1 -DeviceName "DESKTOP-ABC1234"

.NOTES
    Authentication Method: Device Identity + WAM (No secrets required)
    Context: User context (leverages user's work account + device trust)
    Perfect for: Entra ID joined devices with seamless SSO
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Enter the display name of the device in Entra ID.")]
    [string]$DeviceName
)

# Define required modules and correct permission scopes
$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
$requiredScopes = @("DeviceLocalCredential.Read.All", "Device.Read.All") # Corrected scope names

function Test-EntraDeviceJoinStatus {
    <#
    .SYNOPSIS
    Verifies the device is properly Entra ID joined for seamless authentication
    #>
    
    try {
        Write-Host "🔍 Checking device Entra ID join status..." -ForegroundColor Cyan
        
        $dsregOutput = dsregcmd /status
        $joinInfo = @{}
        
        # Parse dsregcmd output
        foreach ($line in $dsregOutput) {
            if ($line -match "^\s*([^:]+?)\s*:\s*(.+)$") {
                $joinInfo[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        
        $isAzureADJoined = $joinInfo["AzureAdJoined"] -eq "YES"
        $isDomainJoined = $joinInfo["DomainJoined"] -eq "YES"
        $hasPRT = $joinInfo["AzureAdPrt"] -eq "YES"
        $prtUpdateTime = $joinInfo["AzureAdPrtUpdateTime"]
        $userEmail = $joinInfo["UserEmail"]
        
        $joinStatus = @{
            IsEntraJoined = $isAzureADJoined
            IsDomainJoined = $isDomainJoined
            HasPRT = $hasPRT
            PRTUpdateTime = $prtUpdateTime
            UserEmail = $userEmail
            CanUseWAM = $isAzureADJoined -and $hasPRT
            JoinType = if ($isAzureADJoined -and $isDomainJoined) { "Hybrid Joined" } elseif ($isAzureADJoined) { "Entra ID Joined" } elseif ($isDomainJoined) { "Domain Joined Only" } else { "Not Joined" }
        }
        
        # Display status
        Write-Host "✅ Device Join Status:" -ForegroundColor Green
        Write-Host "   Join Type: $($joinStatus.JoinType)" -ForegroundColor White
        Write-Host "   Entra ID Joined: $(if ($joinStatus.IsEntraJoined) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($joinStatus.IsEntraJoined) { 'Green' } else { 'Red' })
        Write-Host "   Has PRT: $(if ($joinStatus.HasPRT) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($joinStatus.HasPRT) { 'Green' } else { 'Red' })
        
        if ($joinStatus.UserEmail) {
            Write-Host "   Work Account: $($joinStatus.UserEmail)" -ForegroundColor Gray
        }
        
        if ($joinStatus.PRTUpdateTime) {
            Write-Host "   PRT Updated: $($joinStatus.PRTUpdateTime)" -ForegroundColor Gray
        }
        
        if ($joinStatus.CanUseWAM) {
            Write-Host "🎉 Perfect! Device can use WAM for seamless authentication" -ForegroundColor Green
        } else {
            Write-Warning "⚠️  Device may not support seamless WAM authentication"
            if (-not $joinStatus.IsEntraJoined) {
                Write-Host "   Issue: Device is not Entra ID joined" -ForegroundColor Yellow
            }
            if (-not $joinStatus.HasPRT) {
                Write-Host "   Issue: No Primary Refresh Token found" -ForegroundColor Yellow
            }
        }
        
        return $joinStatus
    }
    catch {
        Write-Warning "Could not determine device join status: $($_.Exception.Message)"
        return @{ 
            IsEntraJoined = $false
            CanUseWAM = $false 
            Error = $_.Exception.Message
        }
    }
}

function Connect-UsingDeviceIdentity {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph using device identity + WAM (no secrets required)
    #>
    param (
        [string[]]$Scopes
    )
    
    try {
        Write-Host "🚀 Initiating device-based authentication..." -ForegroundColor Cyan
        
        # Enable WAM for device-based authentication
        Write-Host "   Enabling Web Account Manager (WAM)..." -ForegroundColor Gray
        Set-MgGraphOption -EnableLoginByWAM $true
        
        # Check if already connected with required scopes
        $currentContext = Get-MgContext
        if ($currentContext) {
            $hasAllScopes = $true
            foreach ($scope in $Scopes) {
                if ($scope -notin $currentContext.Scopes) {
                    $hasAllScopes = $false
                    break
                }
            }
            
            if ($hasAllScopes) {
                Write-Host "✅ Already connected with required permissions" -ForegroundColor Green
                Write-Host "   Account: $($currentContext.Account)" -ForegroundColor Gray
                return $true
            } else {
                Write-Host "   Current connection lacks required scopes, reconnecting..." -ForegroundColor Yellow
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
        }
        
        Write-Host "   Connecting with delegated permissions..." -ForegroundColor Gray
        Write-Host "   Scopes: $($Scopes -join ', ')" -ForegroundColor Gray
        
        # Connect using device identity + user context
        # This leverages the Entra ID joined device's PRT for seamless auth
        Connect-MgGraph -Scopes $Scopes -NoWelcome
        
        $context = Get-MgContext
        if (-not $context) {
            throw "Failed to establish connection to Microsoft Graph"
        }
        
        Write-Host "✅ Successfully connected using device identity!" -ForegroundColor Green
        Write-Host "   Account: $($context.Account)" -ForegroundColor Gray
        Write-Host "   App: $($context.AppName)" -ForegroundColor Gray
        Write-Host "   Auth Method: Device Identity + WAM" -ForegroundColor Gray
        
        return $true
    }
    catch {
        Write-Error "Device identity authentication failed: $($_.Exception.Message)"
        return $false
    }
}

# --- Main Script Body ---
try {
    Write-Host "=== LAPS Password Retrieval - Entra ID Device Authentication ===" -ForegroundColor Magenta
    Write-Host "Leveraging device's Entra ID join status - NO SECRETS REQUIRED!" -ForegroundColor Cyan
    Write-Host ""
    
    #region Device Join Status Check
    $deviceStatus = Test-EntraDeviceJoinStatus
    
    if (-not $deviceStatus.IsEntraJoined) {
        throw "Device must be Entra ID joined to use this authentication method. Current status: $($deviceStatus.JoinType)"
    }
    
    if (-not $deviceStatus.HasPRT) {
        Write-Warning "⚠️  No Primary Refresh Token found. SSO may not work optimally."
        Write-Host "💡 Try logging out and back in with your work account." -ForegroundColor Cyan
    }
    #endregion
    
    #region Module Installation
    Write-Host "`n📦 Checking for required PowerShell modules..." -ForegroundColor Green
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "   Installing: $module" -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                Write-Host "   ✅ $module installed successfully" -ForegroundColor Green
            }
            catch {
                throw "Failed to install module '$module': $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "   ✅ $module" -ForegroundColor Green
        }
    }
    
    # Check for LAPS module
    if (-not (Get-Module -ListAvailable -Name "LAPS")) {
        throw "Windows LAPS module not found. Please ensure Windows updates are installed."
    }
    Import-Module LAPS -Force
    Write-Host "   ✅ LAPS module loaded" -ForegroundColor Green
    #endregion

    #region Device Identity Authentication
    Write-Host "`n🔐 Connecting using device identity..." -ForegroundColor Green
    
    $authSuccess = Connect-UsingDeviceIdentity -Scopes $requiredScopes
    
    if (-not $authSuccess) {
        throw "Failed to authenticate using device identity"
    }
    
    # Show that we're using the device's identity without storing secrets
    Write-Host "🔒 Authentication Details:" -ForegroundColor Cyan
    Write-Host "   Method: Device Identity + WAM" -ForegroundColor White
    Write-Host "   Secrets Required: None ❌" -ForegroundColor Green
    Write-Host "   Certificates Required: None ❌" -ForegroundColor Green
    Write-Host "   Uses: Entra ID Device Trust + PRT ✅" -ForegroundColor Green
    #endregion

    #region LAPS Password Retrieval
    Write-Host "`n🔍 Retrieving LAPS password..." -ForegroundColor Green
    
    Write-Host "   Searching for device: $DeviceName" -ForegroundColor Gray
    $device = Get-MgDevice -Filter "displayName eq '$DeviceName'" -ErrorAction SilentlyContinue
    
    if (-not $device) {
        throw "Device '$DeviceName' not found in Entra ID"
    }
    
    if ($device.Count -gt 1) {
        Write-Warning "Multiple devices found with name '$DeviceName'. Using first match."
        $device = $device[0]
    }

    Write-Host "   Device found: $($device.DisplayName)" -ForegroundColor Gray
    Write-Host "   Device ID: $($device.Id)" -ForegroundColor Gray

    # Retrieve LAPS password using device identity authentication
    Write-Host "   Retrieving LAPS password using device identity..." -ForegroundColor Gray
    $lapsPasswordObject = Get-LapsAADPassword -DeviceIds $device.Id -IncludePasswords -AsPlainText

    if ($lapsPasswordObject -and $lapsPasswordObject.Password) {
        Write-Host "`n" + "="*70 -ForegroundColor Cyan
        Write-Host "🎯 LAPS PASSWORD RETRIEVED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "="*70 -ForegroundColor Cyan
        Write-Host "Device Name: $($lapsPasswordObject.DeviceName)" -ForegroundColor White
        Write-Host "Account: $($lapsPasswordObject.Account)" -ForegroundColor White
        Write-Host "Password: $($lapsPasswordObject.Password)" -ForegroundColor Yellow
        Write-Host "Last Updated: $($lapsPasswordObject.PasswordUpdateTime)" -ForegroundColor White
        Write-Host "Expires: $($lapsPasswordObject.PasswordExpirationTime)" -ForegroundColor White
        Write-Host "="*70 -ForegroundColor Cyan
        
        Write-Host "`n✅ SUCCESS: Password retrieved using device identity!" -ForegroundColor Green
        Write-Host "🔐 No secrets were stored or used in this script" -ForegroundColor Green
        
        if ($deviceStatus.CanUseWAM -and $deviceStatus.HasPRT) {
            Write-Host "🎉 Used seamless SSO via Primary Refresh Token" -ForegroundColor Green
        }
    }
    else {
        Write-Warning "❌ Could not retrieve LAPS password for '$DeviceName'"
        Write-Host "`n🔧 Possible reasons:" -ForegroundColor Yellow
        Write-Host "   • LAPS not enabled for this device" -ForegroundColor White
        Write-Host "   • Password not yet rotated" -ForegroundColor White
        Write-Host "   • User lacks required Entra ID role permissions" -ForegroundColor White
        Write-Host "   • Device not properly configured for LAPS" -ForegroundColor White
    }
    #endregion

}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    
    if ($_.Exception.Message -like "*permission*" -or $_.Exception.Message -like "*authorization*") {
        Write-Host "`n🔧 PERMISSION TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "Required Entra ID roles for user:" -ForegroundColor Yellow
        Write-Host "  • Cloud Device Administrator" -ForegroundColor Yellow
        Write-Host "  • Intune Administrator" -ForegroundColor Yellow
        Write-Host "  • Global Administrator" -ForegroundColor Yellow
        Write-Host "  • Custom role with deviceLocalCredentials/password/read" -ForegroundColor Yellow
    }
    
    if ($_.Exception.Message -like "*device*" -or $_.Exception.Message -like "*join*") {
        Write-Host "`n🔧 DEVICE JOIN TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "  • Ensure device is Entra ID joined: dsregcmd /status" -ForegroundColor Yellow
        Write-Host "  • User must be logged in with work account" -ForegroundColor Yellow
        Write-Host "  • Check Primary Refresh Token status" -ForegroundColor Yellow
    }
}
finally {
    # Clean up Graph session
    if (Get-MgContext) {
        Write-Host "`n🧹 Cleaning up Graph session..." -ForegroundColor Gray
        Disconnect-MgGraph
    }
    
    Write-Host "`n📊 AUTHENTICATION SUMMARY:" -ForegroundColor Cyan
    Write-Host "Method: Device Identity (Entra ID Joined)" -ForegroundColor White
    Write-Host "Secrets Used: None" -ForegroundColor White
    Write-Host "Certificates Used: None" -ForegroundColor White
    Write-Host "WAM Enabled: Yes" -ForegroundColor White
    Write-Host "Device Trust: Leveraged" -ForegroundColor White
    Write-Host "Security: High (No stored credentials)" -ForegroundColor White
}