param(
    [int]$DisableThresholdDays = 150,
    [int]$DeleteThresholdDays = 180,
    [switch]$DisableOnly,
    [switch]$DeleteDisabledDevicesOnly,
    [bool]$TestMode = $true,
    [bool]$ShowTokenDetails = $false
)

function Get-DateSafe {
    param([string]$dateString)
    if ([string]::IsNullOrWhiteSpace($dateString)) { 
        return $null 
    }
    try { 
        return [datetime]::Parse($dateString) 
    } catch { 
        return $null 
    }
}

# Import required modules
try {
    Import-Module Az.Accounts -ErrorAction Stop
    Write-Output "✅ Az.Accounts module is available and imported."
} catch {
    Write-Output "❌ ERROR: Az.Accounts module is missing or failed to load. $($_.Exception.Message)"
    exit 1
}

try {
    Import-Module Az.Profile -ErrorAction Stop
    Write-Output "✅ Az.Profile module is available and imported."
} catch {
    Write-Output "⚠️ WARNING: Az.Profile module not available, continuing without it."
}

# Connect using Managed Identity
try {
    $AzureContext = Connect-AzAccount -Identity
    if ($AzureContext.Context) {
        $TenantId = $AzureContext.Context.Tenant.Id
        Write-Output "✅ Managed Identity authentication succeeded for tenant: $TenantId"
    } else {
        throw "Failed to get Azure context"
    }
} catch {
    Write-Output "❌ ERROR: Managed Identity authentication failed. Ensure the Automation Account has a System-Assigned Identity enabled."
    Write-Output "Error details: $($_.Exception.Message)"
    exit 1
}

# Get access token for Microsoft Graph
try {
    $Resource = "https://graph.microsoft.com"
    $AccessTokenResponse = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AzureContext.Context.Account, $AzureContext.Context.Environment, $TenantId, $null, "Never", $null, $Resource)
    $AccessToken = $AccessTokenResponse.AccessToken
    
    if ([string]::IsNullOrEmpty($AccessToken)) {
        throw "Access token is null or empty"
    }
    
    Write-Output "✅ Access token for Microsoft Graph acquired."

    if ($ShowTokenDetails) {
        Write-Output "🔎 Token Details:"
        Write-Output "TenantId: $TenantId"
        Write-Output "Token Length: $($AccessToken.Length)"
    }
} catch {
    Write-Output "❌ ERROR: Failed to acquire Microsoft Graph token. $($_.Exception.Message)"
    exit 1
}

# Calculate threshold dates
$DisableThresholdDate = (Get-Date).AddDays(-$DisableThresholdDays)
$DeleteThresholdDate = (Get-Date).AddDays(-$DeleteThresholdDays)

Write-Output "📅 Disable threshold date: $($DisableThresholdDate.ToString('yyyy-MM-dd'))"
Write-Output "📅 Delete threshold date: $($DeleteThresholdDate.ToString('yyyy-MM-dd'))"

# Retrieve devices with paging
try {
    $Headers = @{
        Authorization  = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    
    $baseUri = "https://graph.microsoft.com/v1.0/devices?`$top=999&`$select=id,displayName,accountEnabled,approximateLastSignInDateTime"
    $Devices = @()
    $uri = $baseUri
    $pageCount = 0
    
    do {
        $pageCount++
        Write-Output "📄 Fetching page $pageCount..."
        
        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method GET -ErrorAction Stop
        $Devices += $response.value
        $uri = $response.'@odata.nextLink'
        
        Write-Output "📊 Retrieved $($response.value.Count) devices from page $pageCount"
    } while ($uri)
    
    if ($Devices.Count -eq 0) {
        Write-Output "✅ No devices found in tenant."
        exit 0
    }
    
    Write-Output "📊 Total devices fetched: $($Devices.Count)"
} catch {
    Write-Output "❌ ERROR: Failed to retrieve devices using Microsoft Graph REST API."
    Write-Output "Details: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        Write-Output "Status Code: $($_.Exception.Response.StatusCode)"
    }
    exit 1
}

# Filter devices safely
$DevicesToDisable = @()
$DevicesToDelete = @()

foreach ($device in $Devices) {
    $lastSeenDate = Get-DateSafe $device.approximateLastSignInDateTime
    
    if ($device.accountEnabled -eq $true -and $lastSeenDate -and $lastSeenDate -lt $DisableThresholdDate) {
        $DevicesToDisable += $device
    }
    
    if ($device.accountEnabled -eq $false -and $lastSeenDate -and $lastSeenDate -lt $DeleteThresholdDate) {
        $DevicesToDelete += $device
    }
}

Write-Output "📉 Devices eligible for disable: $($DevicesToDisable.Count)"
Write-Output "🗑️ Devices eligible for delete: $($DevicesToDelete.Count)"

# Process devices based on parameters
$processedCount = 0
$successCount = 0
$errorCount = 0

if ($DeleteDisabledDevicesOnly) {
    Write-Output "🔄 Processing disabled devices for deletion..."
    foreach ($Device in $DevicesToDelete) {
        $processedCount++
        $DeviceId = $Device.id
        $DeviceName = $Device.displayName
        $LastSeen = $Device.approximateLastSignInDateTime
        
        Write-Output "➡️ [$processedCount/$($DevicesToDelete.Count)] Processing device: $DeviceName, LastSignIn: $LastSeen"
        
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would delete disabled device: $DeviceName"
            $successCount++
        } else {
            try {
                $uri = "https://graph.microsoft.com/v1.0/devices/$DeviceId"
                Invoke-RestMethod -Uri $uri -Headers $Headers -Method DELETE -ErrorAction Stop
                Write-Output "🗑️ Successfully deleted disabled device: $DeviceName"
                $successCount++
            } catch {
                Write-Output "❌ Failed to delete $DeviceName. $($_.Exception.Message)"
                $errorCount++
            }
        }
    }
} elseif ($DisableOnly) {
    Write-Output "🔄 Processing enabled devices for disabling..."
    foreach ($Device in $DevicesToDisable) {
        $processedCount++
        $DeviceId = $Device.id
        $DeviceName = $Device.displayName
        $LastSeen = $Device.approximateLastSignInDateTime
        
        Write-Output "➡️ [$processedCount/$($DevicesToDisable.Count)] Processing device: $DeviceName, LastSignIn: $LastSeen"
        
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would disable device: $DeviceName"
            $successCount++
        } else {
            $PatchBody = @{ accountEnabled = $false } | ConvertTo-Json -Depth 3
            try {
                $uri = "https://graph.microsoft.com/v1.0/devices/$DeviceId"
                Invoke-RestMethod -Uri $uri -Headers $Headers -Method PATCH -Body $PatchBody -ContentType "application/json" -ErrorAction Stop
                Write-Output "🚫 Successfully disabled device: $DeviceName"
                $successCount++
            } catch {
                Write-Output "❌ Failed to disable $DeviceName. $($_.Exception.Message)"
                $errorCount++
            }
        }
    }
} else {
    Write-Output "🔄 Processing devices for both disable and delete operations..."
    
    # First disable eligible devices
    foreach ($Device in $DevicesToDisable) {
        $processedCount++
        $DeviceId = $Device.id
        $DeviceName = $Device.displayName
        $LastSeen = $Device.approximateLastSignInDateTime
        
        Write-Output "➡️ [$processedCount] Disabling device: $DeviceName, LastSignIn: $LastSeen"
        
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would disable device: $DeviceName"
            $successCount++
        } else {
            $PatchBody = @{ accountEnabled = $false } | ConvertTo-Json -Depth 3
            try {
                $uri = "https://graph.microsoft.com/v1.0/devices/$DeviceId"
                Invoke-RestMethod -Uri $uri -Headers $Headers -Method PATCH -Body $PatchBody -ContentType "application/json" -ErrorAction Stop
                Write-Output "🚫 Successfully disabled device: $DeviceName"
                $successCount++
            } catch {
                Write-Output "❌ Failed to disable $DeviceName. $($_.Exception.Message)"
                $errorCount++
            }
        }
    }
    
    # Then delete eligible disabled devices
    foreach ($Device in $DevicesToDelete) {
        $processedCount++
        $DeviceId = $Device.id
        $DeviceName = $Device.displayName
        $LastSeen = $Device.approximateLastSignInDateTime
        
        Write-Output "➡️ [$processedCount] Deleting disabled device: $DeviceName, LastSignIn: $LastSeen"
        
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would delete disabled device: $DeviceName"
            $successCount++
        } else {
            try {
                $uri = "https://graph.microsoft.com/v1.0/devices/$DeviceId"
                Invoke-RestMethod -Uri $uri -Headers $Headers -Method DELETE -ErrorAction Stop
                Write-Output "🗑️ Successfully deleted disabled device: $DeviceName"
                $successCount++
            } catch {
                Write-Output "❌ Failed to delete $DeviceName. $($_.Exception.Message)"
                $errorCount++
            }
        }
    }
}

# Summary
Write-Output ""
Write-Output "📋 EXECUTION SUMMARY:"
Write-Output "Total devices processed: $processedCount"
Write-Output "Successful operations: $successCount"
Write-Output "Failed operations: $errorCount"
Write-Output "Test Mode: $TestMode"

if ($TestMode) {
    Write-Output "⚠️ Running in TEST MODE - no actual changes were made"
} else {
    Write-Output "✅ Device cleanup run completed with actual changes"
}

if ($errorCount -gt 0) {
    Write-Output "⚠️ Some operations failed. Check the logs above for details."
    exit 1
} else {
    Write-Output "✅ All operations completed successfully."
    exit 0
}