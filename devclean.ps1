# GraphDeviceCleanup.ps1
# Description: Azure Automation Runbook script to identify and disable/delete stale Azure AD devices using Microsoft Graph and Managed Identity.
# Note: This script is compliant with PowerShell 5.1, uses Az.Accounts for Managed Identity authentication, and avoids AzureRM module conflicts.

param(
    [int]$DisableThresholdDays = 150,
    [int]$DeleteThresholdDays = 180,
    [switch]$DisableOnly,
    [switch]$DeleteDisabledDevicesOnly,
    [bool]$TestMode = $true
)

# Validate required modules
try {
    Import-Module Az.Accounts -ErrorAction Stop
    Write-Output "✅ Az.Accounts module is available and imported."
} catch {
    Write-Output "❌ ERROR: Az.Accounts module is missing or failed to load. $_"
    exit 1
}

# Authenticate using Managed Identity
try {
    $AzureContext = (Connect-AzAccount -Identity).Context
    Write-Output "✅ Managed Identity authentication succeeded for tenant: $($AzureContext.Tenant.Id)"
} catch {
    Write-Output "❌ ERROR: Managed Identity authentication failed. Ensure the Automation Account has a System-Assigned Identity enabled."
    exit 1
}

# Acquire Microsoft Graph token
try {
    $AccessToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    Write-Output "✅ Access token for Microsoft Graph acquired."
} catch {
    Write-Output "❌ ERROR: Failed to acquire Microsoft Graph token. $_"
    exit 1
}

# Step 3: Get all Devices using Microsoft Graph REST API
$DisableThresholdDate = (Get-Date).AddDays(-$DisableThresholdDays)
try {
    $Headers = @{ Authorization = "Bearer $AccessToken" }
    $uri = "https://graph.microsoft.com/v1.0/devices?`$top=999"
    $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method GET -ErrorAction Stop
    $Devices = $response.value

    if (-not $Devices) {
        Write-Output "✅ No devices found in tenant."
        exit 0
    }
} catch {
    Write-Output "❌ ERROR: Failed to retrieve devices using Microsoft Graph REST API. $_"
    exit 1
}

# Filter results client-side
$DeleteThresholdDate = (Get-Date).AddDays(-$DeleteThresholdDays)
$DevicesToDisable = $Devices | Where-Object { $_.AccountEnabled -eq $true -and [datetime]::Parse($_.ApproximateLastSignInDateTime) -lt $DisableThresholdDate }
$DevicesToDelete = $Devices | Where-Object { $_.AccountEnabled -eq $false -and [datetime]::Parse($_.ApproximateLastSignInDateTime) -lt $DeleteThresholdDate }

Write-Output "📊 Total devices fetched: $($Devices.Count)"
Write-Output "📉 Devices eligible for disable: $($DevicesToDisable.Count)"
Write-Output "🗑️ Devices eligible for delete: $($DevicesToDelete.Count)"

# Step 4: Loop through and apply action
foreach ($Device in $Devices) {
    $DeviceId = $Device.Id
    $DeviceName = $Device.DisplayName
    $LastSeen = $Device.ApproximateLastSignInDateTime
    $LastSeenDate = [datetime]::Parse($LastSeen)

    Write-Output "➡️ Processing device: $DeviceName ($DeviceId), LastSignIn: $LastSeen"

    if ($DeleteDisabledDevicesOnly -and -not $Device.AccountEnabled -and $LastSeenDate -lt $DeleteThresholdDate) {
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would delete disabled device: $DeviceName"
        } else {
            try {
                $uri = "https://graph.microsoft.com/v1.0/devices/$DeviceId"
                Invoke-RestMethod -Uri $uri -Headers $Headers -Method DELETE -ErrorAction Stop
                Write-Output "🗑️ Deleted disabled device: $DeviceName"
            } catch {
                Write-Output "❌ Failed to delete $DeviceName. $_"
            }
        }
    } elseif ($DisableOnly -and $Device.AccountEnabled -and $LastSeenDate -lt $DisableThresholdDate) {
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would disable device: $DeviceName"
        } else {
            $PatchBody = @{ accountEnabled = $false } | ConvertTo-Json -Depth 3
            try {
                $uri = "https://graph.microsoft.com/v1.0/devices/$DeviceId"
                Invoke-RestMethod -Uri $uri -Headers $Headers -Method PATCH -Body $PatchBody -ContentType "application/json" -ErrorAction Stop
                Write-Output "🚫 Disabled device: $DeviceName"
            } catch {
                Write-Output "❌ Failed to disable $DeviceName. $_"
            }
        }
    } else {
        Write-Output "ℹ️ Skipped device: $DeviceName (conditions not met)."
    }
}

Write-Output "✅ Device cleanup run completed."
