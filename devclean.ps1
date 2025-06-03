# GraphDeviceCleanup.ps1
# Description: Azure Automation Runbook script to identify and disable/delete stale Azure AD devices using Microsoft Graph and Managed Identity.

param(
    [Parameter(Mandatory = $true)]
    [int]$DisableThresholdDays = 150,

    [Parameter(Mandatory = $true)]
    [int]$DeleteThresholdDays = 180,

    [switch]$DisableOnly,
    [switch]$DeleteDisabledDevicesOnly,

    [Parameter(Mandatory = $true)]
[bool]$TestMode = $true
)

# Step 1: Authenticate using Managed Identity
try {
    $AzureContext = (Connect-AzAccount -Identity).Context
    Write-Output "✅ Managed Identity authentication succeeded for tenant: $($AzureContext.Tenant.Id)"
} catch {
    Write-Output "❌ ERROR: Managed Identity authentication failed. Ensure the Automation Account has a System-Assigned Identity enabled."
    exit 1
}

# Step 2: Connect-MgGraph with Managed Identity token
try {
    Connect-MgGraph -AccessToken (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token | Out-Null
    Write-Output "✅ Connected to Microsoft Graph via MgGraph module."
} catch {
    Write-Output "❌ ERROR: Failed to connect to Microsoft Graph with Managed Identity. $_"
    exit 1
}

# Step 3: Get Devices older than disable threshold using Invoke-MgGraphRequest
$DisableThresholdDate = (Get-Date).AddDays(-$DisableThresholdDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
$DeviceQuery = "/devices?`$filter=approximateLastSignInDateTime le $DisableThresholdDate&`$top=100"

try {
    $DeviceResponse = Invoke-MgGraphRequest -Method GET -Uri $DeviceQuery
    $Devices = $DeviceResponse.value

    if (-not $Devices) {
        Write-Output "✅ No stale devices found."
        exit 0
    }
} catch {
    Write-Output "❌ ERROR: Failed to retrieve devices using Microsoft Graph. $_"
    exit 1
}

# Summary Report Before Actions
$DeleteThresholdDate = (Get-Date).AddDays(-$DeleteThresholdDays)
$TotalDevices = $Devices.Count
$DevicesToDisable = $Devices | Where-Object { $_.accountEnabled -eq $true }
$DevicesToDelete = $Devices | Where-Object { $_.accountEnabled -eq $false -and ([datetime]::Parse($_.approximateLastSignInDateTime) -lt $DeleteThresholdDate) }

Write-Output "📊 Total devices fetched: $TotalDevices"
Write-Output "📉 Devices eligible for disable: $($DevicesToDisable.Count)"
Write-Output "🗑️ Devices eligible for delete: $($DevicesToDelete.Count)"

# Step 4: Loop through and apply action
foreach ($Device in $Devices) {
    $DeviceId = $Device.id
    $DeviceName = $Device.displayName
    $LastSeen = $Device.approximateLastSignInDateTime
    $LastSeenDate = [datetime]::Parse($LastSeen)

    Write-Output "➡️ Processing device: $DeviceName ($DeviceId), LastSignIn: $LastSeen"

    if ($DeleteDisabledDevicesOnly -and -not $Device.accountEnabled -and $LastSeenDate -lt $DeleteThresholdDate) {
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would delete disabled device: $DeviceName"
        } else {
            try {
                Invoke-MgGraphRequest -Method DELETE -Uri "/devices/$DeviceId"
                Write-Output "🗑️ Deleted disabled device: $DeviceName"
            } catch {
                Write-Output "❌ Failed to delete $DeviceName. $_"
            }
        }
    } elseif ($DisableOnly -and $Device.accountEnabled) {
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would disable device: $DeviceName"
        } else {
            $PatchBody = @{ accountEnabled = $false } | ConvertTo-Json -Depth 3
            try {
                Invoke-MgGraphRequest -Method PATCH -Uri "/devices/$DeviceId" -Body $PatchBody
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
