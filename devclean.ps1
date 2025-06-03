# GraphDeviceCleanup.ps1
# Description: Azure Automation Runbook script to identify and disable/delete stale Azure AD devices using Microsoft Graph and Managed Identity.

param(
    [int]$DisableThresholdDays = 150,
    [int]$DeleteThresholdDays = 180,
    [switch]$DisableOnly,
    [switch]$DeleteDisabledDevicesOnly,
    [bool]$TestMode = $true
)



# Validate required modules
# Ensure Az.Accounts module is present and AzureRM is not
try {
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Output "❌ ERROR: Required module 'Az.Accounts' is not installed."
        exit 1
    }
    if (Get-Module -ListAvailable -Name AzureRM*) {
        Write-Output "❌ ERROR: AzureRM modules detected. These conflict with Az modules. Please remove AzureRM modules from your Automation Account."
        exit 1
    }
    Import-Module Az.Accounts -ErrorAction Stop
    Write-Output "✅ Az.Accounts module is available and imported."
} catch {
    Write-Output "❌ ERROR: Failed to validate or import Az.Accounts module. $_"
    exit 1
}


try {
    $requiredModules = @(
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Devices.CorporateManagement'
    )

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Output "❌ ERROR: Required module '$module' is not installed. Please add it to the Automation Account."
            exit 1
        }
        Import-Module $module -ErrorAction Stop
    }

    Write-Output "✅ Required Microsoft Graph modules are available and imported."
} catch {
    Write-Output "❌ ERROR: Failed to validate or import required Microsoft Graph modules. $_"
    exit 1
}

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

# Step 3: Get Devices using Get-MgDevice
$DisableThresholdDate = (Get-Date).AddDays(-$DisableThresholdDays)

try {
    $Devices = Get-MgDevice -All | Where-Object {
        $_.ApproximateLastSignInDateTime -and ([datetime]$_.ApproximateLastSignInDateTime -le $DisableThresholdDate)
    }

    if (-not $Devices) {
        Write-Output "✅ No stale devices found."
        exit 0
    }
} catch {
    Write-Output "❌ ERROR: Failed to retrieve devices using Get-MgDevice. $_"
    exit 1
}

# Summary Report Before Actions
$DeleteThresholdDate = (Get-Date).AddDays(-$DeleteThresholdDays)
$TotalDevices = $Devices.Count
$DevicesToDisable = $Devices | Where-Object { $_.AccountEnabled -eq $true }
$DevicesToDelete = $Devices | Where-Object { $_.AccountEnabled -eq $false -and ([datetime]::Parse($_.ApproximateLastSignInDateTime) -lt $DeleteThresholdDate) }

Write-Output "📊 Total devices fetched: $TotalDevices"
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
                Remove-MgDevice -DeviceId $DeviceId -ErrorAction Stop
                Write-Output "🗑️ Deleted disabled device: $DeviceName"
            } catch {
                Write-Output "❌ Failed to delete $DeviceName. $_"
            }
        }
    } elseif ($DisableOnly -and $Device.AccountEnabled) {
        if ($TestMode) {
            Write-Output "🧪 [TestMode] Would disable device: $DeviceName"
        } else {
            $PatchBody = @{ accountEnabled = $false } | ConvertTo-Json -Depth 3
            try {
                Update-MgDevice -DeviceId $DeviceId -BodyParameter $PatchBody -ErrorAction Stop
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
