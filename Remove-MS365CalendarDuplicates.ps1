<#
    Remove-MS365CalendarDuplicates.ps1
  
    .SYNOPSIS
        Removes duplicate calendar events for a given Microsoft 365 user.

    .DESCRIPTION
        Retrieves all calendar events for the specified user via Microsoft Graph,
        groups them by subject and start time, and deletes all but the first
        occurrence of any duplicates found.
        
        Requires Microsoft Graph PowerShell SDK with a connected session
        and appropriate Calendar permissions.
    
    .NOTES
        Create an application registration in Microsoft 365 first. This script will not work with delegated permissions.
        
            - Go to the Entra Portal > App registrations
            - Create a new app registration
            - Name: Graph-Calendar-Script (or whatever name you prefer)
            - Supported account types: Accounts in this organizational directory only
            - Redirect URI: [leave blank]
            - Add these Microsoft Graph application API permissions
                - Calendars.ReadWrite
                - User.Read.All
            - Grant admin consent
            - Create a new client secret at Certificates & secrets
                - Copy the secret value. It will not be shown again.
            - Copy the Application (client) ID
            - Copy the Directory (tenant) ID

        Use this to connect to Graph before running the script:
            $tenantId = "<tenant ID>"
            $clientId = "<app (client) ID"
            $ClientSecretText = "<secret value>"
            $clientSecret = ConvertTo-SecureString $ClientSecretText -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($clientId, $clientSecret)
            Connect-MgGraph -NoWelcome -ClientSecretCredential $credential -TenantId $tenantId

    .PARAMETER UserID
        The UPN or object ID of the Microsoft 365 user whose calendar will
        be deduplicated. For example: jdoe@contoso.com

    .PARAMETER PrintDuplicates
        When specified, prints a formatted table of each duplicate event set
        before deletion. Useful for reviewing what was found.

    .PARAMETER DryRun
        When specified, reports what would be deleted without actually deleting
        anything. Recommended for a first pass before running for real.

    .EXAMPLE
        .\Remove-CalendarDupes.ps1 -UserID "jdoe@contoso.com" -DryRun
        
        Checks for duplicates and reports what would be deleted, without
        making any changes.

    .EXAMPLE
        .\Remove-CalendarDupes.ps1 -UserID "jdoe@contoso.com" -DryRun -PrintDuplicates
        
        Checks for duplicates, prints a detailed table of each duplicate set,
        and reports what would be deleted without making any changes.

    .EXAMPLE
        .\Remove-CalendarDupes.ps1 -UserID "jdoe@contoso.com"
        
        Removes duplicate calendar events for the specified user.

    .NOTES
        Requires: Microsoft Graph PowerShell SDK
        Permissions: Calendars.ReadWrite, User.Read.All
#>

[CmdletBinding()]
param (
    # User to deduplicate events for, e.g. jdoe@contoso.com
    [Parameter(Mandatory = $true)]
    [string]$UserID,

    # Print a list of duplicates
    [switch]$PrintDuplicates = $false,
    
    # Print what would be deleted, but don't actually delete.
    [switch]$DryRun = $false
)

# Get all events
$events = Get-MgUserEvent -UserId $userId -All

# Group by subject + start time to find duplicates
$dupes = $events | Group-Object { "$($_.Subject)|$($_.Start.DateTime)" } | Where-Object { $_.Count -gt 1 }

if (-not $dupes) {
    Write-Host "No duplicates found!"
}

else {
    # Optional - print duplicates
    if ($PrintDuplicates) {
        foreach ($group in $dupes) {
            Write-Host "`nDuplicate Set ($($group.Count) events)" -ForegroundColor Yellow
            Write-Host "Key: $($group.Name)"

            $group.Group | Select-Object `
                Subject,
                @{Name='Start';Expression={$_.Start.DateTime}},
                @{Name='End';Expression={$_.End.DateTime}},
                Id |
            Format-Table -AutoSize
        }
    }

    # Remove the duplicates
    foreach ($group in $dupes) {
        $toDelete = $group.Group | Select-Object -Skip 1

        foreach ($event in $toDelete) {
            if ($DryRun) {
                Write-Host "DRY RUN: would have deleted event $($event.Subject)."
            }
            else {
                Write-Host "Deleting Event $($event.Subject)..."
                Remove-MgUserEvent -UserId $userId -EventId $event.Id
            }
        }
    }
    Write-Host "Duplicate removal complete."
}