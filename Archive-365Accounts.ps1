<#

Archive-365Accounts.ps1

.SYNOPSIS
This script updates Microsoft 365 user accounts by appending "ARCHIVED -" to their display names and disabling their accounts.
You can use this script to bulk rename and disable old 365 accounts.

.DESCRIPTION
The script uses the Microsoft Graph PowerShell SDK to perform bulk updates on user accounts. It accepts a CSV file path as a parameter, reads a list of UserPrincipalNames, retrieves user details, updates their display names to include "ARCHIVED -", and disables their accounts.

.PARAMETER CsvPath
The path to the CSV file containing the list of UserPrincipalNames. The CSV must have a column named 'UserPrincipalName'.

.EXAMPLE
# Connect to Microsoft Graph first:
Connect-MgGraph -Scopes "User.ReadWrite.All" -UseDeviceCode

# Run the script:
.\Archive-365Accounts

.NOTES
- Ensure the Microsoft Graph PowerShell SDK is installed (`Install-Module Microsoft.Graph`).
- You must have appropriate permissions in Microsoft Graph (e.g., `User.ReadWrite.All`).
- Always test the script on a small dataset before running it in production.

.INPUTS
CSV file containing UserPrincipalNames of users to archive.

.OUTPUTS
Logs messages indicating success or failure for each user update.

.EXAMPLE CSV Layout:
UserPrincipalName
jdoe@contoso.com
rroe@contoso.com
hsimpson@contoso.com

#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the full path to the CSV file.")]
    [string]$CsvPath
)

$users = Import-Csv -Path $CsvPath

# Prompt the user for confirmation
$confirmation = Read-Host -Prompt "Are you sure you want to proceed with user archiving? (Yes/No)"

if ($confirmation -ne "Yes") {
    Write-Host "Operation cancelled."
    return  # Exit the script if the user does not confirm
}

Write-Host "Proceeding with user archiving..."

foreach ($user in $users) {
    # Get the current user details
    $upn = $user.UserPrincipalName
    $user = Get-MgUser -UserId $upn -Property "DisplayName"

    if ($user) {
        # Construct the new display name
        $newDisplayName = "ARCHIVED - $($user.DisplayName)"

        # Update the user's display name
        Update-MgUser -UserId $upn -DisplayName $newDisplayName

        #Disable the account
        Update-MgUser -UserId $upn -AccountEnabled:$false
        
        Write-Host "Updated display name for $upn to '$newDisplayName' and disabled the account."
    } else {
        Write-Host "User not found: $upn"
    }
}