<#
    Reset-365UsersPasswords.ps1
    
    Quick and dirty script to bulk reset 365 user's passwords. May need work.
    
    Resets passwords for all users with a certain domain in their username.
    Set a temporary password for each.
    A password change will be required on next login.
    Uses pwpush.com API to generate a secure link to share the temporary password.
    
#>


# Script will change password of all users with this domain in their UPN!
$domain = "contoso.com" 

# Users to exclude
$excludedUsers =@( 
    "jdoe@contoso.com",
    "admin@contoso.com"
)

# Output CSV file
$outputFile = "C:\!TECH\TemporaryPasswords.csv"

################################
# MAIN SCRIPT
################################

# PWPush.com API Token
$PWPushApiToken = Read-Host -Prompt "Enter PWPush.com API token"

# Temporary password settings
# (Adjust complexity as needed)
function New-RandomPassword {
    param (
        [int]$length = 12
    )

    $lower   = "abcdefghjkmnpqrstuvwxyz"   # removed i, l, o
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"   # removed I, O
    $numbers = "23456789"                    # removed 0, 1
    $symbols = "!@#$*?"

    # Build the body (all letters and numbers, no symbols)
    $bodyChars = $lower + $upper + $numbers

    # Ensure at least one of each type in the body
    $passwordChars = @()
    $passwordChars += $lower[(Get-Random -Maximum $lower.Length)]
    $passwordChars += $upper[(Get-Random -Maximum $upper.Length)]
    $passwordChars += $numbers[(Get-Random -Maximum $numbers.Length)]

    # Fill remaining length minus 1 (symbol goes at end)
    for ($i = $passwordChars.Count; $i -lt ($length - 1); $i++) {
        $passwordChars += $bodyChars[(Get-Random -Maximum $bodyChars.Length)]
    }

    # Shuffle the body, then append one symbol at the end
    $shuffled = $passwordChars | Sort-Object { Get-Random }
    $symbol = $symbols[(Get-Random -Maximum $symbols.Length)]

    return (-join $shuffled) + $symbol
}

# Get PWPush Link
function New-PWPushSecret {
    param (
        [Parameter(Mandatory)]
        [string]$ApiToken,

        [Parameter(Mandatory)]
        [string]$SecretValue,

        [int]$ExpireAfterDuration = 10,  # default: expire after 5 days. See here for values: https://us.pwpush.com/help/api/pushes#pushes-create
        [int]$ExpireAfterViews = 3,     # default: expire after 3 views

        [string]$Passphrase = $null,
        [string]$Name = $null,
        [string]$Note = $null,

        [bool]$DeletableByViewer = $true,
        [bool]$RetrievalStep = $true,

        [string]$Region = "us"
    )

    $baseUrl = "https://$Region.pwpush.com"
    $uri = "$baseUrl/api/v2/pushes"

    $headers = @{
        Authorization = "Bearer $ApiToken"
        "Content-Type" = "application/json"
    }

    # Build request body
    $push = @{
        payload               = $SecretValue
        expire_after_duration = $ExpireAfterDuration
        expire_after_views    = $ExpireAfterViews
        deletable_by_viewer   = $DeletableByViewer
        retrieval_step        = $RetrievalStep
        kind                  = "text"
    }

    if ($Passphrase) { $push.passphrase = $Passphrase }
    if ($Name)       { $push.name = $Name }
    if ($Note)       { $push.note = $Note }

    $body = @{
        push = $push
    } | ConvertTo-Json -Depth 5

    try {
        $response = Invoke-RestMethod `
            -Uri $uri `
            -Method POST `
            -Headers $headers `
            -Body $body

        return [PSCustomObject]@{
            ShareURL        = $response.html_url
            Token           = $response.url_token
            ExpiresAt       = $response.expires_at
            ViewsRemaining  = $response.views_remaining
            HasPassphrase   = [bool]$response.passphrase
        }
    }
    catch {
        Write-Error "Failed to create push: $_"
    }
}

# Get all enabled users (skip guests if desired)
$users = Get-MgUser -All | Where-Object { $_.UserPrincipalName -like "*@$domain" -and $_.UserPrincipalName -notin $excludedUsers}

# Prepare results array
$results = @()

foreach ($user in $users) {
    try {
        $tempPassword = New-RandomPassword

        Write-Host "Resetting password for $($user.UserPrincipalName)"

        # Reset password + require change
        # TODO
        Update-MgUserPassword -UserId $user.Id -BodyParameter @{
            passwordProfile = @{
                password = $tempPassword
                forceChangePasswordNextSignIn = $true
            }
        }
        
        # Get PWPush Link
        # Sleep 1 second to avoid hitting rate limit
        Start-Sleep 1
        $PwPushLink = (New-PWPushSecret -ApiToken $PWPushApiToken -SecretValue $tempPassword).ShareURL

        # Store in results
        $results += [PSCustomObject]@{
            DisplayName        = $user.DisplayName
            UserPrincipalName  = $user.UserPrincipalName
            TemporaryPassword  = $tempPassword
            PwPushLink         = $PwPushLink
        }
    }
    catch {
        Write-Host "Failed for $($user.UserPrincipalName): $_" -ForegroundColor Red
    }
}

# Export to CSV
$results | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "Password reset complete. Output saved to $outputFile"