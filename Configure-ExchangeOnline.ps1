<#
.SYNOPSIS
    TODO fill this in.

.DESCRIPTION
    TODO
    
.PARAMETER tenantOnmicrosoftDomain
    The tenant's .onmicrosoft domain name. Use Get-AcceptedDomain or check at https://admin.microsoft.com/#/Domains
    
    Type: String
    Mandatory: Yes

.PARAMETER primaryEmailDomain
    The primary email domain for the tenant.
    
    Type: String[]
    Mandatory: Yes

.PARAMETER enableAutoExpandingArchive
    Toggles whether to enable or disable the Auto Expanding Archive. 
    
    Type: Bool[]
    Mandatory: Yes
    Default: $false


.PARAMETER enablePersonalArchive
    Toggles whether to enable or disable the Personal Archive Mailbox. 
    
    Type: Bool[]
    Mandatory: Yes
    Default: $false

.EXAMPLE
    TODO
    
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$tenantOnmicrosoftDomain,

    [Parameter(Mandatory=$true)]
    [string[]]$primaryEmailDomain,
    
    [bool]$enableAutoExpandingArchive = $false,
    
    [bool]$enablePersonalArchive = $false

)


# Enable Organization Customization
Enable-OrganizationCustomization

# Enable Unified Audit Log
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

#Disable SMTP
$answer = Read-Host 'Do you want to disable SMTP? This is recommended, but check if SMTP is in use first using the SMTP Auth Clients Report.'

while ($answer -ne 'Yes' -and $answer -ne 'No') {
    $answer = Read-Host 'Please enter Yes or No.'
}

if ($answer -eq 'Yes') {
    Write-Host "Disabling SMTP"
    Set-TransportConfig -SmtpClientAuthenticationDisabled $true
} elseif ($answer -eq 'No') {
    Write-Output "Skipping SMTP disable"
}

#Create a rule to block .onmicrosoft domains

#Changing the postmaster address prevents blocking some internal notifications
Set-TransportConfig -ExternalPostmasterAddress "postmaster@$primaryEmailDomain"


New-TransportRule -Name "Block onmicrosoft domains" `
    -FromAddressContainsWords "onmicrosoft.com", "@onmicrosoft.com" `
    -RejectMessageEnhancedStatusCode "5.7.1" `
    -RejectMessageReasonText "You can’t send emails to this recipient" `
    -ExceptIfFromAddressContainsWords $tenantOnmicrosoftDomain
    
# Disable access to consumer storage locations such as DropBox, Gsuite and OneDrive (personal) in Outlook on the Web
Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $False

# Set the deleted items retention period to the maximum 30 days
# https://github.com/vanvfields/Microsoft-365/blob/master/Exchange%20Online/Set-DeletedItemsRetention.ps1
$MessageColor = "cyan"
$AssessmentColor = "magenta"
Write-Host 
$CurrentRetention = (Get-Mailbox -ResultSize Unlimited).RetainDeletedItemsFor
Write-Host -ForegroundColor $AssessmentColor "Current retention limit (in days and number of mailboxes):"
$CurrentRetention | group | select name, count | ft
Write-Host 
$Answer = Read-Host "By default Exchange Online retains deleted items for 14 days; would you like to enforce the maximum allowed value of 30 days for all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30
    Get-MailboxPlan | Set-MailboxPlan -RetainDeletedItemsFor 30
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Deleted items will be retained for the maximum of 30 days for all mailboxes"
    } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "The deleted items retention value has not been modified on any mailboxes"
    }

# Enable PDF Encryption in encrypted messages
$IRMConfig = Get-IRMConfiguration
if (!$IRMConfig.EnablePdfEncryption) {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "PDF attachments are not encrypted by OME"
    Write-Host
    $Answer = Read-Host "Do you want to enable encryption of PDF attachments in OME protected messages? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-IRMConfiguration -EnablePdfEncryption $true
        Write-Host
        Write-Host -ForegroundColor $MessageColor "PDF attachments will now be encrypted by OME"
    } 
    else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "PDF attachments will not be encrypted by OME"
    }
} 
else {
    Write-Host
    Write-Host -ForegroundColor $MessageColor "PDF attachments are already being encrypted by OME"
}

#Enable Auto-Expanding Archive
if ($enableAutoExpandingArchive) {
    Write-Host "Enabling the Auto-Expanding Archive."
    Set-OrganizationConfig -AutoExpandingArchive
}

#Enable Personal Archive Mailbox
if ($enablePersonalArchive) {
    Get-Mailbox -ResultSize Unlimited -Filter {
        ArchiveStatus -Eq "None" -AND
        RecipientTypeDetails -eq "UserMailbox"
    } | Enable-Mailbox -Archive
}

# Add custom transport rules

# Define HTML disclaimer templates
$HTMLDisclaimerSuspiciousAttachment = @'
    <p>
        <div style="background-color:#FFD700; width:100%; border-style: solid; border-color:#800000; border-width:1pt; padding:2pt; font-size:10pt; line-height:12pt; font-family:\'Arial\'; color:Black; text-align: left;">
            <span style="color:#A52A2A;">
                <b><strong>CAUTION:</strong></b>
            </span>
            A potentially malicious attachment, such as a .ZIP file or macro-enabled document, was detected. While these attachments may be legitimate, these types of files can contain malicious code. Do not open these attachments if you were not expecting them, even if you know the sender. Please contact your IT provider with any questions.
        </div>
        <br>
    </p>
'@

$HTMLDisclaimerSuspiciousContent = @'
    <p>
        <div style="background-color:#FFD700; width:100%; border-style: solid; border-color:#800000; border-width:1pt; padding:2pt; font-size:10pt; line-height:12pt; font-family:'Arial'; color:Black; text-align: left;">
            <span style="color:#A52A2A;">
                <b><strong>CAUTION:</strong></b>
            </span>
            This email has a suspicious subject or content, such as a message asking for a payment or password. This may be legitimate, but please take care when clicking links or opening attachments. When in doubt, don't click! Please contact your IT provider with any questions.
        </div>
        <br>
    </p>
'@

# Create transport rules

# Define lists of attachment and ransomware extensions
$suspiciousExtensions = 'dotm', 'docm', 'xlsm', 'sltm', 'xla', 'xlam', 'xll', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm', 'htm', 'html', 'zip'
$ransomwareExtensions = 'ade', 'adp', 'ani', 'bas', 'bat', 'chm', 'cmd', 'com', 'cpl', 'crt', 'hlp', 'ht', 'hta', 'inf', 'ins', 'isp', 'job', 'js', 'jse', 'lnk', 'mda', 'mdb', 'mde', 'mdz', 'msc', 'msi', 'msp', 'mst', 'pcd', 'reg', 'scr', 'sct', 'shs', 'url', 'vb', 'vbe', 'vbs', 'wsc', 'wsf', 'wsh', 'exe', 'pif'

# Define list of suspicious email patterns
$suspiciousEmailPatterns = @(
    "Password.*[expire|reset]",
    "Password access",
    "[reset|change|update].*password",
    "Change.*password",
    "\.odt",
    "E-Notification",
    "EMERGENCY",
    "Retrieve.*document",
    "Download.*document",
    "confirm ownership for",
    "word must be installed",
    "prevent further unauthorized",
    "prevent further unauthorised",
    "informations has been",
    "follow our process",
    "confirm your informations",
    "failed to validate",
    "unable to verify",
    "delayed payment",
    "activate your account",
    "Update your payment",
    "submit your payment",
    "via Paypal",
    "has been compromised",
    "FRAUD NOTICE",
    "your account will be closed",
    "your apple id was used to sign in to",
    "was blocked for violation",
    "urged to download",
    "that you validate your account",
    "multiple login attempt",
    "trying to access your account",
    "suspend your account",
    "restricted if you fail to update",
    "informations on your account",
    "update your account information",
    "update in our security",
    "Unusual sign-in activity",
    "Account Was Limited",
    "verify and reactivate",
    "has.*been.*limited",
    "have.*locked",
    "has.*been.*suspended",
    "unusual.*activity",
    "notifications.*pending",
    "your\ (customer\ )?account\ has",
    "your\ (customer\ )?account\ was",
    "new.*voice(\ )?mail",
    "Periodic.*Maintenance",
    "refund.*not.*approved",
    "account.*(is\ )?on.*hold",
    "wire.*transfer",
    "secure.*update",
    "secure.*document",
    "temporar(il)?y.*deactivated",
    "verification.*required",
    "blocked\ your?\ online",
    "suspicious\ activit",
    "securely*.onedrive",
    "securely*.dropbox",
    "securely*.google drive",
    "view message",
    "view attachment"
)

# Create and configure transport rules

# RULE ONE: Suspicious attachment rule: warn users
New-TransportRule -Name "Suspicious Attachment Rule: Warn Users" `
    -AttachmentExtensionMatchesWords $suspiciousExtensions `
    -ApplyHtmlDisclaimerLocation Prepend `
    -ApplyHtmlDisclaimerText $HTMLDisclaimerSuspiciousAttachment `
    -ApplyHtmlDisclaimerFallbackAction Wrap `
    -Enabled $true

# RULE TWO: Anti-ransomware rule: block file types
New-TransportRule -Name "Anti-ransomware Rule: Block File Types" `
    -AttachmentExtensionMatchesWords $ransomwareExtensions `
    -RejectMessageReasonText "Your message was rejected. For security reasons, certain attachment types are blocked. Please contact your IT provider with any questions." `
    -Enabled $true

# RULE THREE: Suspicious External Email Content Warning
New-TransportRule -Name "Suspicious External Email Content Warning" `
    -FromScope NotInOrganization `
    -SentToScope InOrganization `
    -SubjectOrBodyMatchesPatterns $suspiciousEmailPatterns `
    -ApplyHtmlDisclaimerLocation Prepend `
    -ApplyHtmlDisclaimerText $HTMLDisclaimerSuspiciousContent `
    -ApplyHtmlDisclaimerFallbackAction Wrap `
    -ExceptIfSenderDomainIs "greenmtnitsolutions.com", "greenmtnit.com" `
    -Enabled $true

# Display rules as a check
Write-Host "`nListing all transport rules now" -ForegroundColor Green
Get-TransportRule