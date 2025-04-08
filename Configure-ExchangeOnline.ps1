<#
.SYNOPSIS
    Configures reccomended settings in Exchange Online.

.DESCRIPTION
    - Enables organization customization
    - Enables the Unified Audit Log
    - Disables SMTP (optional)
    - Disable access to consumer storage locations such as DropBox, Gsuite and OneDrive (personal) in Outlook on the Web
    - Sets the deleted items retention period to the maximum 30 days
    - Enables PDF Encryption in encrypted messages
    - (Optionally) Enables Auto-Expanding Archive
    - (Optionally) Enables Personal Archive Mailbox
    - Creates mail flow rules:
        - Rule to block .onmicrosoft domains (these are abused more than they're legitimately used)

.PARAMETER PrimaryEmailDomain
    The primary email domain for the tenant.
    
    Type: String[]
    Mandatory: Yes
    
.PARAMETER TenantOnmicrosoftDomain
    The tenant's .onmicrosoft domain name. Use Get-AcceptedDomain or check at https://admin.microsoft.com/#/Domains
    
    Type: String
    Mandatory: Yes
    
.PARAMETER DisableSMTP
    Toggles whether to disable SMTP (reccomended). Check the SMTP Auth Report first: 
    https://admin.exchange.microsoft.com/#/reports/smtpauthmailflowdetails    
    
    Type: Bool[]
    Default: $true 

.PARAMETER EnableAutoExpandingArchive
    Toggles whether to enable or disable the Auto Expanding Archive. 
    
    Type: Bool[]
    Default: $false


.PARAMETER EnablePersonalArchive
    Toggles whether to enable or disable the Personal Archive Mailbox. 
    
    Type: Bool[]
    Default: $false

.EXAMPLE
    Configure with all reccomended settings for Contoso's tenant:
    .\Configure-ExchangeOnline -PrimaryEmailDomain contoso.com -TenantOnmicrosoftDomain contoso.onmicrosoft.com
    
    Do not disable SMTP:
    .\Configure-ExchangeOnline -PrimaryEmailDomain contoso.com -TenantOnmicrosoftDomain contoso.onmicrosoft.com -DisableSMTP $false

    
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$PrimaryEmailDomain,
    
    [Parameter(Mandatory=$true)]
    [string]$TenantOnmicrosoftDomain,
    
    [bool]$DisableSMTP = $true,
    
    [bool]$EnableAutoExpandingArchive = $false,
    
    [bool]$EnablePersonalArchive = $false

)

# Colors for formatiing output
$MessageColor = "cyan"
$AssessmentColor = "magenta"

Write-Host

# Enable Organization Customization
Write-Host -ForegroundColor $MessageColor "`nEnabling organization customization"
Enable-OrganizationCustomization

# Enable Unified Audit Log
Write-Host -ForegroundColor $MessageColor "`nEnabling Unified Audit Log"
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# Disable SMTP
if ($DisableSMTP) {
    Write-Host -ForegroundColor $MessageColor "`nDisabling SMTP"
    Set-TransportConfig -SmtpClientAuthenticationDisabled $true
}

# Disable access to consumer storage locations such as DropBox, Gsuite and OneDrive (personal) in Outlook on the Web
Write-Host -ForegroundColor $MessageColor "`nDisabling Consumer Storage"
Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $False

# Set the deleted items retention period to the maximum 30 days
# https://github.com/vanvfields/Microsoft-365/blob/master/Exchange%20Online/Set-DeletedItemsRetention.ps1
$CurrentRetention = (Get-Mailbox -ResultSize Unlimited).RetainDeletedItemsFor
Write-Host -ForegroundColor $MessageColor "`nSetting deleted items retention"
Write-Host -ForegroundColor $AssessmentColor "Current retention limit (in days and number of mailboxes):"
$CurrentRetention | group | select name, count | ft
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30
Get-MailboxPlan | Set-MailboxPlan -RetainDeletedItemsFor 30
Write-Host -ForegroundColor $MessageColor "Deleted items will now be retained for the maximum of 30 days for all mailboxes"

# Enable PDF Encryption in encrypted messages
Write-Host -ForegroundColor $MessageColor "`nEnabling PDF Encryption"
$IRMConfig = Get-IRMConfiguration
if (!$IRMConfig.EnablePdfEncryption) {
    Write-Host -ForegroundColor $AssessmentColor "PDF attachments are not encrypted by OME"
    Set-IRMConfiguration -EnablePdfEncryption $true
    Write-Host -ForegroundColor $MessageColor "PDF attachments will now be encrypted by OME" 
} 
else {
    Write-Host -ForegroundColor $MessageColor "PDF attachments are already being encrypted by OME"
}

# Enable Auto-Expanding Archive
if ($EnableAutoExpandingArchive) {
    Write-Host -ForegroundColor $MessageColor "`nEnabling the Auto-Expanding Archive."
    Set-OrganizationConfig -AutoExpandingArchive
}

# Enable Personal Archive Mailbox
if ($EnablePersonalArchive) {
    Write-Host -ForegroundColor $MessageColor "`nEnabling Personal Archive"
    Get-Mailbox -ResultSize Unlimited -Filter {
        ArchiveStatus -Eq "None" -AND
        RecipientTypeDetails -eq "UserMailbox"
    } | Enable-Mailbox -Archive
}

# CREATE MAIL FLOW RULES

# Define HTML disclaimer templates
$HTMLDisclaimerSuspiciousAttachment = @'
    <p>
        <div style="background-color:#FFD700; width:100%; border-style: solid; border-color:#800000; border-width:1pt; padding:2pt; font-size:10pt; line-height:12pt; font-family:\'Arial\'; color:Black; text-align: left;">
            <span style="color:#A52A2A;">
                <b><strong>CAUTION:</strong></b>
            </span>
            A suspicious attachment type was detected. While these attachments may be legitimate, these types of files can contain malicious code. Do not open these attachments if you were not expecting them, even if you know the sender. Please contact your IT provider with any questions.
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

# Define lists of suspicious and malicious extensions
$suspiciousExtensions = 'dotm', 'docm', 'xlsm', 'sltm', 'xla', 'xlam', 'xll', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm', 'htm', 'html', 'zip'
$maliciousExtensions = 'ade', 'adp', 'ani', 'bas', 'bat', 'chm', 'cmd', 'com', 'cpl', 'crt', 'hlp', 'ht', 'hta', 'inf', 'ins', 'isp', 'job', 'js', 'jse', 'lnk', 'mda', 'mdb', 'mde', 'mdz', 'msc', 'msi', 'msp', 'mst', 'pcd', 'reg', 'scr', 'sct', 'shs', 'url', 'vb', 'vbe', 'vbs', 'wsc', 'wsf', 'wsh', 'exe', 'pif'

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

Write-Host -ForegroundColor $MessageColor "`nCreating transport rules"

# RULE ONE: block .onmicrosoft domains


Write-Host -ForegroundColor $MessageColor "`nRULE ONE: block .onmicrosoft domains"

# Changing the postmaster address prevents blocking some internal notifications that come from .onmicrosoft.com domains
Set-TransportConfig -ExternalPostmasterAddress "postmaster@$PrimaryEmailDomain"

New-TransportRule -Name "Block onmicrosoft domains" `
    -FromAddressContainsWords "onmicrosoft.com", "@onmicrosoft.com" `
    -RejectMessageEnhancedStatusCode "5.7.1" `
    -RejectMessageReasonText "You can’t send emails to this recipient" `
    -ExceptIfFromAddressContainsWords $TenantOnmicrosoftDomain

# RULE TWO: Suspicious attachment rule: warn users

Write-Host -ForegroundColor $MessageColor "`nRULE TWO: Suspicious attachment rule: warn users"

New-TransportRule -Name "Suspicious Attachment Rule: Warn Users" `
    -AttachmentExtensionMatchesWords $suspiciousExtensions `
    -ApplyHtmlDisclaimerLocation Prepend `
    -ApplyHtmlDisclaimerText $HTMLDisclaimerSuspiciousAttachment `
    -ApplyHtmlDisclaimerFallbackAction Wrap `
    -Enabled $true

# RULE THREE: Malicious attachment rule: block file types

Write-Host -ForegroundColor $MessageColor "`nRULE THREE: Malicious attachment rule: block file types"

New-TransportRule -Name "Malicious Attachment Rule: Block File Types" `
    -AttachmentExtensionMatchesWords $maliciousExtensions `
    -RejectMessageReasonText "Your message was rejected. For security reasons, certain attachment types are blocked. Please contact your IT provider with any questions." `
    -Enabled $true

# RULE FOUR: Suspicious External Email Content Warning

Write-Host -ForegroundColor $MessageColor "`n RULE FOUR: Suspicious External Email Content Warning"

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
Write-Host -ForegroundColor $MessageColor "`nListing all transport rules now"
Get-TransportRule