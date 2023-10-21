# Define HTML disclaimer templates
$HTMLDisclaimerSuspiciousAttachment = @'
<table border=0 cellspacing=0 cellpadding=0 align="left" width="100%">
  <tr>
    <td style="background:#ffb900;padding:5pt 2pt 5pt 2pt"></td>
    <td width="100%" cellpadding="7px 6px 7px 15px" style="background:#fff8e5;padding:5pt 4pt 5pt 12pt;word-wrap:break-word">
   <div style="color:#222222;">
        <span style="color:#222; font-weight:bold;">Warning:</span>
        A possible malicious attachment was detected, such as a .zip file or Macro-enabled Office document. While these attachments may be legitimate, these types of files can contain malicious code. Do not open these attachments if you were not expecting them. Also note that knowing the sender is NOT a guarantee of safety. Please contact your IT provider with any questions.
      </div>
    </td>
  </tr>
</table>
<br/>
'@

$HTMLDisclaimerSuspiciousContent = @'
<table border=0 cellspacing=0 cellpadding=0 align="left" width="100%">
  <tr>
    <td style="background:#ffb900;padding:5pt 2pt 5pt 2pt"></td>
    <td width="100%" cellpadding="7px 6px 7px 15px" style="background:#fff8e5;padding:5pt 4pt 5pt 12pt;word-wrap:break-word">
   <div style="color:#222222;">
        <span style="color:#222; font-weight:bold;">Caution:</span>
        This is an external email and has a suspicious subject or content, such as a message asking for a payment or password. This may be legitimate, but please take care when clicking links or opening attachments. When in doubt, don't click! Please contact your IT provider with any questions.
      </div>
    </td>
  </tr>
</table>
<br/>
'@

# Create transport rules

# Define lists of attachment and ransomware extensions
$suspiciousExtensions = 'dotm', 'docm', 'xlsm', 'sltm', 'xla', 'xlam', 'xll', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm', 'htm', 'html', 'zip'
$ransomwareExtensions = 'ade', 'adp', 'ani', 'bas', 'bat', 'chm', 'cmd', 'com', 'cpl', 'crt', 'hlp', 'ht', 'hta', 'inf', 'ins', 'isp', 'job', 'js', 'jse', 'lnk', 'mda', 'mdb', 'mde', 'mdz', 'msc', 'msi', 'msp', 'mst', 'pcd', 'reg', 'scr', 'sct', 'shs', 'url', 'vb', 'vbe', 'vbs', 'wsc', 'wsf', 'wsh', 'exe', 'pif'

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
