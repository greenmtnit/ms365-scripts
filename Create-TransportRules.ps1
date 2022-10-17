#Suspicious attachment rule: warn users
Write-Host "Creating transport rule ... Suspicious attachment rule: warn users" -ForegroundColor Green
$HTMLDisclaimerSuspiciousAttachment = '<table border=0 cellspacing=0 cellpadding=0 align="left" width="100%">  <tr> <td style="background:#ffb900;padding:5pt 2pt 5pt 2pt"></td> <td width="100%" cellpadding="7px 6px 7px 15px" style="background:#fff8e5;padding:5pt 4pt 5pt 12pt;word-wrap:break-word"> <div style="color:#ff0000;"> <span style="color:#222; font-weight:bold;"></span> WARNING! Possible malicious attachment detected! Do not open these attachments (unless you were expecting them) because the files may contain malicious code. Also note that knowing the sender is NOT a guarantee of safety. Be careful! </div> </td> </tr> </table> <br/>' 
New-TransportRule "Suspicious attachment rule: warn users" `
-AttachmentExtensionMatchesWords 'dotm','docm','xlsm','sltm','xla','xlam','xll','pptm','potm','ppam','ppsm','sldm' , 'htm', 'html', 'zip'`
-ApplyHtmlDisclaimerLocation Prepend `
-ApplyHtmlDisclaimerText $HTMLDisclaimerSuspiciousAttachment `
-ApplyHtmlDisclaimerFallbackAction Wrap `
-Enabled $true
Write-Host "Transport rule created" -ForegroundColor Green

#Anti-ransomware rule: block file types
Write-Host "Creating transport rule ... Anti-ransomware rule: block file types" -ForegroundColor Green
New-TransportRule "Anti-ransomware rule: block file types" `
-AttachmentExtensionMatchesWords 'ade','adp','ani','bas','bat','chm','cmd','com','cpl','crt','hlp','ht','hta','inf','ins','isp','job','js','jse','lnk','mda','mdb','mde','mdz','msc','msi','msp','mst','pcd','reg','scr','sct','shs','url','vb','vbe','vbs','wsc','wsf','wsh','exe','pif' `
-RejectMessageReasonText "Your message was rejected. A possible malicious attachment was detected." `
-Enabled $true
Write-Host "Transport rule created" -ForegroundColor Green

#Suspicious External Email Warning
Write-Host "Creating transport rule ... Suspicious External Email Warning" -ForegroundColor Green
#
$HTMLDisclaimerSuspiciousExternalEmail = '<table border=0 cellspacing=0 cellpadding=0 align="left" width="100%">
  <tr>
    <td style="background:#ffb900;padding:5pt 2pt 5pt 2pt"></td>
    <td width="100%" cellpadding="7px 6px 7px 15px" style="background:#fff8e5;padding:5pt 4pt 5pt 12pt;word-wrap:break-word">
   <div style="color:#222222;">
        <span style="color:#222; font-weight:bold;">Caution:</span>
        This is an external email and has a suspicious subject or content, such as a message asking for a payment or password. Please take care when clicking links or opening attachments. When in doubt, contact your IT provider.
      </div>
    </td>
  </tr>
</table>
<br/>'


New-TransportRule -Name "Suspicious External Email Warning" `
                  -FromScope NotInOrganization `
                  -SentToScope InOrganization `
                  -SubjectOrBodyMatchesPatterns `
                      "Password.*[expire|reset]", `
                      "Password access", `
                      "[reset|change|update].*password", `
                      "Change.*password", `
                      "\.odt", `
                      "E-Notification", `
                      "EMERGENCY", `
                      "Retrieve*.document", `
                      "Download*.document", `
                      "confirm ownership for", `
                      "word must be installed", `
                      "prevent further unauthorized", `
                      "prevent further unauthorised", `
                      "informations has been", `
                      "fallow our process", `
                      "confirm your informations", `
                      "failed to validate", `
                      "unable to verify", `
                      "delayed payment", `
                      "activate your account", `
                      "Update your payment", `
                      "submit your payment", `
                      "via Paypal", `
                      "has been compromised", `
                      "FRAUD NOTICE", `
                      "your account will be closed", `
                      "your apple id was used to sign in to", `
                      "was blocked for violation", `
                      "urged to download", `
                      "that you validate your account", `
                      "multiple login attempt", `
                      "trying to access your account", `
                      "suspend your account", `
                      "restricted if you fail to update", `
                      "informations on your account", `
                      "update your account information", `
                      "update in our security", `
                      "Unusual sign-in activity", `
                      "Account Was Limited", `
                      "verify and reactivate", `
                      "has.*been.*limited", `
                      "have.*locked", `
                      "has.*been.*suspended", `
                      "unusual.*activity", `
                      "notifications.*pending", `
                      "your\ (customer\ )?account\ has", `
                      "your\ (customer\ )?account\ was", `
                      "new.*voice(\ )?mail", `
                      "Periodic.*Maintenance", `
                      "refund.*not.*approved", `
                      "account.*(is\ )?on.*hold", `
                      "wire.*transfer", `
                      "secure.*update", `
                      "secure.*document", `
                      "temporar(il)?y.*deactivated", `
                      "verification.*required", `
                      "blocked\ your?\ online", `
                      "suspicious\ activit", `
                      "securely*.onedrive", `
                      "securely*.dropbox", `
                      "securely*.google drive", `
                      "view message", `
                      "view attachment" `
                  -ApplyHtmlDisclaimerLocation Prepend `
                  -ApplyHtmlDisclaimerText $HTMLDisclaimerSuspiciousExternalEmail `
                  -ApplyHtmlDisclaimerFallbackAction Wrap `
                  -ExceptIfSenderDomainIs "greenmtnitsolutions.com", "greenmtnit.com"
#
Write-Host "Transport rule created" -ForegroundColor Green

# Display Rules
Write-Host "`nListing all transport rules now" -ForegroundColor Green
Get-TransportRule
