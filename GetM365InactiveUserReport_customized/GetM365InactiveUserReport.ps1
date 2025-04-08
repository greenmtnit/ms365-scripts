<#
=============================================================================================
Name:           Export Microsoft 365 Inactive Users Report using MS Graph PowerShell
Version:        1.0
website:        o365reports.com

CUSTOMIZED BY GREEN MOUNTAIN IT SOLUTIONS

Script Highlights:
~~~~~~~~~~~~~~~~~
1.The single script allows you to generate 10+ different inactive user reports.
2.The script can be executed with an MFA-enabled account too. 
3.The script supports Certificate-based authentication (CBA). 
4.Provides details about non-interactive sign-ins too. 
5.You can generate reports based on inactive days.
6.Helps to filter never logged-in users alone. 
7.Generates report for sign-in enabled users alone. 
8.Supports filtering licensed users alone. 
9.Gets inactive external users report. 
10.Export results to CSV file. 
11.The assigned licenses column will show you the user-friendly-name like ‘Office 365 Enterprise E3’ rather than ‘ENTERPRISEPACK’. 
12.Automatically installs the MS Graph PowerShell module (if not installed already) upon your confirmation. 
13.The script is scheduler friendly.

For detailed Script execution:  https://o365reports.com/2023/06/21/microsoft-365-inactive-user-report-ms-graph-powershell
============================================================================================
#>

Param
(
    [int]$InactiveDays,
    [int]$InactiveDays_NonInteractive,
    [switch]$ReturnNeverLoggedInUser,
    [switch]$EnabledUsersOnly,
    [switch]$DisabledUsersOnly,
    [switch]$LicensedUsersOnly,
    [switch]$ExternalUsersOnly,
    [switch]$CreateSession,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$ExportCSV  # Optional parameter for custom export path

)

Function Connect_MgGraph {
    # Check if the Microsoft Graph Beta module is installed
    $MsGraphBetaModule = Get-Module Microsoft.Graph.Beta -ListAvailable
    if ($MsGraphBetaModule -eq $null) {
        Write-Host "Important: Microsoft Graph Beta module is unavailable. It is mandatory to have this module installed in the system to run the script successfully."

        # Prompt user to install the module
        $confirm = Read-Host "Are you sure you want to install Microsoft Graph Beta module? [Y] Yes [N] No"
        if ($confirm -match "[yY]") {
            Write-Host "Installing Microsoft Graph Beta module..."
            Install-Module Microsoft.Graph.Beta -Scope CurrentUser -AllowClobber
            Write-Host "Microsoft Graph Beta module is installed in the machine successfully" -ForegroundColor Magenta
        } else {
            Write-Host "Exiting. `nNote: Microsoft Graph Beta module must be available in your system to run the script" -ForegroundColor Red
            Exit
        }
    }

    # Check if a session should be created and disconnect any existing session
    if ($CreateSession.IsPresent) {
        # Disconnect existing MgGraph session
        Disconnect-MgGraph

        # Connecting to MgGraph beta
        Write-Host "Connecting to Microsoft Graph..."
        if (($TenantId -ne "") -and ($ClientId -ne "") -and ($CertificateThumbprint -ne "")) {
            Connect-MgGraph -TenantId $TenantId -AppId $ClientId -CertificateThumbprint $CertificateThumbprint
        } else {
            Connect-MgGraph -Scopes "User.Read.All", "AuditLog.read.All" -UseDeviceCode
        }
    }
}

Connect_MgGraph

# Check if Microsoft Graph is connected
$context = Get-MgContext

if ($context -ne $null) {
    Write-Host "Microsoft Graph is already connected." -ForegroundColor Green
    Write-Host "Connected Account: $($context.Account)"
    Write-Host "Tenant ID: $($context.TenantId)"
    Write-Host "Scopes: $($context.Scopes -join ', ')"
} else {
    Write-Host "Microsoft Graph is not connected." -ForegroundColor Yellow
    $confirm = Read-Host "Try connecting now? [Y] Yes [N] No"
    if ($confirm -match "[yY]") {
        Connect_MgGraph
    }
    else {
        Write-Host "Could not connect Graph. Exiting." -ForegroundColor Red
        exit 0
    }
}

Write-Host "`nNote: If you encounter module related conflicts, run the script in a fresh PowerShell window."


# Determine export CSV path based on user input or default value
if ([string]::IsNullOrEmpty($ExportCSV)) {
    # Default path if ExportCSVPath is not provided
    $ExportCSV = ".\InactiveM365UserReport_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm-ss` tt).ToString()).csv"
}

$ExportResult=""   
$ExportResults=@()  

#Get friendly name of license plan from external file
$FriendlyNameHash=Get-Content -Raw -Path .\LicenseFriendlyName.txt -ErrorAction Stop | ConvertFrom-StringData

$Count=0
$PrintedUser=0
#retrieve users
$RequiredProperties=@('UserPrincipalName','DisplayName','EmployeeId','CreatedDateTime','AccountEnabled','Department','JobTitle','RefreshTokensValidFromDateTime','SigninActivity')
Get-MgBetaUser -All -Property $RequiredProperties | select $RequiredProperties | ForEach-Object {
 $Count++
 $UPN=$_.UserPrincipalName
 Write-Progress -Activity "`n     Processing user: $Count - $UPN"
 $DisplayName=$_.DisplayName
 $EmployeeId=$_.EmployeeId
 $LastInteractiveSignIn=$_.SignInActivity.LastSignInDateTime
 $LastNon_InteractiveSignIn=$_.SignInActivity.LastNonInteractiveSignInDateTime
 $CreatedDate=$_.CreatedDateTime
 $AccountEnabled=$_.AccountEnabled
 $Department=$_.Department
 $JobTitle=$_.JobTitle
 $RefreshTokenValidFrom=$_.RefreshTokensValidFromDateTime
 #Calculate Inactive days
 if($LastInteractiveSignIn -eq $null)
 {
  $LastInteractiveSignIn = "Never Logged In"
  $InactiveDays_InteractiveSignIn = "-"
 }
 else
 {
  $InactiveDays_InteractiveSignIn = (New-TimeSpan -Start $LastInteractiveSignIn).Days
 }
 if($LastNon_InteractiveSignIn -eq $null)
 {
  $LastNon_InteractiveSignIn = "Never Logged In"
  $InactiveDays_NonInteractiveSignIn = "-"
 }
 else
 {
  $InactiveDays_NonInteractiveSignIn = (New-TimeSpan -Start $LastNon_InteractiveSignIn).Days
 }
 if($AccountEnabled -eq $true)
 {
  $AccountStatus='Enabled'
 }
 else
 {
  $AccountStatus='Disabled'
 }

 #Get licenses assigned to mailboxes
 $Licenses = (Get-MgBetaUserLicenseDetail -UserId $UPN).SkuPartNumber
 $AssignedLicense = @()

 #Convert license plan to friendly name
 if($Licenses.count -eq 0)
 {
  $LicenseDetails = "No License Assigned"
 }
 else
 {
  foreach($License in $Licenses)
  {
   $EasyName = $FriendlyNameHash[$License]
   if(!($EasyName))
   {$NamePrint = $License}
   else
   {$NamePrint = $EasyName}
   $AssignedLicense += $NamePrint
  }
  $LicenseDetails = $AssignedLicense -join ", "
 }
 $Print=1


 #Inactive days based on interactive signins filter
 if($InactiveDays_InteractiveSignIn -ne "-")
 {
  if(($InactiveDays -ne "") -and ($InactiveDays -gt $InactiveDays_InteractiveSignIn))
  {
   $Print=0
  }
 }
    
 #Inactive days based on non-interactive signins filter
 if($InactiveDays_NonInteractiveSignIn -ne "-")
 {
  if(($InactiveDays_NonInteractive -ne "") -and ($InactiveDays_NonInteractive -gt $InactiveDays_NonInteractiveSignIn))
  {
   $Print=0
  }
 }

 #Never Logged In user
 if(($ReturnNeverLoggedInUser.IsPresent) -and ($LastInteractiveSignIn -ne "Never Logged In"))
 {
  $Print=0
 }

 #Filter for external users
 if(($ExternalUsersOnly.IsPresent) -and ($UPN -notmatch '#EXT#'))
 {
   $Print=0
 }
 
 #Signin Allowed Users
 if($EnabledUsersOnly.IsPresent -and $AccountStatus -eq 'Disabled')
 {      
  $Print=0
 }

 #Signin disabled users
 if($DisabledUsersOnly.IsPresent -and $AccountStatus -eq 'Enabled')
 {
  $Print=0
 }

 #Licensed Users ony
 if($LicensedUsersOnly -and $Licenses.Count -eq 0)
 {
  $Print=0
 }

 #Export users to output file
 if($Print -eq 1)
 {
  $PrintedUser++
  $ExportResult=[PSCustomObject]@{'UPN'=$UPN;'DisplayName'=$DisplayName;'Account Status'=$AccountStatus;'Creation Date'=$CreatedDate;'Last Interactive SignIn Date'=$LastInteractiveSignIn;'Last Non Interactive SignIn Date'=$LastNon_InteractiveSignIn;'Inactive Days(Interactive SignIn)'=$InactiveDays_InteractiveSignIn;'Inactive Days(Non-Interactive Signin)'=$InactiveDays_NonInteractiveSignin;'Refresh Token Valid From'=$RefreshTokenValidFrom;'Emp id'=$EmployeeId;'License Details'=$LicenseDetails;'Department'=$Department;'Job Title'=$JobTitle}
  $ExportResult | Export-Csv -Path $ExportCSV -Notype -Append
 }
}

#Open output file after execution
Write-Host `nScript executed successfully.
if((Test-Path -Path $ExportCSV) -eq "True")
{
    Write-Host "Exported report has $PrintedUser user(s)." 
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?",` 0,"Open Output File",4)
    if ($UserInput -eq 6)
    {
        Invoke-Item "$ExportCSV"
    }
    Write-Host "Detailed report available in:" -NoNewline -ForegroundColor Yellow; Write-Host "$ExportCSV"
}
else
{
    Write-Host "No user found" -ForegroundColor Red
}
Write-Host `n~~ Script prepared by AdminDroid Community ~~`n -ForegroundColor Green
Write-Host "~~ Check out " -NoNewline -ForegroundColor Green; Write-Host "admindroid.com" -ForegroundColor Yellow -NoNewline; Write-Host " to get access to 1800+ Microsoft 365 reports. ~~" -ForegroundColor Green `n`n