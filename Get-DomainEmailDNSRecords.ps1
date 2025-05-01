<#
.SYNOPSIS
    Checks email security DNS records (SPF, DKIM, DMARC) for specified domains.
    Supports interactive mode and optional report output.

.PARAMETER OutputDir
    Directory for the output report file. If not provided, no report is written.

.PARAMETER Domains
    Array of domain names to check.

.PARAMETER DomainsFile
    Path to a text file with domain names to check.

.PARAMETER Interactive
    If specified, runs in interactive mode (prompts for domains one at a time).
    
.PARAMETER Quiet
    Use with OutputDir. Do not prompt user to open the report when finished.
#>

param (
    [string]$OutputDir,
    [string[]]$Domains,
    [string]$DomainsFile,
    [switch]$Interactive,
    [switch]$Quiet
)

function Show-DomainRecords {
    param (
        [string]$domain,
        [string]$OutputFile = $null
    )

    $separator = "-" * 50

    function OutMsg {
        param (
            [string]$msg,
            [string]$fg = "White",
            [string]$bg = $null
        )
        if ($OutputFile) {
            Write-Output $msg | Out-File -FilePath $OutputFile -Append
        } else {
            if ($bg) {
                Write-Host $msg -ForegroundColor $fg -BackgroundColor $bg
            } else {
                Write-Host $msg -ForegroundColor $fg
            }
        }
    }

    OutMsg $separator
    OutMsg "Domain: $domain"

    # NS Records
    $nsRecords = Resolve-DnsName -Name $domain -Type NS -ErrorAction SilentlyContinue
    if ($nsRecords) {
        OutMsg "`nNS records:"
        $nsRecords | ForEach-Object {
            OutMsg "    $($_.NameHost)"
        }
    } else {
        OutMsg "NOITCE: No NS records found. This domain may not exist. Skipping checks for this domain." "Yellow"
        return
    }

    # MX Records
    $mxRecords = Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue
    if ($mxRecords) {
        OutMsg "`nMX records:"
        $mxRecords | ForEach-Object {
            OutMsg "    $($_.NameExchange) - Priority: $($_.Preference)"
        }
    } else {
        OutMsg "No MX records found" "Yellow"
    }

    # SPF Record (TXT with "spf")
    $spfRecords = Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings -like '*spf*' }
    if ($spfRecords) {
        OutMsg "`nSPF record:"
        $spfRecords | ForEach-Object {
            OutMsg "    $($_.Name) - $($_.Strings -join '; ')"
        }
    } else {
        OutMsg "No SPF record found" "Yellow"
    }

    OutMsg "`nDKIM records: `n    NOTICE: This script only checks for default Microsoft and Google DKIM records. Other records may exist." "Yellow"

    # Google DKIM
    $googleDkimRecords = Resolve-DnsName -Name "google._domainkey.$domain" -Type TXT -ErrorAction SilentlyContinue
    if ($googleDkimRecords) {
        OutMsg "`nGoogle DKIM records:"
        $googleDkimRecords | ForEach-Object {
            OutMsg "    $($_.Name) - $($_.Strings -join '; ')"
        }
    }

    # Microsoft 365 DKIM
    $m365Dkim1 = Resolve-DnsName -Name "selector1._domainkey.$domain" -Type CNAME -ErrorAction SilentlyContinue
    $m365Dkim2 = Resolve-DnsName -Name "selector2._domainkey.$domain" -Type CNAME -ErrorAction SilentlyContinue
    if ($m365Dkim1 -or $m365Dkim2) {
        OutMsg "`nMicrosoft 365 DKIM records:"
        if ($m365Dkim1) {
            $m365Dkim1 | ForEach-Object {
                OutMsg "    $($_.Name) - $($_.NameHost)"
            }
        }
        if ($m365Dkim2) {
            $m365Dkim2 | ForEach-Object {
                OutMsg "    $($_.Name) - $($_.NameHost)"
            }
        }
    }
    if (-not ($m365Dkim1 -or $m365Dkim2 -or $googleDkimRecords)) {
        OutMsg "No DKIM records found." "Yellow"
    }

    # DMARC
    $dmarcRecords = Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction SilentlyContinue
    if ($dmarcRecords) {
        OutMsg "`nDMARC record:"
        $dmarcRecords | ForEach-Object {
            OutMsg "    $($_.Name) - $($_.Strings -join '; ')"
        }
    } else {
        OutMsg "No DMARC record found" "Yellow"
    }

    OutMsg "" "White"
}

# Setup report output if OutputDir is provided
$Report = $false
$outputFile = $null
if ($OutputDir) {
    $Report = $true
    if (-not (Test-Path -Path $OutputDir -PathType Container)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = "$OutputDir\dns_lookup_results_$timestamp.txt"
}

function Start-InteractiveMode {
    param (
        [string]$OutputFile = $null
    )
    while ($true) {
        $input = Read-Host "Enter a domain name or email address (or type 'q' to quit)"
        if ($input -eq 'q') { break }
        if ($input -like "*@*") {
            $domain = $input.Split("@")[1]
        } else {
            $domain = $input
        }
        Show-DomainRecords -domain $domain -OutputFile $OutputFile
        if ($OutputFile) {
            Write-Host "Saved output to $OutputFile." -ForegroundColor Green
        }
    }
    Write-Host "Program terminated. Goodbye!" -ForegroundColor Green
}

# Main logic
if ($Domains -and $DomainsFile) {
    Write-Host "Please provide either -Domains or -DomainsFile, not both." -ForegroundColor Yellow -BackgroundColor Red
    exit 1
}

if (-not ($Domains -or $DomainsFile -or $Interactive)) {
    Write-Host "NOTICE: No -Domains or -DomainsFile provided. Entering interactive mode.`n" -ForegroundColor Green
    Start-InteractiveMode -OutputFile $outputFile
    exit 0
}

if ($Interactive) {
    Start-InteractiveMode -OutputFile $outputFile
    exit 0
}

if (-not $Domains) {
    $Domains = Get-Content -Path $DomainsFile
}
foreach ($domain in $Domains) {
    Show-DomainRecords -domain $domain -OutputFile $outputFile
}
if ($outputFile) {
    Write-Host "Done. Saved output to $outputFile." -ForegroundColor Green
    
    if (-not $Quiet){
        $answer = Read-Host "View the file now? [y/n]"

        if ($answer -eq 'y') {
            Invoke-Item $outputFile
        } else {
            Write-Output "Exiting"
        }
    }
}