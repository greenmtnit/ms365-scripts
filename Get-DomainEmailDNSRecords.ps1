<#
.SYNOPSIS
    Checks and reports on email security DNS records (SPF, DKIM, DMARC, MX, NS) for one or more domains.
    Supports interactive mode, batch mode, and optional report file output.

.DESCRIPTION
    This script performs DNS lookups for a set of domains to gather information about their email security configuration.
    It checks for:
      - NS (Name Server) records
      - MX (Mail Exchanger) records
      - SPF (Sender Policy Framework) records
      - DKIM (DomainKeys Identified Mail) records for default Microsoft 365 and Google selectors
      - DMARC (Domain-based Message Authentication, Reporting & Conformance) records

    You can specify domains directly, provide a file containing domains, or run in interactive mode to enter domains one at a time.
    If no domains or domain file are provided, the script automatically enters interactive mode.

    Results can be displayed in the console or saved to a timestamped report file in a specified directory.
    When a report is generated, you can optionally prompt the user to open the report file upon completion.

.PARAMETER OutputDir
    If specified, saves the DNS lookup results to a timestamped text report in this directory.
    If not provided, results are output only to the console.

.PARAMETER Domains
    An array of domain names to check. Cannot be used with -DomainsFile.

.PARAMETER DomainsFile
    Path to a text file containing a list of domain names to check (one per line). Cannot be used with -Domains.

.PARAMETER Interactive
    If specified, runs in interactive mode, prompting the user to enter domains or email addresses one at a time.

.PARAMETER Quiet
    Used only when -OutputDir is specified.
    Suppresses the prompt to open the report file when the script finishes.

.EXAMPLE
    .\Check-EmailDnsRecords.ps1 -Domains "example.com","contoso.com"

    Checks the specified domains and displays results in the console.

.EXAMPLE
    .\Check-EmailDnsRecords.ps1 -DomainsFile "C:\domains.txt" -OutputDir "C:\Reports"

    Checks all domains listed in "C:\domains.txt" and writes a report to the "C:\Reports" directory.

.EXAMPLE
    .\Check-EmailDnsRecords.ps1 -Interactive

    Runs in interactive mode, prompting for domains, one by one.

.EXAMPLE
    .\Check-EmailDnsRecords.ps1 -OutputDir "C:\Reports" -Quiet

    Runs in interactive mode (since no domains or file are specified), writes a report, and does not prompt to open the file.

.NOTES
    - If both -Domains and -DomainsFile are provided, the script will exit with an error.
    - If neither -Domains, -DomainsFile, nor -Interactive is specified, the script will enter interactive mode by default.
    - Only default DKIM selectors for Microsoft 365 and Google are checked; custom selectors are not detected.
    - Requires PowerShell 5.1+ and network access for DNS queries.
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