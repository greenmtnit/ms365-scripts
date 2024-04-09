param (
    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [string[]]$Domains,

    [string]$DomainsFile
)

# Check if both $Domains and $DomainsFile are provided
if ($Domains -and $DomainsFile) {
    Write-Host "Please provide either a list of domains or a path to a domains text file, but not both."
    Exit
}

# If neither $Domains nor $DomainsFile is provided, exit
if (-not ($Domains -or $DomainsFile)) {
    Write-Host "Please provide either a list of domains or a path to a domains text file."
    exit 1
}

# If the Domains parameter is not provided, read the list of domains from the text file
if (-not $Domains) {
    $Domains = Get-Content -Path $DomainsFile
}

# Check if the output directory exists
if (-not (Test-Path -Path $OutputDir -PathType Container)) {
    # Output directory doesn't exist, create it
    New-Item -Path $OutputDir -ItemType Directory -Force
}


$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "$OutputDir\dns_lookup_results_$timestamp.txt"

# Loop through each domain and lookup NS, MX, TXT, CNAME, and _dmarc records
foreach ($domain in $domains) {
    $separator = "-" * 50
    Write-Output "$separator" | Out-File -FilePath $outputFile -Append
    Write-Output "Domain: $domain" | Out-File -FilePath $outputFile -Append
    try {
        # Lookup NS records
        Write-Output "NS Records:" | Out-File -FilePath $outputFile -Append
        Resolve-DnsName -Name $domain -Type NS -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "  $($_.NameHost)" | Out-File -FilePath $outputFile -Append
        }

        # Lookup MX records
        Write-Output "MX Records:" | Out-File -FilePath $outputFile -Append
        Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "  $($_.NameExchange) - Priority: $($_.Preference)" | Out-File -FilePath $outputFile -Append
        }
        
        # Lookup TXT records with "spf" in the value
        Write-Output "SPF Record:" | Out-File -FilePath $outputFile -Append
        Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings -like '*spf*' } | ForEach-Object {
            Write-Output "  $($_.Name) - $($_.Strings -join '; ')" | Out-File -FilePath $outputFile -Append
        }

        # Lookup TXT records containing "google._domainkey" in the hostname
        Write-Output "Google DKIM records:" | Out-File -FilePath $outputFile -Append
        Resolve-DnsName -Name "google._domainkey.$domain" -Type TXT -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "  $($_.Name) - $($_.Strings -join '; ')" | Out-File -FilePath $outputFile -Append
        }

        # Lookup CNAME records for selector1._domainkey and selector2._domainkey
        Write-Output "Microsoft 365 DKIM records:" | Out-File -FilePath $outputFile -Append
        Resolve-DnsName -Name "selector1._domainkey.$domain" -Type CNAME -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "  $($_.Name) - $($_.NameHost)" | Out-File -FilePath $outputFile -Append
        }
        Resolve-DnsName -Name "selector2._domainkey.$domain" -Type CNAME -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "  $($_.Name) - $($_.NameHost)" | Out-File -FilePath $outputFile -Append
        }

        # Lookup _dmarc TXT records
        Write-Output "DMARC records:" | Out-File -FilePath $outputFile -Append
        Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "  $($_.Name) - $($_.Strings -join '; ')" | Out-File -FilePath $outputFile -Append
        }

    } catch {
        Write-Output "Error occurred while looking up records for $domain $_" | Out-File -FilePath $outputFile -Append
    }
    Write-Output "`n" | Out-File -FilePath $outputFile -Append
}

Write-Host "Done. Saved output to $outputFile."
