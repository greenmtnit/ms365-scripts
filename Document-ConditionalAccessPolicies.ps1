<#
.SYNOPSIS
    Exports all Entra ID Conditional Access policies to Markdown, CSV, and JSON.

.DESCRIPTION
    Connects to Microsoft Graph with read-only delegated permissions, retrieves every
    Conditional Access policy, resolves IDs (users, groups, roles, apps, named locations)
    to display names, and saves:
      - CA-Policies.md   : readable documentation (one table per policy)
      - CA-Policies.csv  : one-line summary per policy
      - CA-Policies.json : full raw export (backup / restore reference)
    Output folder: C:\Users\<user>\CA-Policies-<yyyyMMdd_HHmmss>

    Read-only. Makes no changes to the tenant.

#>

#Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All","Application.Read.All" -NoWelcome -ContextScope Process

$outDir = Join-Path $HOME "CA-Policies-$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$graph = "https://graph.microsoft.com/beta"   # beta includes every CA setting (e.g. authentication flows)

function Get-All($uri) {
    $items = @()
    do {
        $r = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        $items += $r.value
        $uri = $r.'@odata.nextLink'
    } while ($uri)
    $items
}

$policies  = Get-All "$graph/identity/conditionalAccess/policies"
$locations = Get-All "$graph/identity/conditionalAccess/namedLocations"
$roles     = Get-All "https://graph.microsoft.com/v1.0/directoryRoleTemplates"

# Name lookup cache
$names = @{}
$locations | ForEach-Object { $names[$_.id] = "$($_.displayName) (location)" }
$roles     | ForEach-Object { $names[$_.id] = "$($_.displayName) (role)" }
$special   = "All","None","GuestsOrExternalUsers","Office365","MicrosoftAdminPortals","AllTrusted"

function Resolve-Ids($ids, [switch]$App) {
    if (-not $ids) { return "-" }
    ($ids | ForEach-Object {
        $id = $_
        if ($id -in $special) { return $id }
        if (-not $names.ContainsKey($id)) {
            try {
                if ($App) {
                    $o = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$id')?`$select=displayName"
                } else {
                    $o = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                        -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$id"
                }
                $names[$id] = $o.displayName
            } catch { $names[$id] = "$id (not found)" }
        }
        $names[$id]
    }) -join "; "
}

function Join-List($v) { if ($v) { ($v -join ", ") } else { "-" } }

$md  = @("# Conditional Access policies", "", "Exported $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $((Get-MgContext).TenantId)", "")
$csv = @()

foreach ($p in ($policies | Sort-Object displayName)) {
    $u = $p.conditions.users
    $a = $p.conditions.applications
    $c = $p.conditions
    $g = $p.grantControls
    $s = $p.sessionControls

    $grant = @()
    if ($g.builtInControls)        { $grant += $g.builtInControls }
    if ($g.authenticationStrength) { $grant += "Authentication strength: $($g.authenticationStrength.displayName)" }
    $grantText = if ($grant) { "$($grant -join ' ' + $g.operator + ' ')" } else { "-" }

    $session = @()
    if ($s.signInFrequency.isEnabled) {
        $session += if ($s.signInFrequency.frequencyInterval -eq "everyTime") { "Sign-in frequency: every time" }
                    else { "Sign-in frequency: $($s.signInFrequency.value) $($s.signInFrequency.type)" }
    }
    if ($s.persistentBrowser.isEnabled) { $session += "Persistent browser: $($s.persistentBrowser.mode)" }
    if ($s.applicationEnforcedRestrictions.isEnabled) { $session += "App enforced restrictions" }
    if ($s.cloudAppSecurity.isEnabled)  { $session += "Conditional Access App Control" }
    if ($s.secureSignInSession.isEnabled) { $session += "Token protection" }
    $sessionText = Join-List $session

    $md += "## $($p.displayName)"
    $md += ""
    $md += "| Setting | Value |"
    $md += "|---|---|"
    $md += "| State | $($p.state) |"
    $md += "| Include users | $(Resolve-Ids $u.includeUsers) |"
    $md += "| Include groups | $(Resolve-Ids $u.includeGroups) |"
    $md += "| Include roles | $(Resolve-Ids $u.includeRoles) |"
    $md += "| Exclude users | $(Resolve-Ids $u.excludeUsers) |"
    $md += "| Exclude groups | $(Resolve-Ids $u.excludeGroups) |"
    $md += "| Exclude roles | $(Resolve-Ids $u.excludeRoles) |"
    $md += "| Include apps | $(Resolve-Ids $a.includeApplications -App) |"
    $md += "| Exclude apps | $(Resolve-Ids $a.excludeApplications -App) |"
    $md += "| User actions | $(Join-List $a.includeUserActions) |"
    $md += "| Platforms | $(Join-List $c.platforms.includePlatforms) (exclude: $(Join-List $c.platforms.excludePlatforms)) |"
    $md += "| Locations | $(Resolve-Ids $c.locations.includeLocations) (exclude: $(Resolve-Ids $c.locations.excludeLocations)) |"
    $md += "| Client apps | $(Join-List $c.clientAppTypes) |"
    $md += "| Authentication flows | $(Join-List $c.authenticationFlows.transferMethods) |"
    $md += "| Sign-in risk | $(Join-List $c.signInRiskLevels) |"
    $md += "| User risk | $(Join-List $c.userRiskLevels) |"
    $md += "| Grant | $grantText |"
    $md += "| Session | $sessionText |"
    $md += "| Last modified | $($p.modifiedDateTime) |"
    $md += ""

    $csv += [PSCustomObject]@{
        Policy        = $p.displayName
        State         = $p.state
        IncludeRoles  = Resolve-Ids $u.includeRoles
        IncludeUsers  = Resolve-Ids $u.includeUsers
        IncludeGroups = Resolve-Ids $u.includeGroups
        ExcludeUsers  = Resolve-Ids $u.excludeUsers
        ExcludeGroups = Resolve-Ids $u.excludeGroups
        Apps          = Resolve-Ids $a.includeApplications -App
        UserActions   = Join-List $a.includeUserActions
        Grant         = $grantText
        Session       = $sessionText
    }
}

$md  | Set-Content -Path (Join-Path $outDir "CA-Policies.md") -Encoding utf8
$csv | Export-Csv  -Path (Join-Path $outDir "CA-Policies.csv") -NoTypeInformation -Encoding utf8
$policies | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $outDir "CA-Policies.json") -Encoding utf8

#Disconnect-MgGraph | Out-Null
Write-Host "Saved to $outDir"