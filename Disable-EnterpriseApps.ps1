<#
.SYNOPSIS
    Disables Enterprise Apps

.PARAMETER AppNames
    Comma-separated list of app display names to disable.
    Use the App Display Name seen in the Enterprise Applications GUI, or use the cmdlet Get-MgBetaServicePrincipal -All  
    
    Type: String[]
    Mandatory: Yes
    
.EXAMPLE
    Disable a single app named "MyApp"
    .\Disable-EnterpriseApplications -AppNames "MyApp"    

    Disable apps called "MyApp" and "Another App"
    .\Disable-EnterpriseApplications -AppNames "MyApp","Another App"   
    
#>

param (
    [Parameter(Mandatory=$true)]
    [string[]]$AppNames
)

# Get if already connected to Graph and if the needed scope is already present
$context = Get-MgContext
if ($null -eq $context -or -not ($context.Scopes -contains "Application.ReadWrite.All")) {
    Connect-MgGraph -Scopes "Application.ReadWrite.All"
}

foreach ($appName in $AppNames) {
    # Get all App IDs for the given app name
    $AppIds = (Get-MgBetaServicePrincipal -All | Where-Object -Property DisplayName -eq "$appName").AppId
     
    #Some apps may appear multiple times.
    
    foreach ($AppId in $AppIds) {
        $servicePrincipal = Get-MgBetaServicePrincipal -All -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue

        # If Service principal exists already, disable it, else, create it and disable it at the same time
        if ($servicePrincipal) {
            Update-MgBetaServicePrincipal -ServicePrincipalId $servicePrincipal.Id -AccountEnabled:$false
        } else {
            $servicePrincipal = New-MgBetaServicePrincipal -AppId $AppId -AccountEnabled:$false
        }
    }
}
