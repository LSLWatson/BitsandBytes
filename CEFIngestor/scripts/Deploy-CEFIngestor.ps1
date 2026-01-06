#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the CEF Ingestor solution to Azure.

.DESCRIPTION
    This script deploys all components of the CEF Ingestor solution:
    - Azure Function App with System-Assigned Managed Identity
    - Data Collection Endpoint (DCE)
    - Data Collection Rule (DCR) for CommonSecurityLog
    - Role assignment for Monitoring Metrics Publisher
    - Application Insights
    - Storage Account

.PARAMETER SubscriptionId
    The Azure subscription ID where resources will be deployed.

.PARAMETER ResourceGroupName
    The name of the resource group. Will be created if it doesn't exist.

.PARAMETER Location
    The Azure region for deployment (e.g., 'eastus', 'westeurope').

.PARAMETER WorkspaceResourceId
    The full resource ID of the Log Analytics workspace.

.PARAMETER BaseName
    Base name for all resources (default: 'cefingestor').

.PARAMETER InitialLogTypes
    Comma-separated list of log types to generate (default: 'firewall,ids,auth,antivirus').

.PARAMETER InitialEventsPerMinute
    Number of events to generate per minute (default: 100, range: 50-500).

.PARAMETER EnableOnDeploy
    Whether to enable event generation on deployment (default: true).

.PARAMETER DeployWorkbook
    Whether to deploy the Azure Workbook (default: true).

.EXAMPLE
    .\Deploy-CEFIngestor.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-cefingestor" `
        -Location "eastus" `
        -WorkspaceResourceId "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.OperationalInsights/workspaces/xxx"

.NOTES
    Requires Azure CLI to be installed and authenticated.
    Requires Bicep CLI or Azure CLI with Bicep extension.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Location,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceResourceId,

    [Parameter(Mandatory = $false)]
    [string]$BaseName = "cefingestor",

    [Parameter(Mandatory = $false)]
    [string]$InitialLogTypes = "firewall,ids,auth,antivirus",

    [Parameter(Mandatory = $false)]
    [ValidateRange(50, 500)]
    [int]$InitialEventsPerMinute = 100,

    [Parameter(Mandatory = $false)]
    [bool]$EnableOnDeploy = $true,

    [Parameter(Mandatory = $false)]
    [bool]$DeployWorkbook = $true
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║           CEF Ingestor Deployment Script                      ║
║     Microsoft Sentinel - Fake CEF Data Generator              ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Validate Azure CLI is installed
Write-Host "Checking prerequisites..." -ForegroundColor Yellow
try {
    $azVersion = az version --output json | ConvertFrom-Json
    Write-Host "  ✓ Azure CLI version: $($azVersion.'azure-cli')" -ForegroundColor Green
}
catch {
    Write-Error "Azure CLI is not installed or not in PATH. Please install from https://aka.ms/installazurecliwindows"
    exit 1
}

# Check if logged in
$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "  → Not logged in. Running 'az login'..." -ForegroundColor Yellow
    az login
}
else {
    Write-Host "  ✓ Logged in as: $($account.user.name)" -ForegroundColor Green
}

# Set subscription
Write-Host "`nSetting subscription..." -ForegroundColor Yellow
az account set --subscription $SubscriptionId
$currentSub = az account show --output json | ConvertFrom-Json
Write-Host "  ✓ Using subscription: $($currentSub.name) ($($currentSub.id))" -ForegroundColor Green

# Validate workspace exists
Write-Host "`nValidating Log Analytics workspace..." -ForegroundColor Yellow
try {
    $workspace = az resource show --ids $WorkspaceResourceId --output json | ConvertFrom-Json
    Write-Host "  ✓ Workspace found: $($workspace.name)" -ForegroundColor Green
}
catch {
    Write-Error "Log Analytics workspace not found: $WorkspaceResourceId"
    exit 1
}

# Create resource group if it doesn't exist
Write-Host "`nChecking resource group..." -ForegroundColor Yellow
$rgExists = az group exists --name $ResourceGroupName
if ($rgExists -eq "false") {
    Write-Host "  → Creating resource group: $ResourceGroupName in $Location" -ForegroundColor Yellow
    az group create --name $ResourceGroupName --location $Location --output none
    Write-Host "  ✓ Resource group created" -ForegroundColor Green
}
else {
    Write-Host "  ✓ Resource group exists: $ResourceGroupName" -ForegroundColor Green
}

# Get the script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$infraDir = Join-Path $scriptDir ".." "infra"
$bicepFile = Join-Path $infraDir "main.bicep"
$armFile = Join-Path $infraDir "azuredeploy.json"

# Choose template file
if (Test-Path $bicepFile) {
    $templateFile = $bicepFile
    Write-Host "`nUsing Bicep template: $templateFile" -ForegroundColor Yellow
}
elseif (Test-Path $armFile) {
    $templateFile = $armFile
    Write-Host "`nUsing ARM template: $templateFile" -ForegroundColor Yellow
}
else {
    Write-Error "No template file found. Expected main.bicep or azuredeploy.json in infra folder."
    exit 1
}

# Deploy infrastructure
Write-Host "`nDeploying infrastructure..." -ForegroundColor Yellow
Write-Host "  This may take a few minutes..." -ForegroundColor Gray

$deploymentName = "cefingestor-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

$deploymentParams = @(
    "--resource-group", $ResourceGroupName,
    "--template-file", $templateFile,
    "--name", $deploymentName,
    "--parameters",
    "baseName=$BaseName",
    "location=$Location",
    "workspaceResourceId=$WorkspaceResourceId",
    "initialLogTypes=$InitialLogTypes",
    "initialEventsPerMinute=$InitialEventsPerMinute",
    "enableOnDeploy=$($EnableOnDeploy.ToString().ToLower())"
)

$deployment = az deployment group create @deploymentParams --output json | ConvertFrom-Json

if ($LASTEXITCODE -ne 0) {
    Write-Error "Deployment failed"
    exit 1
}

Write-Host "  ✓ Infrastructure deployed successfully" -ForegroundColor Green

# Get deployment outputs
$outputs = $deployment.properties.outputs

Write-Host "`nDeployment Outputs:" -ForegroundColor Cyan
Write-Host "  Function App Name: $($outputs.functionAppName.value)" -ForegroundColor White
Write-Host "  Function App ID:   $($outputs.functionAppResourceId.value)" -ForegroundColor White
Write-Host "  DCE Endpoint:      $($outputs.dataCollectionEndpointUri.value)" -ForegroundColor White
Write-Host "  DCR ID:            $($outputs.dataCollectionRuleId.value)" -ForegroundColor White
Write-Host "  Storage Account:   $($outputs.storageAccountName.value)" -ForegroundColor White

# Deploy Function App code
Write-Host "`nDeploying Function App code..." -ForegroundColor Yellow
$srcDir = Join-Path $scriptDir ".." "src"

if (Test-Path $srcDir) {
    # Create a zip package
    $zipPath = Join-Path $env:TEMP "cefingestor-func.zip"
    
    # Remove existing zip if present
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    
    # Create zip
    Compress-Archive -Path "$srcDir\*" -DestinationPath $zipPath -Force
    
    # Deploy using zip deploy
    az functionapp deployment source config-zip `
        --resource-group $ResourceGroupName `
        --name $outputs.functionAppName.value `
        --src $zipPath `
        --output none
    
    Write-Host "  ✓ Function App code deployed" -ForegroundColor Green
    
    # Cleanup
    Remove-Item $zipPath -Force
}
else {
    Write-Host "  ⚠ Source directory not found. Please deploy function code manually." -ForegroundColor Yellow
}

# Deploy workbook
if ($DeployWorkbook) {
    Write-Host "`nDeploying Azure Workbook..." -ForegroundColor Yellow
    $workbookTemplateFile = Join-Path $scriptDir ".." "workbook" "workbook-template.json"
    
    if (Test-Path $workbookTemplateFile) {
        $workbookDeploymentName = "cefingestor-workbook-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        
        az deployment group create `
            --resource-group $ResourceGroupName `
            --template-file $workbookTemplateFile `
            --name $workbookDeploymentName `
            --parameters workspaceResourceId=$WorkspaceResourceId `
            --output none
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Workbook deployed successfully" -ForegroundColor Green
        }
        else {
            Write-Host "  ⚠ Workbook deployment had warnings" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  ⚠ Workbook template not found. Skipping workbook deployment." -ForegroundColor Yellow
    }
}

# Summary
Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                    Deployment Complete!                       ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green

Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. The Function App will start generating CEF events every 5 minutes" -ForegroundColor White
Write-Host "  2. Events will appear in the CommonSecurityLog table in Sentinel" -ForegroundColor White
Write-Host "  3. Use the Azure Workbook to control event generation" -ForegroundColor White
Write-Host ""
Write-Host "Useful Links:" -ForegroundColor Cyan
Write-Host "  Function App: https://portal.azure.com/#resource$($outputs.functionAppResourceId.value)" -ForegroundColor White
Write-Host "  Log Analytics: https://portal.azure.com/#resource$WorkspaceResourceId/logs" -ForegroundColor White
Write-Host ""
Write-Host "Query to verify events:" -ForegroundColor Cyan
Write-Host "  CommonSecurityLog | where DeviceVendor == 'Contoso' | take 10" -ForegroundColor Gray
Write-Host ""
