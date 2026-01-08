// ============================================================================
// CEF Ingestor - Main Bicep Template
// Deploys Azure Function App with Managed Identity, DCR, DCE for Sentinel ingestion
// ============================================================================

@description('Base name for all resources')
param baseName string = 'cefingestor'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Log Analytics Workspace Resource ID')
param workspaceResourceId string

@description('Initial CEF log types to generate (comma-separated: firewall,ids,auth,antivirus)')
param initialLogTypes string = 'firewall,ids,auth,antivirus'

@description('Initial events per minute')
@minValue(50)
@maxValue(500)
param initialEventsPerMinute int = 100

@description('Enable CEF generation on deployment')
param enableOnDeploy bool = true

// Variables
var uniqueSuffix = uniqueString(resourceGroup().id, baseName)
var functionAppName = '${baseName}-func-${uniqueSuffix}'
var storageAccountName = toLower('${take(baseName, 6)}st${take(uniqueSuffix, 10)}')
var appServicePlanName = '${baseName}-plan-${uniqueSuffix}'
var appInsightsName = '${baseName}-ai-${uniqueSuffix}'
var dceName = '${baseName}-dce-${uniqueSuffix}'
var dcrName = '${baseName}-dcr-${uniqueSuffix}'

// ============================================================================
// Storage Account for Function App
// ============================================================================
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

// ============================================================================
// Application Insights
// ============================================================================
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspaceResourceId
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ============================================================================
// App Service Plan (Consumption)
// ============================================================================
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true // Linux
  }
}

// ============================================================================
// Data Collection Endpoint
// ============================================================================
resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ============================================================================
// Data Collection Rule for CommonSecurityLog
// ============================================================================
resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dcrName
  location: location
  kind: 'Direct'
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      'Custom-CEFEvents': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'DeviceVendor', type: 'string' }
          { name: 'DeviceProduct', type: 'string' }
          { name: 'DeviceVersion', type: 'string' }
          { name: 'DeviceEventClassID', type: 'string' }
          { name: 'Activity', type: 'string' }
          { name: 'LogSeverity', type: 'string' }
          { name: 'SourceIP', type: 'string' }
          { name: 'DestinationIP', type: 'string' }
          { name: 'SourceHostName', type: 'string' }
          { name: 'DestinationHostName', type: 'string' }
          { name: 'SourceUserName', type: 'string' }
          { name: 'Protocol', type: 'string' }
          { name: 'DeviceAction', type: 'string' }
          { name: 'Message', type: 'string' }
          { name: 'Computer', type: 'string' }
          { name: 'DeviceExternalID', type: 'string' }
          { name: 'DeviceName', type: 'string' }
          { name: 'DestinationPort', type: 'int' }
          { name: 'SourcePort', type: 'int' }
          { name: 'FileName', type: 'string' }
          { name: 'FilePath', type: 'string' }
          { name: 'FileHash', type: 'string' }
          { name: 'SimplifiedDeviceAction', type: 'string' }
          { name: 'ReceiptTime', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: 'sentinel-workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-CEFEvents']
        destinations: ['sentinel-workspace']
        transformKql: 'source'
        outputStream: 'Microsoft-CommonSecurityLog'
      }
    ]
  }
}

// ============================================================================
// Function App with System-Assigned Managed Identity
// ============================================================================
resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      pythonVersion: '3.11'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'CEF_ENABLED'
          value: enableOnDeploy ? 'true' : 'false'
        }
        {
          name: 'CEF_LOG_TYPES'
          value: initialLogTypes
        }
        {
          name: 'CEF_EVENTS_PER_MINUTE'
          value: string(initialEventsPerMinute)
        }
        {
          name: 'DCE_ENDPOINT'
          value: dataCollectionEndpoint.properties.logsIngestion.endpoint
        }
        {
          name: 'DCR_IMMUTABLE_ID'
          value: dataCollectionRule.properties.immutableId
        }
        {
          name: 'DCR_STREAM_NAME'
          value: 'Custom-CEFEvents'
        }
      ]
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
    }
  }
}

// ============================================================================
// Role Assignment: Monitoring Metrics Publisher on DCR
// ============================================================================
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dataCollectionRule.id, functionApp.id, monitoringMetricsPublisherRoleId)
  scope: dataCollectionRule
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ============================================================================
// Outputs
// ============================================================================
output functionAppName string = functionApp.name
output functionAppResourceId string = functionApp.id
output functionAppPrincipalId string = functionApp.identity.principalId
output dataCollectionEndpointUri string = dataCollectionEndpoint.properties.logsIngestion.endpoint
output dataCollectionRuleId string = dataCollectionRule.id
output dataCollectionRuleImmutableId string = dataCollectionRule.properties.immutableId
output storageAccountName string = storageAccount.name
output appInsightsName string = appInsights.name
