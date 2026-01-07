# CEF Ingestor for Microsoft Sentinel

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FLSLWatson%2FBitsandBytes%2Fmain%2FCEFIngestor%2Finfra%2Fazuredeploy.json)

A deployable solution to ingest fake CommonSecurityLog (CEF format) data into Microsoft Sentinel for testing, training, and demonstration purposes.

## 🎯 Overview

This solution generates realistic fake CEF (Common Event Format) security events and ingests them into Microsoft Sentinel's `CommonSecurityLog` table via the Logs Ingestion API. It's perfect for:

- Testing Sentinel analytics rules and playbooks
- Training SOC analysts with realistic data
- Demonstrating Sentinel capabilities
- Developing KQL queries against CEF data

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Azure Workbook                               │
│                    (Configuration Control Panel)                     │
│                              │                                       │
│                              │ ARM Action (PATCH App Settings)       │
│                              ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Azure Function App                          │  │
│  │           (Python, Timer Trigger - 5 minutes)                  │  │
│  │                              │                                  │  │
│  │    ┌─────────────────────────┼─────────────────────────┐       │  │
│  │    │   System-Assigned       │                         │       │  │
│  │    │   Managed Identity      │                         │       │  │
│  │    └─────────────────────────┼─────────────────────────┘       │  │
│  └───────────────────────────────│───────────────────────────────┘  │
│                                  │                                   │
│                                  │ Logs Ingestion API                │
│                                  ▼                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              Data Collection Endpoint (DCE)                    │  │
│  └───────────────────────────────│───────────────────────────────┘  │
│                                  │                                   │
│                                  ▼                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              Data Collection Rule (DCR)                        │  │
│  │         (Custom-CEFEvents → CommonSecurityLog)                 │  │
│  └───────────────────────────────│───────────────────────────────┘  │
│                                  │                                   │
│                                  ▼                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              Log Analytics Workspace                           │  │
│  │                  CommonSecurityLog Table                       │  │
│  │                    (Microsoft Sentinel)                        │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## 📦 Components

| Component | Description |
|-----------|-------------|
| **Azure Function App** | Python 3.11 function with 5-minute timer trigger |
| **Managed Identity** | System-assigned identity for secure API access |
| **Data Collection Endpoint** | Entry point for the Logs Ingestion API |
| **Data Collection Rule** | Routes events to CommonSecurityLog table |
| **Azure Workbook** | Configuration control panel |
| **Application Insights** | Function monitoring and diagnostics |

## 🚀 Deployment

### Option 1: Deploy to Azure Button

Click the button below to deploy directly from the Azure Portal:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FLSLWatson%2FBitsandBytes%2Fmain%2FCEFIngestor%2Finfra%2Fazuredeploy.json)

### Option 2: PowerShell Script

```powershell
# Clone the repository
git clone https://github.com/LSLWatson/BitsandBytes.git
cd BitsandBytes/CEFIngestor

# Run the deployment script
.\scripts\Deploy-CEFIngestor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-cefingestor" `
    -Location "eastus" `
    -WorkspaceResourceId "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.OperationalInsights/workspaces/xxx"
```

### Option 3: Azure CLI with Bicep

```bash
# Create resource group
az group create --name rg-cefingestor --location eastus

# Deploy infrastructure
az deployment group create \
    --resource-group rg-cefingestor \
    --template-file infra/main.bicep \
    --parameters workspaceResourceId="/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.OperationalInsights/workspaces/xxx"

# Deploy function code
cd src
func azure functionapp publish <function-app-name>
```

## ⚙️ Configuration

### App Settings (Function App)

| Setting | Description | Default |
|---------|-------------|---------|
| `CEF_ENABLED` | Enable/disable event generation | `true` |
| `CEF_LOG_TYPES` | Comma-separated log types | `firewall,ids,auth,antivirus` |
| `CEF_EVENTS_PER_MINUTE` | Events generated per minute (50-500) | `100` |
| `DCE_ENDPOINT` | Data Collection Endpoint URI | (auto-configured) |
| `DCR_IMMUTABLE_ID` | Data Collection Rule immutable ID | (auto-configured) |

### Log Types

| Type | Description | Events Generated |
|------|-------------|------------------|
| `firewall` | Firewall allow/deny events | Connection allowed, Connection blocked |
| `ids` | IDS/IPS alerts | Port scan, SQL injection, XSS, Brute force, Malware communication |
| `auth` | Authentication events | Login success/failure |
| `antivirus` | Antivirus detections | Malware, Ransomware, Trojan detections |

## 📊 Using the Control Panel (Workbook)

1. Navigate to Microsoft Sentinel → Workbooks
2. Open "CEF Ingestor Control Panel"
3. Select your subscription, resource group, and function app
4. Configure:
   - **Enable/Disable** generation
   - **Log Types** to generate
   - **Events per minute** volume
5. Click "Apply Changes" to update settings

## 🔍 Querying Events

### Verify events are being ingested

```kql
CommonSecurityLog
| where DeviceVendor == "Contoso"
| where TimeGenerated > ago(1h)
| summarize count() by DeviceProduct
```

### View recent events

```kql
CommonSecurityLog
| where DeviceVendor == "Contoso"
| project TimeGenerated, DeviceProduct, Activity, SourceIP, DestinationIP, LogSeverity
| order by TimeGenerated desc
| take 100
```

### Events by severity

```kql
CommonSecurityLog
| where DeviceVendor == "Contoso"
| where TimeGenerated > ago(24h)
| summarize 
    HighSeverity = countif(LogSeverity >= 7),
    MediumSeverity = countif(LogSeverity >= 4 and LogSeverity < 7),
    LowSeverity = countif(LogSeverity < 4)
```

### Top source IPs (potential attackers)

```kql
CommonSecurityLog
| where DeviceVendor == "Contoso"
| where DeviceAction in ("Deny", "Alert", "Block")
| summarize AttackCount = count() by SourceIP
| top 10 by AttackCount
```

## 🔐 Security

- **Managed Identity**: No secrets or keys stored - uses Azure AD authentication
- **RBAC**: Function app identity has only "Monitoring Metrics Publisher" role on the DCR
- **No Public Access**: Function app can be configured with VNet integration
- **HTTPS Only**: All endpoints use TLS 1.2+

## 📁 Project Structure

```
CEFIngestor/
├── src/
│   ├── function_app.py      # Main function code
│   ├── requirements.txt     # Python dependencies
│   ├── host.json           # Function host configuration
│   └── local.settings.json  # Local development settings
├── infra/
│   ├── main.bicep          # Bicep infrastructure template
│   └── azuredeploy.json    # ARM template for Deploy to Azure
├── workbook/
│   ├── CEFIngestorControlPanel.workbook  # Workbook source
│   └── workbook-template.json            # ARM template for workbook
├── scripts/
│   └── Deploy-CEFIngestor.ps1  # PowerShell deployment script
└── README.md
```

## 🛠️ Local Development

1. Install prerequisites:
   - [Azure Functions Core Tools](https://docs.microsoft.com/azure/azure-functions/functions-run-local)
   - [Python 3.11](https://www.python.org/downloads/)
   - [Azure CLI](https://docs.microsoft.com/cli/azure/install-azure-cli)

2. Create virtual environment:
   ```bash
   cd src
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

3. Update `local.settings.json` with your DCE and DCR values

4. Run locally:
   ```bash
   func start
   ```

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues and feature requests, please use the [GitHub Issues](https://github.com/LSLWatson/BitsandBytes/issues) page.
