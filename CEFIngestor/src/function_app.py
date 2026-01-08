"""
CEF Ingestor Azure Function
Generates fake CommonSecurityLog (CEF format) data and ingests into Microsoft Sentinel
via the Logs Ingestion API.
"""
import azure.functions as func
import logging
import os
import json
import random
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

app = func.FunctionApp()

# CEF Event Templates
CEF_TEMPLATES = {
    "firewall": {
        "allow": {
            "DeviceVendor": "Contoso",
            "DeviceProduct": "Firewall",
            "DeviceVersion": "3.0",
            "DeviceEventClassID": "100",
            "Activity": "Connection Allowed",
            "LogSeverity": 1,
            "Protocol": ["TCP", "UDP", "ICMP"],
            "DestinationPort": [80, 443, 22, 3389, 8080, 8443],
            "DeviceAction": "Allow"
        },
        "deny": {
            "DeviceVendor": "Contoso",
            "DeviceProduct": "Firewall",
            "DeviceVersion": "3.0",
            "DeviceEventClassID": "101",
            "Activity": "Connection Blocked",
            "LogSeverity": 5,
            "Protocol": ["TCP", "UDP"],
            "DestinationPort": [23, 445, 1433, 3306, 5432, 6379],
            "DeviceAction": "Deny"
        }
    },
    "ids": {
        "alert": {
            "DeviceVendor": "Contoso",
            "DeviceProduct": "IDS",
            "DeviceVersion": "2.5",
            "DeviceEventClassID": ["2001", "2002", "2003", "2004", "2005"],
            "Activity": ["Port Scan Detected", "SQL Injection Attempt", "XSS Attack Detected", 
                        "Brute Force Attack", "Malware Communication Detected"],
            "LogSeverity": [6, 7, 8, 9, 10],
            "Protocol": "TCP",
            "DeviceAction": "Alert"
        }
    },
    "auth": {
        "failure": {
            "DeviceVendor": "Contoso",
            "DeviceProduct": "AuthServer",
            "DeviceVersion": "1.0",
            "DeviceEventClassID": "4625",
            "Activity": "Authentication Failed",
            "LogSeverity": 5,
            "Protocol": "TCP",
            "DestinationPort": [389, 636, 88, 443],
            "DeviceAction": "Failure"
        },
        "success": {
            "DeviceVendor": "Contoso",
            "DeviceProduct": "AuthServer",
            "DeviceVersion": "1.0",
            "DeviceEventClassID": "4624",
            "Activity": "Authentication Succeeded",
            "LogSeverity": 1,
            "Protocol": "TCP",
            "DestinationPort": [389, 636, 88, 443],
            "DeviceAction": "Success"
        }
    },
    "antivirus": {
        "detection": {
            "DeviceVendor": "Contoso",
            "DeviceProduct": "Antivirus",
            "DeviceVersion": "4.2",
            "DeviceEventClassID": ["5001", "5002", "5003"],
            "Activity": ["Malware Detected", "Ransomware Blocked", "Trojan Quarantined"],
            "LogSeverity": [8, 9, 10],
            "DeviceAction": ["Quarantine", "Block", "Clean"],
            "FileName": ["invoice.exe", "update.bat", "document.scr", "patch.dll", "setup.msi"],
            "FilePath": ["C:\\Users\\Public\\Downloads", "C:\\Temp", "C:\\Users\\user\\AppData\\Local\\Temp"]
        }
    }
}

# Sample IP addresses for realistic data
INTERNAL_IPS = [
    "10.0.0.10", "10.0.0.25", "10.0.0.50", "10.0.0.100", "10.0.0.150",
    "10.0.1.10", "10.0.1.25", "10.0.1.50", "10.0.1.100", "10.0.1.150",
    "192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.100"
]

EXTERNAL_IPS = [
    "203.0.113.10", "203.0.113.25", "203.0.113.100",
    "198.51.100.10", "198.51.100.25", "198.51.100.100",
    "192.0.2.10", "192.0.2.25", "192.0.2.100",
    "45.33.32.156", "104.16.123.96", "151.101.1.140"
]

HOSTNAMES = [
    "WORKSTATION-001", "WORKSTATION-002", "WORKSTATION-003",
    "SERVER-DC01", "SERVER-DB01", "SERVER-WEB01", "SERVER-APP01",
    "LAPTOP-USER01", "LAPTOP-USER02", "LAPTOP-ADMIN01"
]

USERNAMES = [
    "jsmith", "mwilliams", "tjohnson", "agarcia", "blee",
    "admin", "svc_backup", "svc_sql", "guest", "administrator"
]


def get_random_item(items):
    """Get a random item from a list or return the item if not a list."""
    if isinstance(items, list):
        return random.choice(items)
    return items


def generate_ip_pair(event_type: str) -> tuple:
    """Generate source and destination IP pair based on event type."""
    if event_type in ["firewall_deny", "ids_alert"]:
        # External attacking internal
        return random.choice(EXTERNAL_IPS), random.choice(INTERNAL_IPS)
    elif event_type in ["auth_failure", "antivirus_detection"]:
        # Internal source
        return random.choice(INTERNAL_IPS), random.choice(INTERNAL_IPS)
    else:
        # Mixed
        return random.choice(INTERNAL_IPS + EXTERNAL_IPS), random.choice(INTERNAL_IPS + EXTERNAL_IPS)


def generate_cef_event(log_type: str, timestamp: datetime) -> dict:
    """Generate a single CEF event based on log type."""
    
    # Parse log type (e.g., "firewall" -> "firewall_allow" or "firewall_deny")
    if log_type == "firewall":
        subtype = random.choice(["allow", "deny"])
        template = CEF_TEMPLATES["firewall"][subtype]
        event_type = f"firewall_{subtype}"
    elif log_type == "ids":
        template = CEF_TEMPLATES["ids"]["alert"]
        event_type = "ids_alert"
    elif log_type == "auth":
        subtype = random.choices(["failure", "success"], weights=[0.3, 0.7])[0]
        template = CEF_TEMPLATES["auth"][subtype]
        event_type = f"auth_{subtype}"
    elif log_type == "antivirus":
        template = CEF_TEMPLATES["antivirus"]["detection"]
        event_type = "antivirus_detection"
    else:
        # Default to firewall
        template = CEF_TEMPLATES["firewall"]["allow"]
        event_type = "firewall_allow"
    
    source_ip, dest_ip = generate_ip_pair(event_type)
    
    # Build CEF event for CommonSecurityLog table
    event = {
        "TimeGenerated": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "DeviceVendor": template["DeviceVendor"],
        "DeviceProduct": template["DeviceProduct"],
        "DeviceVersion": template["DeviceVersion"],
        "DeviceEventClassID": get_random_item(template["DeviceEventClassID"]),
        "Activity": get_random_item(template["Activity"]),
        "LogSeverity": str(get_random_item(template["LogSeverity"])),  # Must be string for CommonSecurityLog
        "SourceIP": source_ip,
        "DestinationIP": dest_ip,
        "SourceHostName": random.choice(HOSTNAMES),
        "DestinationHostName": random.choice(HOSTNAMES),
        "SourceUserName": random.choice(USERNAMES),
        "Protocol": get_random_item(template.get("Protocol", "TCP")),
        "DeviceAction": get_random_item(template.get("DeviceAction", "Allow")),
        "Message": f"CEF:0|{template['DeviceVendor']}|{template['DeviceProduct']}|{template['DeviceVersion']}|{get_random_item(template['DeviceEventClassID'])}|{get_random_item(template['Activity'])}|{get_random_item(template['LogSeverity'])}|",
        "Computer": random.choice(HOSTNAMES),
        "DeviceExternalID": f"device-{random.randint(1000, 9999)}",
        "DeviceName": random.choice(HOSTNAMES),
    }
    
    # Add port information if available
    if "DestinationPort" in template:
        event["DestinationPort"] = get_random_item(template["DestinationPort"])
        event["SourcePort"] = random.randint(49152, 65535)
    
    # Add file information for antivirus events
    if log_type == "antivirus":
        event["FileName"] = get_random_item(template.get("FileName", "unknown.exe"))
        event["FilePath"] = get_random_item(template.get("FilePath", "C:\\Temp"))
        event["FileHash"] = f"SHA256:{random.randbytes(32).hex()}"
    
    # Add additional extensions
    event["SimplifiedDeviceAction"] = event["DeviceAction"]
    event["ReceiptTime"] = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    return event


def generate_events_batch(log_types: list, count: int, window_minutes: int = 5) -> list:
    """Generate a batch of CEF events distributed across a time window."""
    events = []
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_minutes)
    
    for _ in range(count):
        # Random timestamp within the window
        random_offset = random.uniform(0, window_minutes * 60)
        timestamp = window_start + timedelta(seconds=random_offset)
        
        # Random log type from enabled types
        log_type = random.choice(log_types)
        
        event = generate_cef_event(log_type, timestamp)
        events.append(event)
    
    return events


def get_config() -> dict:
    """Get configuration from environment variables (App Settings)."""
    return {
        "enabled": os.environ.get("CEF_ENABLED", "true").lower() == "true",
        "log_types": [lt.strip() for lt in os.environ.get("CEF_LOG_TYPES", "firewall,ids,auth,antivirus").split(",")],
        "events_per_minute": int(os.environ.get("CEF_EVENTS_PER_MINUTE", "100")),
        "dce_endpoint": os.environ.get("DCE_ENDPOINT", ""),
        "dcr_immutable_id": os.environ.get("DCR_IMMUTABLE_ID", ""),
        "stream_name": os.environ.get("DCR_STREAM_NAME", "Custom-CEFEvents")
    }


@app.timer_trigger(schedule="0 */5 * * * *", arg_name="timer", run_on_startup=False)
def cef_ingestor(timer: func.TimerRequest) -> None:
    """
    Timer-triggered function that generates and ingests CEF events.
    Runs every 5 minutes.
    """
    logging.info("CEF Ingestor function triggered")
    
    # Get configuration
    config = get_config()
    
    # Check if enabled
    if not config["enabled"]:
        logging.info("CEF Ingestor is disabled via configuration")
        return
    
    # Validate configuration
    if not config["dce_endpoint"] or not config["dcr_immutable_id"]:
        logging.error("DCE_ENDPOINT and DCR_IMMUTABLE_ID must be configured")
        return
    
    if not config["log_types"]:
        logging.warning("No log types configured, using defaults")
        config["log_types"] = ["firewall", "ids", "auth", "antivirus"]
    
    # Calculate batch size (5 minutes worth of events)
    batch_size = config["events_per_minute"] * 5
    
    logging.info(f"Generating {batch_size} events for log types: {config['log_types']}")
    
    # Generate events
    events = generate_events_batch(
        log_types=config["log_types"],
        count=batch_size,
        window_minutes=5
    )
    
    logging.info(f"Generated {len(events)} CEF events")
    
    # Ingest to Sentinel via Logs Ingestion API
    try:
        credential = DefaultAzureCredential()
        client = LogsIngestionClient(
            endpoint=config["dce_endpoint"],
            credential=credential,
            logging_enable=True
        )
        
        # Upload logs
        client.upload(
            rule_id=config["dcr_immutable_id"],
            stream_name=config["stream_name"],
            logs=events
        )
        
        logging.info(f"Successfully ingested {len(events)} events to Sentinel")
        
    except HttpResponseError as e:
        logging.error(f"Failed to ingest events: {e.message}")
        logging.error(f"Status code: {e.status_code}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during ingestion: {str(e)}")
        raise
