"""
cveBuster Data Generator
Generates vulnerability records with randomized data and current timestamps
Run this script whenever you need fresh data for the API to serve

PAGINATION DEMO VERSION: Generates 100+ records for better pagination testing
"""

import json
import random
from datetime import datetime, timedelta

# Configuration: Expanded VM names pool for more unique records
VM_NAMES = [
    # Web Servers
    "WebServer01", "WebServer02", "WebServer03", "WebServer04", "WebServer05",
    "WebServer06", "WebServer07", "WebServer08", "WebServer09", "WebServer10",
    # Database Servers
    "DBServer01", "DBServer02", "DBServer03", "DBServer04", "DBServer05",
    "DBServer06", "DBServer07", "DBServer08", "DBServer09", "DBServer10",
    # Application Servers
    "AppServer01", "AppServer02", "AppServer03", "AppServer04", "AppServer05",
    "AppServer06", "AppServer07", "AppServer08", "AppServer09", "AppServer10",
    # File Servers
    "FileServer01", "FileServer02", "FileServer03", "FileServer04", "FileServer05",
    # Domain Controllers
    "DCServer01", "DCServer02", "DCServer03", "DCServer04",
    # Production Servers
    "ProdServer01", "ProdServer02", "ProdServer03", "ProdServer04", "ProdServer05",
    "ProdServer06", "ProdServer07", "ProdServer08", "ProdServer09", "ProdServer10",
    # Development Servers
    "DevServer01", "DevServer02", "DevServer03", "DevServer04", "DevServer05",
    "DevServer06", "DevServer07", "DevServer08", "DevServer09", "DevServer10",
    # Test Servers
    "TestServer01", "TestServer02", "TestServer03", "TestServer04", "TestServer05",
    # Special Purpose
    "EicarVM", "MonitoringHost", "LoggingHost", "BackupServer01", "BackupServer02",
    # Container Hosts
    "K8sNode01", "K8sNode02", "K8sNode03", "K8sNode04", "K8sNode05",
    "DockerHost01", "DockerHost02", "DockerHost03",
    # Additional Infrastructure
    "LoadBalancer01", "LoadBalancer02", "ProxyServer01", "ProxyServer02",
    "CacheServer01", "CacheServer02", "QueueServer01", "QueueServer02"
]

# IP ranges for random generation
IP_PREFIXES = ["10.0.0", "10.0.1", "10.0.2", "10.0.3", "10.0.4", "172.16.0", "172.16.1", "172.16.2", "192.168.1", "192.168.2"]

# OS Families
OS_FAMILIES = [
    "Windows Server 2019",
    "Windows Server 2022",
    "Windows Server 2016",
    "Ubuntu 20.04",
    "Ubuntu 22.04",
    "Ubuntu 18.04",
    "Red Hat Enterprise Linux 8",
    "Red Hat Enterprise Linux 9",
    "Red Hat Enterprise Linux 7",
    "CentOS 7",
    "CentOS 8",
    "Debian 11",
    "Debian 10",
    "Amazon Linux 2",
    "SUSE Linux Enterprise 15"
]

# Vulnerable Applications with their typical paths
APPLICATIONS = [
    {"name": "Apache", "path": "/usr/sbin/apache2"},
    {"name": "Nginx", "path": "/usr/sbin/nginx"},
    {"name": "Exim", "path": "/opt/exim/bin"},
    {"name": "Zoho ManageEngine", "path": "/opt/zoho_manageengine/bin"},
    {"name": "Microsoft Exchange", "path": "C:\\Program Files\\Microsoft\\Exchange Server"},
    {"name": "Apache Tomcat", "path": "/opt/tomcat/bin"},
    {"name": "Jenkins", "path": "/var/lib/jenkins"},
    {"name": "Docker", "path": "/usr/bin/docker"},
    {"name": "Kubernetes", "path": "/usr/local/bin/kubectl"},
    {"name": "Redis", "path": "/usr/bin/redis-server"},
    {"name": "PostgreSQL", "path": "/usr/lib/postgresql"},
    {"name": "MySQL", "path": "/usr/bin/mysql"},
    {"name": "Elasticsearch", "path": "/usr/share/elasticsearch"},
    {"name": "Apache Struts", "path": "/opt/struts/lib"},
    {"name": "Log4j", "path": "/opt/apps/lib/log4j"},
    {"name": "OpenSSL", "path": "/usr/bin/openssl"},
    {"name": "Samba", "path": "/usr/sbin/smbd"},
    {"name": "MongoDB", "path": "/usr/bin/mongod"},
    {"name": "RabbitMQ", "path": "/usr/lib/rabbitmq"},
    {"name": "Grafana", "path": "/usr/share/grafana"}
]

# CVE database (sample vulnerabilities)
VULNERABILITIES = [
    {"id": "CVE-2021-44228", "title": "Log4j Remote Code Execution", "cvss": 10.0},
    {"id": "CVE-2022-26134", "title": "Atlassian Confluence RCE", "cvss": 9.8},
    {"id": "CVE-2020-10189", "title": "Exim remote command execution", "cvss": 8.2},
    {"id": "CVE-2022-29144", "title": "ManageEngine RCE", "cvss": 8.5},
    {"id": "CVE-2023-23397", "title": "Microsoft Outlook Privilege Escalation", "cvss": 9.1},
    {"id": "CVE-2023-32315", "title": "Openfire Authentication Bypass", "cvss": 8.6},
    {"id": "CVE-2021-26855", "title": "Microsoft Exchange Server RCE", "cvss": 9.0},
    {"id": "CVE-2022-22965", "title": "Spring4Shell RCE", "cvss": 9.8},
    {"id": "CVE-2023-22515", "title": "Atlassian Confluence Privilege Escalation", "cvss": 8.8},
    {"id": "CVE-2022-41040", "title": "Microsoft Exchange ProxyNotShell", "cvss": 8.8},
    {"id": "CVE-2023-34362", "title": "MOVEit Transfer SQL Injection", "cvss": 9.8},
    {"id": "CVE-2022-30190", "title": "Microsoft Follina", "cvss": 7.8},
    {"id": "CVE-2023-0669", "title": "Fortra GoAnywhere MFT RCE", "cvss": 9.8},
    {"id": "CVE-2021-34527", "title": "PrintNightmare", "cvss": 8.8},
    {"id": "CVE-2023-38831", "title": "WinRAR Code Execution", "cvss": 7.8},
    {"id": "CVE-2014-0160", "title": "Heartbleed OpenSSL", "cvss": 7.5},
    {"id": "CVE-2017-0144", "title": "EternalBlue SMB", "cvss": 8.1},
    {"id": "CVE-2019-0708", "title": "BlueKeep RDP", "cvss": 9.8},
    {"id": "CVE-2020-1472", "title": "Zerologon", "cvss": 10.0},
    {"id": "CVE-2021-3156", "title": "Sudo Baron Samedit", "cvss": 7.8}
]

# Severity levels
SEVERITIES = ["Critical", "High", "Medium", "Low"]

# Asset Criticality
ASSET_CRITICALITY = ["Critical", "High", "Medium", "Low"]

# Business Owners
BUSINESS_OWNERS = ["SecEng", "IT-Ops", "DevOps", "Platform-Team", "Infrastructure", "Database-Team", "Web-Team", "Security-Team"]


def generate_host_id():
    """Generate a random GUID-style host ID"""
    import uuid
    return str(uuid.uuid4())


def generate_ip_address():
    """Generate a random private IP address"""
    prefix = random.choice(IP_PREFIXES)
    last_octet = random.randint(2, 254)
    return f"{prefix}.{last_octet}"


def get_severity_from_cvss(cvss):
    """Determine severity based on CVSS score"""
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    else:
        return "Low"


def generate_random_datetime(days_ago_min=1, days_ago_max=60):
    """Generate a random datetime in the past"""
    now = datetime.utcnow()
    days_ago = random.randint(days_ago_min, days_ago_max)
    random_date = now - timedelta(days=days_ago)
    return random_date.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_record():
    """Generate a single vulnerability record"""
    vm_name = random.choice(VM_NAMES)
    host_id = generate_host_id()
    ip_address = generate_ip_address()
    os_family = random.choice(OS_FAMILIES)
    
    app = random.choice(APPLICATIONS)
    vuln = random.choice(VULNERABILITIES)
    
    cvss = vuln["cvss"]
    severity = get_severity_from_cvss(cvss)
    
    # Generate timestamps
    first_seen_days = random.randint(30, 90)
    last_seen_days = random.randint(1, 29)
    
    first_seen = generate_random_datetime(first_seen_days, first_seen_days + 10)
    last_seen = generate_random_datetime(last_seen_days, last_seen_days + 5)
    last_scan = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")  # Current time
    
    record = {
        "MachineName": vm_name,
        "HostId": host_id,
        "IPAddress": ip_address,
        "OSFamily": os_family,
        "Application": app["name"],
        "AppFilePath": app["path"],
        "VulnId": vuln["id"],
        "VulnTitle": vuln["title"],
        "Severity": severity,
        "CVSS": cvss,
        "ExploitAvailable": random.choice([True, False]),
        "ExploitedInWild": random.choice([True, False]),
        "PatchAvailable": random.choice([True, False]),
        "FirstSeen": first_seen,
        "LastSeen": last_seen,
        "LastScanTime": last_scan,
        "AssetCriticality": random.choice(ASSET_CRITICALITY),
        "BusinessOwner": random.choice(BUSINESS_OWNERS),
        "Source": "cveBuster:demo"
    }
    
    return record


def generate_data_file(num_records=500, output_file="cvebuster_data.json"):
    """
    Generate vulnerability data and save to JSON file
    
    Args:
        num_records: Number of records to generate (default: 500 for realistic demo)
        output_file: Output filename (default: cvebuster_data.json)
    """
    
    print("=" * 70)
    print(f"🔄 cveBuster Data Generator - REALISTIC PAGINATION DEMO")
    print("=" * 70)
    print(f"📊 Generating {num_records:,} vulnerability records...")
    print(f"   (Real-world scenario: 50 records per page)")
    print()
    
    records = []
    for i in range(num_records):
        record = generate_record()
        records.append(record)
        
        # Progress indicator every 25 records
        if (i + 1) % 25 == 0:
            print(f"   ✓ Generated {i + 1}/{num_records} records...")
    
    # Write to JSON file
    with open(output_file, 'w') as f:
        json.dump(records, f, indent=2)
    
    print()
    print("=" * 70)
    print(f"✅ Successfully generated {num_records:,} records")
    print(f"📁 Saved to: {output_file}")
    print(f"⏰ Generation time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print()
    print("📈 Pagination Statistics (Real-world: PAGE_SIZE=50):")
    print(f"   • Total Records: {num_records:,}")
    print(f"   • Total Pages: {(num_records + 49) // 50}")  # Ceiling division for 50 per page
    print(f"   • Records per page: 50")
    print(f"   • Last page records: {num_records % 50 if num_records % 50 != 0 else 50}")
    print()
    print("🌐 Real-world Context:")
    print("   This mimics typical REST API pagination patterns")
    print("   Common page sizes: 25 (small), 50 (standard), 100 (large)")
    print()
    print("🧪 Test the API:")
    print("   1. First page:  GET /api/vulnerabilities")
    print(f"      → Returns records 1-50 + next_token")
    print("   2. Second page: GET /api/vulnerabilities?next_token=<token>")
    print(f"      → Returns records 51-100 + next_token")
    print("   3. Continue until next_token is null (last page)")
    print()
    print("📊 Sample record preview:")
    print("=" * 70)
    print(json.dumps(records[0], indent=2))
    print("=" * 70)


if __name__ == "__main__":
    # Generate 500 records for realistic pagination demo
    # Real-world pagination scenarios with PAGE_SIZE=50:
    # - 500 records = 10 pages (recommended for demo)
    # - 1000 records = 20 pages (realistic production dataset)
    # - 250 records = 5 pages (smaller demo)
    generate_data_file(num_records=500, output_file="cvebuster_data.json")
