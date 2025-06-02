# Packet Monitor API Documentation

## Overview
The Packet Monitor API provides real-time access to network traffic captured from the attacker network (192.168.100.0/24). The service monitors TCP, UDP, ICMP, and HTTP protocols and provides structured JSON data for AI agent analysis.

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

### 2. Get Packets
**GET** `/packets`

Retrieve captured packets with optional filtering.

**Query Parameters:**
- `limit` (int): Maximum number of packets to return (default: 100)
- `since` (ISO timestamp): Get packets since this timestamp
- `protocol` (string): Filter by protocol (TCP, UDP, ICMP)
- `direction` (string): Filter by direction (inbound, outbound, internal, external)

**Examples:**
```bash
# Get last 50 TCP packets
GET /packets?protocol=TCP&limit=50

# Get outbound traffic from attacker network
GET /packets?direction=outbound&limit=100

# Get packets since specific time
GET /packets?since=2025-06-02T10:00:00&limit=200
```

**Response:**
```json
{
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
      "flags_info": "Flags [S]",
      "capture_time": 1717325445.123456
    }
  ],
  "count": 1,
  "total_captured": 1234,
  "timestamp": "2025-06-02T10:30:45.123456"
}
```

### 3. Get Recent Packets
**GET** `/packets/recent`

Get packets from the last 5 minutes.

**Response:**
```json
{
  "packets": [...],
  "count": 45,
  "period": "5 minutes",
  "timestamp": "2025-06-02T10:30:45.123456"
}
```

### 4. Get Statistics
**GET** `/stats`

Get comprehensive capture statistics.

**Response:**
```json
{
  "total_packets": 1234,
  "memory_packets": 1000,
  "stats": {
    "protocol_TCP": 800,
    "protocol_UDP": 200,
    "protocol_ICMP": 234,
    "direction_outbound": 600,
    "direction_inbound": 400,
    "app_HTTP": 300,
    "app_HTTPS": 150
  },
  "timestamp": "2025-06-02T10:30:45.123456",
  "running": true
}
```

### 5. Get Protocols Summary
**GET** `/packets/protocols`

Get packets grouped by protocol.

**Response:**
```json
{
  "protocols": {
    "TCP": 800,
    "UDP": 200,
    "ICMP": 234
  },
  "details": {
    "TCP": [...],
    "UDP": [...],
    "ICMP": [...]
  },
  "timestamp": "2025-06-02T10:30:45.123456"
}
```

### 6. Get Traffic Flows
**GET** `/packets/flows`

Get summary of traffic flows between IPs.

**Response:**
```json
{
  "flows": {
    "192.168.100.10 -> 172.20.0.2": 150,
    "192.168.100.15 -> 8.8.8.8": 25,
    "172.20.0.2 -> 192.168.100.10": 120
  },
  "total_flows": 3,
  "timestamp": "2025-06-02T10:30:45.123456"
}
```

### 7. Control Endpoints
**POST** `/control/start` - Start packet monitoring
**POST** `/control/stop` - Stop packet monitoring

## Packet Data Structure

Each packet contains the following fields:

### Common Fields
- `timestamp`: ISO format timestamp
- `packet_id`: Unique packet identifier
- `protocol`: Protocol type (TCP, UDP, ICMP)
- `source_ip`: Source IP address
- `dest_ip`: Destination IP address
- `direction`: Traffic direction relative to attacker network
- `capture_time`: Unix timestamp
- `raw_line`: Original tcpdump output

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

## Traffic Direction Values
- `outbound`: From attacker network (192.168.100.x) to external
- `inbound`: From external to attacker network
- `internal`: Within attacker network
- `external`: Neither source nor destination in attacker network

## Monitoring Focus
The packet monitor specifically captures:
- **Source Networks**: Traffic from/to 192.168.100.0/24 (attacker network)
- **Protocols**: TCP, UDP, ICMP
- **Applications**: HTTP (80, 8080), HTTPS (443), SSH (22), FTP (21), Telnet (23), SMTP (25), DNS (53), DHCP (67/68)

## AI Agent Usage Examples

### 1. Detect Suspicious Activity
```python
# Get recent outbound connections
response = requests.get("http://192.168.200.2:6000/packets/recent")
packets = response.json()["packets"]

# Look for unusual ports or protocols
suspicious = [p for p in packets if p.get("dest_port") in [23, 21, 1433, 3389]]
```

### 2. Monitor HTTP Traffic
```python
# Get HTTP traffic
response = requests.get("http://192.168.200.2:6000/packets?protocol=TCP")
packets = response.json()["packets"]

http_traffic = [p for p in packets if p.get("application") == "HTTP"]
```

### 3. Analyze Traffic Flows
```python
# Get flow summary
response = requests.get("http://192.168.200.2:6000/packets/flows")
flows = response.json()["flows"]

# Identify high-volume connections
high_traffic = {k: v for k, v in flows.items() if v > 100}
```

### 4. Generate Firewall Rules
```python
# Get recent packets and analyze for blocking
response = requests.get("http://192.168.200.2:6000/packets/recent")
packets = response.json()["packets"]

# Find connections to block
for packet in packets:
    if packet.get("dest_port") == 23:  # Telnet
        # Use firewall API to block
        firewall_rule = {
            "source_ip": packet["source_ip"],
            "dest_ip": packet["dest_ip"], 
            "port": 23
        }
        # Send to firewall API...
```

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