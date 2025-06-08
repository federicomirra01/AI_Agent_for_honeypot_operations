import json 
import docker
import requests
import logging
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
FIREWALL_URL = "http://192.168.200.2:5000"
MONITOR_URL = "http://192.168.200.2:6000"
REQUEST_TIMEOUT = 10

def _make_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """
    Make HTTP request with error handling
        
    Returns:
        Dict containing response data or error info
    """
    try:
        response = requests.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        
        if response.status_code == 200:
            return {
                'success': True,
                'data': response.json(),
                'status_code': response.status_code
            }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}",
                'status_code': response.status_code
            }
            
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Request timeout'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Connection failed'}
    except Exception as e:
        return {'success': False, 'error': f"Request failed: {str(e)}"}

# Firewall Functions
def get_firewall_rules() -> Dict[str, Any]:
    """
    Get current firewall rules
    
    Returns:
        Dict with success status and rules data
    """
    logger.info("Retrieving firewall rules...")
    url = f"{FIREWALL_URL}/rules"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved firewall rules")
    else:
        logger.error(f"Failed to get firewall rules: {result['error']}")
        
    return {'firewall_config' : result}

def add_allow_rule(source_ip: str, dest_ip: str, port=None, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Add firewall allow rule
    
    Returns:
        Dict with success status and response data
    """
    logger.info(f"Adding allow rule: {source_ip} -> {dest_ip}:{port}")
    url = f"{FIREWALL_URL}/rules/allow"
    
    payload = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'protocol': protocol
    }
    
    if port is not None:
        payload['port'] = port
        
    result = _make_request("POST", url, json=payload)
    
    if result['success']:
        logger.info("Successfully added allow rule")
    else:
        logger.error(f"Failed to add allow rule: {result['error']}")
        
    return result

def add_block_rule(source_ip: str, dest_ip: str,
                  port: Optional[int] = None, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Add firewall block rule
        
    Returns:
        Dict with success status and response data
    """
    logger.info(f"Adding block rule: {source_ip} -> {dest_ip}:{port}")
    url = f"{FIREWALL_URL}/rules/block"
    
    payload = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'protocol': protocol
    }
    
    if port is not None:
        payload['port'] = port
        
    result = _make_request("POST", url, json=payload)
    
    if result['success']:
        logger.info("Successfully added block rule")
    else:
        logger.error(f"Failed to add block rule: {result['error']}")
        
    return result

def remove_firewall_rule(rule_number: int) -> Dict[str, Any]:
    """
    Remove firewall rule by number
        
    Returns:
        Dict with success status and response data
    """
    logger.info(f"Removing firewall rule #{rule_number}")
    url = f"{FIREWALL_URL}/rules/{rule_number}"
    result = _make_request("DELETE", url)
    
    if result['success']:
        logger.info(f"Successfully removed rule #{rule_number}")
    else:
        logger.error(f"Failed to remove rule: {result['error']}")
        
    return result

# Replace/add these tools in your graph_react.py

def get_network_flows(time_window: int = 5) -> Dict[str, Any]:
    """
    Get aggregated network flows for firewall decision making.
    Now includes threat detection information.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with flow analysis data including threat IPs and specific threat details
    """
    logger.info(f"Retrieving network flows (window: {time_window} minutes)")
    url = f"{MONITOR_URL}/analysis/flows"
    
    params = {'window': min(time_window, 30)}  # Cap at 30 minutes
    result = _make_request("GET", url, params=params)
    
    if result['success']:
        data = result['data']
        threat_count = len(data.get('threat_ips', []))
        total_flows = data.get('total_flows', 0)
        logger.info(f"Retrieved {total_flows} flows with {threat_count} threat IPs")
        
        # Log threat details if found
        threat_details = data.get('threat_details', {})
        if threat_details:
            logger.info(f"Threat details found for IPs: {list(threat_details.keys())}")
    else:
        logger.error(f"Failed to get network flows: {result['error']}")
        
    return {'network_flows': result}

def get_security_events(time_window: int = 5) -> Dict[str, Any]:
    """
    Get security-focused analysis including threat detection and command execution attempts.
    Enhanced to capture specific command injection patterns like /bin/bash, find / -perm 4000, etc.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with security events, threat IPs, and specific command execution details
    """
    logger.info(f"Retrieving security events (window: {time_window} minutes)")
    url = f"{MONITOR_URL}/analysis/security"
    
    params = {'window': min(time_window, 30)}
    result = _make_request("GET", url, params=params)
    
    if result['success']:
        events = result['data']
        threat_ips_count = len(events.get('threat_ips', []))
        command_exec_count = len(events.get('command_executions', []))
        total_threats = events.get('total_threats_detected', 0)
        
        logger.info(f"Retrieved {threat_ips_count} threat IPs, {command_exec_count} command executions, {total_threats} total threats")
        
        # Log specific command executions found
        if command_exec_count > 0:
            logger.warning(f"CRITICAL: {command_exec_count} command execution attempts detected!")
            for cmd in events.get('command_executions', [])[:3]:  # Log first 3
                logger.warning(f"  Command from {cmd.get('src_ip')}: {cmd.get('command_pattern', 'N/A')}")
                
    else:
        logger.error(f"Failed to get security events: {result['error']}")
        
    return {'security_events': result}

def get_compressed_packets(limit: int = 100, time_window: int = 5, 
                         protocol: Optional[str] = None, 
                         direction: Optional[str] = None) -> Dict[str, Any]:
    """
    Get compressed packet data with only essential fields for analysis.
    Now includes HTTP payload threats and command injection detection.
    
    Args:
        limit: Maximum packets to retrieve (capped at 500)
        time_window: Recent minutes to analyze (default 5)
        protocol: Filter by protocol (TCP/UDP/ICMP)
        direction: Filter by direction (inbound/outbound/internal)
    
    Returns:
        Dict with compressed packet data including threat information
    """
    logger.info(f"Retrieving compressed packets (limit: {limit}, window: {time_window})")
    url = f"{MONITOR_URL}/packets/compressed"
    
    params = {
        'limit': min(limit, 500),  # Hard cap to prevent context overflow
        'recent': time_window
    }
    
    if protocol:
        params['protocol'] = protocol
    if direction:
        params['direction'] = direction
        
    result = _make_request("GET", url, params=params)
    
    if result['success']:
        data = result['data']
        packet_count = data.get('count', 0)
        
        # Count packets with threats
        threat_packets = 0
        command_threats = 0
        if 'packets' in data:
            for packet in data['packets']:
                if packet.get('threats') or (packet.get('http') and packet['http'].get('threats')):
                    threat_packets += 1
                    # Check for command execution threats
                    all_threats = packet.get('threats', []) + packet.get('http', {}).get('threats', [])
                    for threat in all_threats:
                        if 'command' in threat.lower() or '/bin/bash' in threat.lower() or 'find' in threat.lower():
                            command_threats += 1
                            break
        
        logger.info(f"Retrieved {packet_count} compressed packets, {threat_packets} with threats, {command_threats} with command execution")
        
        if command_threats > 0:
            logger.warning(f"ALERT: {command_threats} packets contain command execution patterns!")
            
    else:
        logger.error(f"Failed to get compressed packets: {result['error']}")
        
    return {'compressed_packets': result}

def get_packets(limit: int = 50, protocol: Optional[str] = None, direction: Optional[str] = None):
    """
    Get recent packets with threat detection. 
    Enhanced to include HTTP payload analysis and command injection detection.
    Limited to prevent context overflow - use other tools for detailed analysis.
    """
    logger.info(f"Retrieving packets (limit: {limit}, protocol: {protocol}, direction: {direction})")
    url = f"{MONITOR_URL}/packets"
    
    # Force smaller limit and recent time window to prevent context overflow
    safe_limit = min(limit, 50)
    params = {'limit': safe_limit, 'recent': 5}  # Only recent 5 minutes
    
    if protocol:
        params['protocol'] = protocol
    if direction:
        params['direction'] = direction
        
    raw_packets = _make_request("GET", url, params=params)
    
    if not raw_packets['success']:
        logger.error(f"Failed to get packets: {raw_packets['error']}")
        return raw_packets
    
    # Count threats in the response for logging
    if raw_packets.get('data') and raw_packets['data'].get('packets'):
        threat_count = 0
        for packet in raw_packets['data']['packets']:
            if packet.get('suspicious_patterns') or packet.get('suspicious_uri_patterns'):
                threat_count += 1
        
        if threat_count > 0:
            logger.warning(f"Found {threat_count} packets with suspicious patterns in raw packet data")
    
    return {'network_packets': raw_packets}

# Health Check Functions
def check_services_health() -> Dict[str, Any]:
    """
    Check health of both firewall and packet monitor services
    
    Returns:
        Dict with health status of both services
    """
    logger.info("Retrieving services status")
    try:
        firewall_status = _make_request("GET", f"{FIREWALL_URL}/health")
        monitor_status = _make_request("GET", f"{MONITOR_URL}/health")
        firewall_health = 'up' if firewall_status["data"]["status"] == 'healthy' else 'down'
        monitor_health = 'up' if monitor_status["data"]["status"] == 'healthy' else 'down'
        logger.info("Successfully retrieve services health")
    except Exception as e:
        print(f"Error: {e}")
    return {
            'firewall_status': firewall_health,
            'monitor_status': monitor_health
        }

def getDockerContainers() -> List[Dict[str, Any]]:
    """
    Get information about running Docker containers using the Docker API,
    including their internal private IP addresses.
    
    Returns:
        list: A list of dictionaries containing container information
    """
    try:
        # Initialize the Docker client
        client = docker.from_env()
        
        # Get list of running containers
        containers = client.containers.list()
        # Format container information similar to "docker ps" output
        container_info = []
        for container in containers:
            
            # Get container's IP address from network settings
            ip_address = None
            networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
            
            # Iterate through networks and get the first IP address found
            # (Most containers have a single network, but some might have multiple)
            for network_name, network_config in networks.items():
                if network_config.get('IPAddress'):
                    ip_address = network_config.get('IPAddress')
                    break
            
            info = {
                'id': container.id[:12],  # Short ID
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else container.image.id[:12],
                'status': container.status,
                'created': container.attrs['Created'],
                'ports': container.ports,
                'ip_address': ip_address
            }
            container_info.append(info)
            
        return {'honeypot_config' : container_info}
        
    except docker.errors.DockerException as e:
        return {"error": f"Docker connection error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


