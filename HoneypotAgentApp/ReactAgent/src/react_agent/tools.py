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
    
    Args:
        method: HTTP method (GET, POST, DELETE)
        url: Full URL to request
        **kwargs: Additional arguments for requests
        
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
        
    return result

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

def get_firewall_stats() -> Dict[str, Any]:
    """
    Get firewall traffic statistics
    
    Returns:
        Dict with success status and stats data
    """
    logger.info("Retrieving firewall statistics...")
    url = f"{FIREWALL_URL}/stats"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved firewall stats")
    else:
        logger.error(f"Failed to get firewall stats: {result['error']}")
        
    return result

# Packet Monitor Functions
def get_packets(limit: int = 100, protocol: Optional[str] = None,
               direction: Optional[str] = None, since: Optional[str] = None) -> Dict[str, Any]:
    """
    Get captured packets with optional filtering
        
    Returns:
        Dict with success status and packets data
    """
    logger.info(f"Retrieving packets (limit: {limit})")
    url = f"{MONITOR_URL}/packets"
    
    params = {'limit': limit}
    if protocol:
        params['protocol'] = protocol
    if direction:
        params['direction'] = direction
    if since:
        params['since'] = since
        
    result = _make_request("GET", url, params=params)
    
    if result['success']:
        packet_count = len(result['data'].get('packets', []))
        logger.info(f"Successfully retrieved {packet_count} packets")
    else:
        logger.error(f"Failed to get packets: {result['error']}")
        
    return result

def get_recent_packets() -> Dict[str, Any]:
    """
    Get packets from the last 5 minutes
    
    Returns:
        Dict with success status and recent packets data
    """
    logger.info("Retrieving recent packets (last 5 minutes)...")
    url = f"{MONITOR_URL}/packets/recent"
    result = _make_request("GET", url)
    
    if result['success']:
        packet_count = len(result['data'].get('packets', []))
        logger.info(f"Successfully retrieved {packet_count} recent packets")
    else:
        logger.error(f"Failed to get recent packets: {result['error']}")
        
    return result

def get_packet_stats() -> Dict[str, Any]:
    """
    Get packet capture statistics
    
    Returns:
        Dict with success status and stats data
    """
    logger.info("Retrieving packet statistics...")
    url = f"{MONITOR_URL}/stats"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved packet stats")
    else:
        logger.error(f"Failed to get packet stats: {result['error']}")
        
    return result

def get_traffic_flows() -> Dict[str, Any]:
    """
    Get traffic flows summary
    
    Returns:
        Dict with success status and flows data
    """
    logger.info("Retrieving traffic flows...")
    url = f"{MONITOR_URL}/packets/flows"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved traffic flows")
    else:
        logger.error(f"Failed to get traffic flows: {result['error']}")
        
    return result

# Health Check Functions
def check_services_health() -> Dict[str, Any]:
    """
    Check health of both firewall and packet monitor services
    
    Returns:
        Dict with health status of both services
    """
    firewall_health = _make_request("GET", f"{FIREWALL_URL}/health")
    monitor_health = _make_request("GET", f"{MONITOR_URL}/health")
    
    return {
        'firewall': firewall_health,
        'monitor': monitor_health,
        'both_healthy': firewall_health['success'] and monitor_health['success']
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
            
        return container_info
        
    except docker.errors.DockerException as e:
        return {"error": f"Docker connection error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
