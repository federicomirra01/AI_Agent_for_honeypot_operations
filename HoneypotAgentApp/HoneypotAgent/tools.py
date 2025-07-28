import json 
import docker
import requests
import logging
from typing import Dict, List, Optional, Any
from langgraph.store.memory import InMemoryStore


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
FIREWALL_URL = "http://192.168.200.2:5000"
SURICATA_URL = "http://192.168.200.2:7000"
REQUEST_TIMEOUT = 3

def _make_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """
    Make HTTP request with error handling

    Args:
        method: HTTP method (GET, POST, DELETE, etc.)
        url: URL to send the request to
        **kwargs: Additional parameters for requests.request()
        
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
        elif response.status_code == 207:
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

def get_firewall_rules() -> Dict[str, Any]:
    """
    Get current firewall rules
    
    Returns:
        Dict with success status and rules data
    """
    url = f"{FIREWALL_URL}/rules"
    result = _make_request("GET", url)
    
    if result['success']:
        success = True # just to keep logger.info commented
    else:
        logger.error(f"Failed to get firewall rules: {result['error']}")
        
    return {'firewall_config' : result}

def add_allow_rule(source_ip: str, dest_ip: str, port=None, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Add firewall allow rule
    
    Returns:
        Dict with success status and response data
    """
    # Create rule description for tracking

    port_str = f":{port}" if port else ""
    rule_description = f"ALLOW {source_ip} -> {dest_ip}{port_str} ({protocol})"
    
    logger.info(f"Adding allow rule: {rule_description}")

    url = f"{FIREWALL_URL}/rules/allow"
    
    payload = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'protocol': protocol
    }
    
    if port is not None:
        payload['port'] = port
        
    result = _make_request("POST", url, json=payload)
    
    if not result['success']:
        logger.error(f"Failed to add allow rule: {result['error']}")
    return {'rules_added_current_epoch': rule_description}

def add_block_rule(source_ip: str, dest_ip: str,
                  port: Optional[int] = None, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Add firewall block rule
        
    Returns:
        Dict with success status and response data
    """

    port_str = f":{port}" if port else ""
    rule_description = f"BLOCK {source_ip} -> {dest_ip}{port_str} ({protocol})"
    
    logger.info(f"Adding block rule: {rule_description}")

    url = f"{FIREWALL_URL}/rules/block"
    
    payload = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'protocol': protocol
    }
    
    if port is not None:
        payload['port'] = port
        
    result = _make_request("POST", url, json=payload)
    
    if not result['success']:
        logger.error(f"Failed to add block rule: {result['error']}")
        
    return {'rules_added_current_epoch': rule_description}

def remove_firewall_rule(rule_numbers: List[int]) -> Dict[str, Any]:
    """
    Remove firewall rule(s) by number(s)

    Args:
        rule_numbers: List of rule numbers to remove (single rule = list with one element)

    Returns:
        Dict with success status and response data
    """
    logger.info(f"Removing firewall rules: {rule_numbers}")
    if not isinstance(rule_numbers, list):
        error_msg = f"Invalid rule_numbers type: {type(rule_numbers)}. Expected List[int]"
        logger.error(error_msg)
        return {
            'success': False,
            'error': error_msg,
            'status_code': 400
        }
    
    # Validate list contains only integers
    if not all(isinstance(num, int) for num in rule_numbers):
        error_msg = "rule_numbers must be a list of integers"
        logger.error(error_msg)
        return {
            'success': False,
            'error': error_msg,
            'status_code': 400
        }
    
    # Get current rules before removal for tracking
    current_rules = {}
    try:
        firewall_result = get_firewall_rules()
        if firewall_result.get('firewall_config', {}).get('success'):
            rules_text = firewall_result['firewall_config']['data']['rules']
            
            # Parse the iptables output to extract individual rules
            for line in rules_text.split('\n'):
                line = line.strip()
                if line and line[0].isdigit():
                    # Extract rule number and rule content
                    parts = line.split(' ', 1)
                    if len(parts) >= 2:
                        rule_num = int(parts[0])
                        rule_content = parts[1]
                        current_rules[rule_num] = rule_content
                        
    except Exception as e:
        logger.warning(f"Could not retrieve current rules for tracking: {e}")
    
    # Create rule descriptions for tracking
    rule_descriptions = []
    for rule_num in rule_numbers:
        if rule_num in current_rules:
            rule_description = f"REMOVED rule #{rule_num}: {current_rules[rule_num]}"
        else:
            rule_description = f"REMOVED rule #{rule_num}: unknown"
        rule_descriptions.append(rule_description)

    url = f"{FIREWALL_URL}/rules"
    payload = {"rule_numbers": rule_numbers}
    result = _make_request("DELETE", url, json=payload)

    if not result['success']:
        logger.error(f"Failed to remove rules: {result['error']}")
    
    return {'rules_removed_current_epoch': rule_descriptions}

# Retrieve Alerts from eve.json
def get_alerts(time_window: int = 5) -> Dict[str, Any]:
    """
    Get Suricata alerts for threat detection.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with Suricata alerts data
    """
    url = f"{SURICATA_URL}/alerts"
    params = {'time_window' : min(time_window, 5)}
    result = _make_request("GET", url, params=params)
    alerts = {}
    if result['success']:
        alerts = result['data']
    else:
        logger.error(f"Failed to get Suricata alerts: {result['error']}")
    return {'security_events' : alerts}

# Retrieve Fast Alerts from fast.log
def get_fast_alerts(time_window: int = 5) -> Dict[str, Any]:
    """
    Get Suricata fast alerts for threat detection.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with Suricata fast alerts data
    """
    url = f"{SURICATA_URL}/fastlog"
    params = {'time_window' : min(time_window, 5)}
    result = _make_request("GET", url, params=params)
    alerts = {}
    if result['success']:
        alerts = result['data']
    else:
        logger.error(f"Failed to get Suricata fast alerts: {result['error']}")
    return {'security_events' : alerts}

# Health Check Functions
def check_services_health() -> Dict[str, Any]:
    """
    Check health of both firewall and packet monitor services
    
    Returns:
        Dict with health status of both services
    """
    try:
        firewall_status = _make_request("GET", f"{FIREWALL_URL}/health")
        suricata_status = _make_request("GET", f"{SURICATA_URL}/health")
        firewall_health = 'up' if firewall_status["data"]["status"] == 'healthy' else 'down'
        suricata_health = 'up' if suricata_status["data"]["status"] == 'ok' else 'down'
    except Exception as e:
        print(f"Error: {e}")
    return {
            'firewall_status': firewall_health,
            'suricata_status': suricata_health
        }

def get_docker_containers() -> List[Dict[str, Any]]:
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
            if ip_address in ['192.168.100.2', '192.168.200.2'] or container.name in ['cve-2021-22205-redis-1', 'cve-2021-22205-postgresql-1', 'suricata']:
                continue # Skip the firewall and attacker containers and backend containers

            info = {
                'id': container.id[:12],  # Short ID
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else container.image.id[:12],
                'status': container.status,
                'created': container.attrs['Created'],
                'ports': list(container.ports.keys()),
                'ip_address': ip_address
            }
            container_info.append(info)
            
        return {'honeypot_config' : container_info}
        
    except docker.errors.DockerException as e:
        return {"error": f"Docker connection error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def save_iteration_summary(
    currently_exposed: str = "",
    evidence_summary: str = "",
    justification: str = "",
    honeypots_exploitation: Dict[str, Dict[str, Any]] = {},  # IP -> {percentage: float, service: str, status: str}
    decision_rationale: str = "",
    next_iteration_guidance: str = "",
    lockdown_status: str = "INACTIVE",
    inferred_attack_graph: Dict[str, Any] = {}
) -> Dict[str, Any]:
    """
    Save iteration summary with structured data for benchmark metrics collection.
    
    Args:
        currently_exposed: IP:PORT or "NONE" if lockdown
        evidence_summary: Brief description of compromise evidence
        justification: Why these rules were necessary
        honeypots_exploitation: Dict mapping IPs to {percentage, service, status}
        decision_rationale: Strategic decision explanation
        next_iteration_guidance: What to monitor/act upon next
        lockdown_status: ACTIVE/INACTIVE
        inferred_attack_graph: Dict representing the inferred attack graph structure
    
    Returns:
        Dict with success status and iteration info
    """
    iteration_data = {
        "currently_exposed": currently_exposed,
        "honeypots_exploitation": honeypots_exploitation,
        "decision_rationale": decision_rationale,
        "lockdown_status": lockdown_status,

        "evidence_summary": evidence_summary,
        "justification": justification,
        "next_iteration_guidance": next_iteration_guidance,
        "inferred_attack_graph": inferred_attack_graph
    }


    return iteration_data

