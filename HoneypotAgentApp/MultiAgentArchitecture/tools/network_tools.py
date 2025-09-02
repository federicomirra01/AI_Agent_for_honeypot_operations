import docker
from typing import Dict, List, Any
from .tools_utils import _make_request_async, _make_request
from .firewall_tools import SURICATA_URL, FIREWALL_URL
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Retrieve Alerts from eve.json
async def get_alerts(time_window: int = 5) -> Dict[str, Any]:
    """
    Get Suricata alerts for threat detection.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with Suricata alerts data
    """
    url = f"{SURICATA_URL}/alerts"
    params = {'time_window' : min(time_window, 5)}
    result = await _make_request_async("GET", url, params=params)
    alerts = {}
    if result['success']:
        alerts = result['data']
    else:
        logger.error(f"Failed to get Suricata alerts: {result['error']}")
    return {'security_events' : alerts}

# Retrieve Fast Alerts from fast.log
async def get_fast_alerts(time_window: int = 5) -> Dict[str, Any]:

    """
    Get Suricata fast alerts for threat detection.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with Suricata fast alerts data
    """
    url = f"{SURICATA_URL}/fastlog"
    params = {'time_window' : min(time_window, 5)}
    result = await _make_request_async("GET", url, params=params)
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
    firewall_health, suricata_health = 'down', 'down'
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

def get_docker_containers() -> Dict[str, Any]:
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
            if ip_address in ['192.168.100.2', '192.168.200.2'] or container.name in ['cve-2021-22205-redis-1', 'cve-2021-22205-postgresql-1', 'suricata', 'cve-2021-22205-gitlab-1']:
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
    inferred_attack_graph: Dict[str, Any] = {},
    exploitation_strategy: str=""
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
        exploitation_strategy: exploitation strategy that the firewall agent needs to follow
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
        "inferred_attack_graph": inferred_attack_graph,
        "exploitation_strategy": exploitation_strategy
    }


    return iteration_data

