from typing import Dict,  Any
import state
from tools import network_tools, firewall_tools
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def network_gathering(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    logger.info("Network gathering Node")
    """
    Network Gathering Node:
    Fetch IDS alerts, Docker containers, and firewall rules.
    """
    time_window = config.get("configurable", {}).get("time_window", "0")
    time_window = int(time_window)
    alerts = config.get("configurable", {}).get("prompt", "Default")
    # Call tools directly
    if "fast" in alerts:
        alerts_response = await network_tools.get_fast_alerts(time_window=time_window)
    else:
        alerts_response = await network_tools.get_alerts(time_window=time_window)

    containers_response = network_tools.get_docker_containers()
    firewall_response = await firewall_tools.get_firewall_rules()
    
    # Parse results 
    security_events = alerts_response.get('security_events', {})
    honeypot_config = containers_response.get('honeypot_config', {})
    firewall_config = firewall_response.get('firewall_config', {})
    
    # Update state
    return {
        "security_events": security_events,
        "honeypot_config": honeypot_config,
        "firewall_config": firewall_config,
    }
