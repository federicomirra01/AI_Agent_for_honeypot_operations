import asyncio
from typing import Dict, List, Any
from .tools_utils import _make_request_async, _make_request
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
FIREWALL_URL = "http://192.168.200.2:5000"
SURICATA_URL = "http://192.168.200.2:7000"
firewall_lock = asyncio.Lock()

async def add_allow_rule(source_ip: str, dest_ip: str, port=None, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Add firewall allow rule
    
    Returns:
        Dict with success status and response data
    """
    async with firewall_lock:
        response = await _add_allow_rule(source_ip, dest_ip, port, protocol)
    
    return response

async def add_block_rule(source_ip: str, dest_ip: str, port=None, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Add firewall block rule
        
    Returns:
        Dict with success status and response data
    """
    async with firewall_lock:
        response = await _add_block_rule(source_ip, dest_ip, port, protocol)
    return response 

async def remove_firewall_rule(rule_numbers: List[int]) -> Dict[str, Any]:
    """
    Remove firewall rule(s) by number(s)

    Args:
        rule_numbers: List of rule numbers to remove (single rule = list with one element)

    Returns:
        Dict with success status and response data
    """
    async with firewall_lock:
        response = await _remove_firewall_rule(rule_numbers)
    return response

async def get_firewall_rules() -> Dict[str, Any]:
    """
    Get current firewall rules
    
    Returns:
        Dict with success status and rules data
    """
    url = f"{FIREWALL_URL}/rules"
    result = await _make_request_async("GET", url)
    
    if result['success']:
        success = True # just to keep logger.info commented
    else:
        logger.error(f"Failed to get firewall rules: {result['error']}")
        
    return {'firewall_config' : result}

async def _add_allow_rule(source_ip: str, dest_ip: str, port=None, protocol: str = "tcp") -> Dict[str, Any]:
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
    result = await _make_request_async("POST", url, json=payload)
    
    if not result['success']:
        logger.error(f"Failed to add allow rule: {result['error']}")
    return {'rules_added_current_epoch': rule_description}

async def _add_block_rule(source_ip: str, dest_ip: str, port=None, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Add firewall block rule
        
    Returns:
        Dict with success status and response data
    """

    port_str = f":{port}" if port else ""
    rule_description = f"BLOCK {source_ip} -> {dest_ip}{port_str} ({protocol})"
    
    logger.info(f"Adding allow rule: {rule_description}")

    url = f"{FIREWALL_URL}/rules/block"
    
    payload = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'protocol': protocol
    }

    if port is not None:
        payload['port'] = port
        
    result = await _make_request_async("POST", url, json=payload)
    
    if not result['success']:
        logger.error(f"Failed to add block rule: {result['error']}")
        
    return {'rules_added_current_epoch': rule_description}

async def _remove_firewall_rule(rule_numbers: List[int]) -> Dict[str, Any]:
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
        firewall_result = await get_firewall_rules()
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
    result = await _make_request_async("DELETE", url, json=payload)

    if not result['success']:
        logger.error(f"Failed to remove rules: {result['error']}")
    
    return {'rules_removed_current_epoch': rule_descriptions}
