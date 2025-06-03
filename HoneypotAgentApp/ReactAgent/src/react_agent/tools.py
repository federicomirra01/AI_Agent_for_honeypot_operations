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

def get_packets(limit: int = 100, 
               protocol: Optional[str] = None,
               direction: Optional[str] = None, 
               since: Optional[str] = None,
               recent_minutes: Optional[int] = None,
               include_stats: bool = False,
               include_protocols: bool = False,
               include_flows: bool = False,
               raw_only: bool = False,
               analysis_mode: Optional[str] = None) -> Dict[str, Any]:
    """
    Get captured packets with optional filtering and enhanced analysis
    
  
    Returns:
        Dict with success status and enhanced packets data including:
        - packets: List of packet data (unless raw_only=True)
        - raw_lines: List of raw tcpdump headers (if raw_only=True)
        - count: Number of packets returned
        - total_captured: Total packets captured since start
        - statistics: Packet statistics (if include_stats=True)
        - protocol_summary: Protocol distribution (if include_protocols=True)
        - top_flows: Top traffic flows (if include_flows=True)
        - analysis: Enhanced analysis results (if analysis_mode specified)
    """
    
    # Determine optimal parameters based on analysis mode
    if analysis_mode == 'security':
        logger.info(f"Security analysis mode: checking for threats in last {recent_minutes or 30} minutes")
        limit = max(limit, 1000)  # Get more packets for threat analysis
        recent_minutes = recent_minutes or 30
        include_stats = True
        include_flows = True
        
    elif analysis_mode == 'http':
        logger.info(f"HTTP analysis mode: analyzing web traffic in last {recent_minutes or 15} minutes")
        protocol = 'TCP'  # HTTP runs over TCP
        limit = max(limit, 500)
        recent_minutes = recent_minutes or 15
        include_stats = True
        
    elif analysis_mode == 'summary':
        logger.info(f"Summary analysis mode: comprehensive overview of last {recent_minutes or 60} minutes")
        limit = max(limit, 200)
        recent_minutes = recent_minutes or 60
        include_stats = True
        include_protocols = True
        include_flows = True
    
    logger.info(f"Retrieving packets (limit: {limit}, protocol: {protocol}, direction: {direction}, mode: {analysis_mode})")
    url = f"{MONITOR_URL}/packets"
    
    # Build parameters
    params = {'limit': limit}
    
    # Add optional filters
    if protocol:
        params['protocol'] = protocol
    if direction:
        params['direction'] = direction
    if since:
        params['since'] = since
    if recent_minutes:
        params['recent'] = recent_minutes
        
    # Add optional enhancement flags
    if include_stats:
        params['stats'] = 'true'
    if include_protocols:
        params['protocols'] = 'true'
    if include_flows:
        params['flows'] = 'true'
    if raw_only:
        params['raw_only'] = 'true'
        
    result = _make_request("GET", url, params=params)
    
    if not result['success']:
        logger.error(f"Failed to get packets: {result['error']}")
        return result
        
    data = result['data']
    packet_count = data.get('count', 0)
    total_captured = data.get('total_captured', 0)
    packets = data.get('packets', [])
    
    logger.info(f"Successfully retrieved {packet_count} packets (total captured: {total_captured})")
    
    # Perform enhanced analysis based on mode
    if analysis_mode and not raw_only:
        analysis_result = _perform_analysis(analysis_mode, packets, data, recent_minutes or 30)
        if analysis_result:
            data['analysis'] = analysis_result
    
    # Log additional info if enhanced data is included
    if include_stats and 'statistics' in data:
        stats = data['statistics']['stats']
        threats = stats.get('security_threats', 0)
        if threats > 0:
            logger.warning(f"Security threats detected: {threats}")
            
    if include_protocols and 'protocol_summary' in data:
        protocols = data['protocol_summary']
        logger.info(f"Protocol distribution: {protocols}")
        
    if include_flows and 'top_flows' in data:
        flows = len(data['top_flows'])
        logger.info(f"Top flows included: {flows}")
        
    return result


def _perform_analysis(mode: str, packets: List[Dict], data: Dict, period_minutes: int) -> Dict[str, Any]:
    """
    Perform enhanced analysis based on the specified mode
    
    Args:
        mode: Analysis mode ('security', 'http', 'summary')
        packets: List of packet data
        data: Full response data from server
        period_minutes: Analysis period in minutes
        
    Returns:
        Dict with analysis results specific to the mode
    """
    
    if mode == 'security':
        return _analyze_security_threats(packets, data, period_minutes)
    elif mode == 'http':
        return _analyze_http_traffic(packets, data, period_minutes)
    elif mode == 'summary':
        return _generate_summary(packets, data, period_minutes)
    
    return {}


def _analyze_security_threats(packets: List[Dict], data: Dict, period_minutes: int) -> Dict[str, Any]:
    """Analyze packets for security threats and suspicious patterns"""
    
    # Filter packets with security threats
    threat_packets = []
    for packet in packets:
        if ('suspicious_patterns' in packet or 
            'suspicious_uri_patterns' in packet):
            threat_packets.append(packet)
    
    # Extract threat statistics
    threat_stats = {}
    if 'statistics' in data:
        stats = data['statistics']['stats']
        threat_stats = {
            'total_threats': stats.get('security_threats', 0),
            'command_injection': stats.get('threat_command_injection', 0),
            'sql_injection': stats.get('threat_sql_injection', 0),
            'xss_attempts': stats.get('threat_xss', 0),
            'reverse_shells': stats.get('threat_reverse_shell', 0),
            'path_traversal': stats.get('threat_path_traversal', 0)
        }
    
    # Analyze threat patterns by source IP
    threat_sources = {}
    for packet in threat_packets:
        source_ip = packet.get('source_ip', 'unknown')
        if source_ip not in threat_sources:
            threat_sources[source_ip] = {
                'count': 0,
                'threat_types': set(),
                'targets': set()
            }
        
        threat_sources[source_ip]['count'] += 1
        threat_sources[source_ip]['targets'].add(packet.get('dest_ip', 'unknown'))
        
        # Categorize threat types
        for pattern in packet.get('suspicious_patterns', []):
            if 'command injection' in pattern.lower():
                threat_sources[source_ip]['threat_types'].add('command_injection')
            elif 'sql injection' in pattern.lower():
                threat_sources[source_ip]['threat_types'].add('sql_injection')
            elif 'xss' in pattern.lower():
                threat_sources[source_ip]['threat_types'].add('xss')
            elif 'reverse shell' in pattern.lower():
                threat_sources[source_ip]['threat_types'].add('reverse_shell')
            elif 'path traversal' in pattern.lower():
                threat_sources[source_ip]['threat_types'].add('path_traversal')
    
    # Convert sets to lists for JSON serialization
    for source in threat_sources:
        threat_sources[source]['threat_types'] = list(threat_sources[source]['threat_types'])
        threat_sources[source]['targets'] = list(threat_sources[source]['targets'])
    
    logger.info(f"Security analysis: {len(threat_packets)} threat packets from {len(threat_sources)} sources")
    if threat_stats.get('total_threats', 0) > 0:
        logger.warning(f"Total security threats detected: {threat_stats['total_threats']}")
    
    return {
        'mode': 'security',
        'analysis_period_minutes': period_minutes,
        'threat_packets': threat_packets,
        'threat_count': len(threat_packets),
        'threat_statistics': threat_stats,
        'threat_sources': threat_sources,
        'total_packets_analyzed': len(packets),
        'top_flows': data.get('top_flows', {}),
        'summary': {
            'threats_detected': len(threat_packets) > 0,
            'high_risk_sources': len([s for s in threat_sources.values() if s['count'] >= 5]),
            'threat_diversity': len(set().union(*[s['threat_types'] for s in threat_sources.values()]))
        }
    }


def _analyze_http_traffic(packets: List[Dict], data: Dict, period_minutes: int) -> Dict[str, Any]:
    """Analyze HTTP traffic with payload inspection"""
    
    # Filter for HTTP traffic with payload data
    http_packets = []
    for packet in packets:
        if (packet.get('application') == 'HTTP' and 
            'http_method' in packet):
            http_packets.append(packet)
    
    # Categorize HTTP traffic
    http_analysis = {
        'requests': [],
        'responses': [],
        'suspicious_requests': [],
        'methods': {},
        'status_codes': {},
        'user_agents': {},
        'uri_patterns': {}
    }
    
    for packet in http_packets:
        if packet.get('http_type') == 'request':
            http_analysis['requests'].append(packet)
            
            # Count methods
            method = packet.get('http_method', 'UNKNOWN')
            http_analysis['methods'][method] = http_analysis['methods'].get(method, 0) + 1
            
            # Analyze URIs
            uri = packet.get('http_uri', '')
            if uri:
                # Extract URI patterns (file extensions, directories)
                if '.' in uri:
                    ext = uri.split('.')[-1].split('?')[0][:10]  # Limit length
                    http_analysis['uri_patterns'][f".{ext}"] = http_analysis['uri_patterns'].get(f".{ext}", 0) + 1
            
            # Extract User-Agent if present
            headers = packet.get('http_headers', {})
            user_agent = headers.get('user-agent', 'Unknown')[:50]  # Limit length
            http_analysis['user_agents'][user_agent] = http_analysis['user_agents'].get(user_agent, 0) + 1
            
            # Check for suspicious patterns
            if ('suspicious_patterns' in packet or 
                'suspicious_uri_patterns' in packet):
                http_analysis['suspicious_requests'].append(packet)
                
        elif packet.get('http_type') == 'response':
            http_analysis['responses'].append(packet)
            
            # Count status codes
            status = packet.get('http_status_code', 0)
            http_analysis['status_codes'][status] = http_analysis['status_codes'].get(status, 0) + 1
    
    # Analyze attack patterns
    attack_summary = {
        'sql_injection_attempts': 0,
        'xss_attempts': 0,
        'command_injection_attempts': 0,
        'path_traversal_attempts': 0,
        'suspicious_user_agents': 0
    }
    
    for packet in http_analysis['suspicious_requests']:
        patterns = packet.get('suspicious_patterns', []) + packet.get('suspicious_uri_patterns', [])
        for pattern in patterns:
            if 'sql injection' in pattern.lower():
                attack_summary['sql_injection_attempts'] += 1
            elif 'xss' in pattern.lower():
                attack_summary['xss_attempts'] += 1
            elif 'command injection' in pattern.lower():
                attack_summary['command_injection_attempts'] += 1
            elif 'path traversal' in pattern.lower():
                attack_summary['path_traversal_attempts'] += 1
    
    logger.info(f"HTTP analysis: {len(http_packets)} HTTP packets "
                f"({len(http_analysis['requests'])} requests, "
                f"{len(http_analysis['responses'])} responses)")
    
    if http_analysis['suspicious_requests']:
        logger.warning(f"Found {len(http_analysis['suspicious_requests'])} suspicious HTTP requests")
    
    return {
        'mode': 'http',
        'analysis_period_minutes': period_minutes,
        'http_packets': http_packets,
        'requests': http_analysis['requests'],
        'responses': http_analysis['responses'],
        'suspicious_requests': http_analysis['suspicious_requests'],
        'method_distribution': http_analysis['methods'],
        'status_code_distribution': http_analysis['status_codes'],
        'user_agent_distribution': dict(sorted(http_analysis['user_agents'].items(), key=lambda x: x[1], reverse=True)[:10]),
        'uri_patterns': dict(sorted(http_analysis['uri_patterns'].items(), key=lambda x: x[1], reverse=True)[:10]),
        'attack_summary': attack_summary,
        'summary': {
            'total_http_packets': len(http_packets),
            'requests': len(http_analysis['requests']),
            'responses': len(http_analysis['responses']),
            'suspicious_requests': len(http_analysis['suspicious_requests']),
            'unique_methods': len(http_analysis['methods']),
            'unique_status_codes': len(http_analysis['status_codes']),
            'unique_user_agents': len(http_analysis['user_agents'])
        }
    }


def _generate_summary(packets: List[Dict], data: Dict, period_minutes: int) -> Dict[str, Any]:
    """Generate comprehensive monitoring summary"""
    
    # Generate summary report
    summary = {
        'mode': 'summary',
        'monitoring_period_minutes': period_minutes,
        'timestamp': data.get('timestamp'),
        'packet_overview': {
            'packets_in_period': data.get('count', 0),
            'total_captured': data.get('total_captured', 0),
            'capture_active': data.get('statistics', {}).get('running', False)
        },
        'protocol_distribution': data.get('protocol_summary', {}),
        'top_traffic_flows': data.get('top_flows', {}),
        'security_summary': {},
        'application_traffic': {},
        'traffic_direction': {}
    }
    
    # Extract security information
    if 'statistics' in data:
        stats = data['statistics']['stats']
        summary['security_summary'] = {
            'total_threats': stats.get('security_threats', 0),
            'threat_types': {
                'command_injection': stats.get('threat_command_injection', 0),
                'sql_injection': stats.get('threat_sql_injection', 0),
                'xss_attempts': stats.get('threat_xss', 0),
                'reverse_shells': stats.get('threat_reverse_shell', 0),
                'path_traversal': stats.get('threat_path_traversal', 0)
            }
        }
        
        # Extract traffic direction stats
        for key, value in stats.items():
            if key.startswith('direction_'):
                direction = key.replace('direction_', '')
                summary['traffic_direction'][direction] = value
    
    # Extract application traffic stats
    apps = {}
    for packet in packets:
        app = packet.get('application', 'Other')
        apps[app] = apps.get(app, 0) + 1
    summary['application_traffic'] = apps
    
    # Calculate additional metrics
    summary['insights'] = {
        'most_active_protocol': max(summary['protocol_distribution'].items(), key=lambda x: x[1])[0] if summary['protocol_distribution'] else 'None',
        'security_risk_level': 'HIGH' if summary['security_summary']['total_threats'] > 10 else 'MEDIUM' if summary['security_summary']['total_threats'] > 0 else 'LOW',
        'top_application': max(apps.items(), key=lambda x: x[1])[0] if apps else 'None',
        'capture_rate': f"{data.get('count', 0) / period_minutes:.1f} packets/minute" if period_minutes > 0 else '0 packets/minute'
    }
    
    logger.info(f"Summary generated: {summary['packet_overview']['packets_in_period']} packets analyzed, "
                f"security risk: {summary['insights']['security_risk_level']}")
    
    return summary

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
