from langgraph.graph import START, END, StateGraph
from langgraph.prebuilt import ToolNode
from typing import Literal
import json
import os
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional, Tuple
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, ToolMessage, AIMessage
from dataclasses import dataclass, field
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
import docker
import requests
import logging
import openai


def is_api_key_valid():
    try:
        response = openai.Completion.create(
            engine="davinci",
            prompt="This is a test.",
            max_tokens=5
        )
    except:
        return False
    else:
        return True

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
openai.api_key = os.environ["OPENAI_API_KEY"]

#  Check the validity of the API key
api_key_valid = is_api_key_valid()
print("API key is valid:", api_key_valid)
print("\n" * 10)
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
FIREWALL_URL = "http://192.168.200.2:5000"
MONITOR_URL = "http://192.168.200.2:6000"
REQUEST_TIMEOUT = 10

@dataclass
class HoneypotStateReact:
    messages: List[BaseMessage] = field(default_factory=list)
    packet_summary: str = ""
    tools_completed: bool = False
    tools_called: set = field(default_factory=set)
    phase: str = "gathering"

    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.packet_summary = kwargs.get('packet_summary', "")
        self.tools_completed = kwargs.get('tools_completed', False)
        self.tools_called = kwargs.get('tools_called', set())
        self.phase = kwargs.get('phase', 'gathering')

# System prompts
# System prompts
SYSTEM_PROMPT_GPT_REACT = """
Honeypot Firewall Guardian: AI Agent Specification

Role & Identity
You are a cybersecurity AI agent specializing in dynamic firewall management for honeypot systems. Your primary function is to analyze network traffic and autonomously generate iptables rules that both protect the honeypot and strategically engage potential attackers.

CRITICAL WORKFLOW INSTRUCTIONS:

PHASE 1 - INFORMATION GATHERING (ONLY ONCE EACH):
You MUST call these 3 tools in order, ONLY ONCE EACH:
1. getDockerContainers - Get honeypot container information
2. get_firewall_rules - Get current firewall configuration  
3. get_recent_packets - Get recent network activity

PHASE 2 - ANALYSIS AND ACTION:
After ALL 3 tools have been called, analyze the data and implement firewall rule changes if needed. You have access to the following tools:
- add_allow_rule - Add a firewall rule to allow traffic
- add_block_rule - Add a firewall rule to block traffic
- remove_firewall_rule - Remove an existing firewall rule

CRITICAL MEMORY RULES:
- BEFORE calling ANY tool, check your conversation history for previous ToolMessage responses
- If you see a ToolMessage with the tool name, that tool was ALREADY CALLED - DO NOT call it again
- Use the existing data from previous tool responses instead of calling tools again
- After calling all 3 required tools, move directly to analysis and rule implementation

STOPPING CONDITION:
Once you have responses from getDockerContainers, get_firewall_rules, and get_recent_packets:
- DO NOT call any more information gathering tools
- Analyze the collected data
- Make firewall rule changes ONLY if actually needed
- Provide your Final Answer with reasoning

Example correct workflow:
1. **Thought**: "I need container information" → **Action**: getDockerContainers
2. **Thought**: "I need firewall rules" → **Action**: get_firewall_rules  
3. **Thought**: "I need packet data" → **Action**: get_recent_packets
4. **Thought**: "I have all data, now I'll analyze..." → **Final Answer**: [analysis and any rule changes]

Network Context:
- Attacker Network: 192.168.100.0/24 (source of potential threats)
- Agent Network: 192.168.200.0/30 (your operational network)  
- Honeypot Containers: Various private IPs within protected network

ABSOLUTE RULES:
- Never call the same information gathering tool twice
- Maximum 6 tool calls total
- Check message history before every tool call
- Stop gathering information after 3 required tools are called
"""

PACKET_SUMMARY_PROMPT = ChatPromptTemplate.from_template("""
**Network Packet Analysis for Security Decision Making**

Analyze the following network packets and create a concise security summary:

{packets}

Provide a structured analysis focusing on:

1. **Threat Assessment**
   - Suspicious IP addresses and their activities
   - Attack patterns (port scans, brute force attempts, etc.)
   - Traffic anomalies

2. **Traffic Patterns**
   - Most active source IPs
   - Target ports and services
   - Protocol distribution

3. **Security Recommendations**
   - IPs that should be blocked
   - Ports that need protection
   - Services requiring attention

Keep the summary concise but actionable for firewall rule generation.
""")

# Helper function for HTTP requests
def _make_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """Make HTTP request with error handling"""
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

# Tool definitions using @tool decorator
@tool
def get_firewall_rules() -> Dict[str, Any]:
    """Get current firewall rules"""
    logger.info("Retrieving firewall rules...")
    url = f"{FIREWALL_URL}/rules"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved firewall rules")
    else:
        logger.error(f"Failed to get firewall rules: {result['error']}")
        
    return result

@tool
def add_allow_rule(source_ip: str, dest_ip: str, port: Optional[int] = None, protocol: str = "tcp") -> Dict[str, Any]:
    """Add firewall allow rule"""
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

@tool
def add_block_rule(source_ip: str, dest_ip: str, port: Optional[int] = None, protocol: str = "tcp") -> Dict[str, Any]:
    """Add firewall block rule"""
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

@tool
def remove_firewall_rule(rule_number: int) -> Dict[str, Any]:
    """Remove firewall rule by number"""
    logger.info(f"Removing firewall rule #{rule_number}")
    url = f"{FIREWALL_URL}/rules/{rule_number}"
    result = _make_request("DELETE", url)
    
    if result['success']:
        logger.info(f"Successfully removed rule #{rule_number}")
    else:
        logger.error(f"Failed to remove rule: {result['error']}")
        
    return result

@tool
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
    
    Args:
        limit: Maximum number of packets to return (default: 100)
        protocol: Filter by protocol (TCP, UDP, ICMP)
        direction: Filter by traffic direction (inbound, outbound, internal, external)
        since: ISO timestamp to get packets since that time
        recent_minutes: Get packets from the last X minutes
        include_stats: Include packet statistics in response
        include_protocols: Include protocol distribution summary
        include_flows: Include top traffic flows
        raw_only: Return only raw tcpdump header lines (minimal processing)
        analysis_mode: Special analysis mode:
            - 'security': Focus on security threats and suspicious patterns
            - 'http': Analyze HTTP traffic with payload inspection
            - 'summary': Comprehensive monitoring overview
            - None: Standard packet retrieval
        
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

@tool
def check_services_health() -> Dict[str, Any]:
    """Check health of both firewall and packet monitor services"""
    firewall_health = _make_request("GET", f"{FIREWALL_URL}/health")
    monitor_health = _make_request("GET", f"{MONITOR_URL}/health")
    
    return {
        'firewall': firewall_health,
        'monitor': monitor_health,
        'both_healthy': firewall_health['success'] and monitor_health['success']
    }

@tool
def getDockerContainers() -> List[Dict[str, Any]]:
    """Get information about running Docker containers including their private IP addresses"""
    try:
        client = docker.from_env()
        containers = client.containers.list()
        container_info = []
        
        for container in containers:
            ip_address = None
            networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
            
            for network_name, network_config in networks.items():
                if network_config.get('IPAddress'):
                    ip_address = network_config.get('IPAddress')
                    break
            
            info = {
                'id': container.id[:12],
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
        return [{"error": f"Docker connection error: {str(e)}"}]
    except Exception as e:
        return [{"error": f"Unexpected error: {str(e)}"}]



# Initialize LLM
llm = ChatOpenAI(model="gpt-4o")

# Create list of tools
tools = [
    get_firewall_rules,
    add_allow_rule,
    add_block_rule,
    remove_firewall_rule,
    get_packets,
    check_services_health,
    getDockerContainers
]

def validate_message_sequence(messages: List[BaseMessage]) -> List[BaseMessage]:
    """
    Validate and fix message sequence to ensure proper tool call/response pairing.
    Remove orphaned tool messages that don't follow assistant messages with tool_calls.
    """
    validated_messages = []
    
    for i, message in enumerate(messages):
        if isinstance(message, ToolMessage):
            # Check if previous message is an AI message with tool_calls
            if (i > 0 and 
                isinstance(messages[i-1], AIMessage) and 
                hasattr(messages[i-1], 'tool_calls') and 
                messages[i-1].tool_calls):
                validated_messages.append(message)
            else:
                # Skip orphaned tool messages
                logger.warning(f"Skipping orphaned tool message: {message.name}")
                continue
        else:
            validated_messages.append(message)
    
    return validated_messages

# Bind tools to LLM
llm_with_tools = llm.bind_tools(tools)

# Create tool node
tool_node = ToolNode(tools)

def assistant(state: HoneypotStateReact):
    """Main assistant function that processes the conversation and calls tools"""
    # Validate and fix message sequence
    validated_messages = validate_message_sequence(state.messages)

    tools_called = set()
    for message in validated_messages:
        if isinstance(message, ToolMessage):
            tools_called.add(message.name)

    
    # Create system message with current state context
    system_context = SYSTEM_PROMPT_GPT_REACT
    
     # Add state awareness to the context
    if tools_called:
        tools_called_list = ", ".join(tools_called)
        state_context = f"\n\nSTATE AWARENESS: You have already called these tools: {tools_called_list}\n"
        state_context += "DO NOT call these tools again. Use the existing data from previous responses.\n"
        system_context += state_context
    # Add packet summary context if available
    if state.packet_summary:
        context_message = HumanMessage(content=f"Current packet analysis summary: {state.packet_summary}")
        messages = [SystemMessage(content=system_context), context_message] + validated_messages
    else:
        messages = [SystemMessage(content=system_context)] + validated_messages
    
    # Get response from LLM
    response = llm_with_tools.invoke(messages)

    new_state = {
        "messages": validated_messages + [response],
        "tools_called": tools_called
    }

    required_tools = {'getDockerContainers', 'get_firewall_rules', 'get_recent_packets'}
    if required_tools.issubset(tools_called):
        new_state['phase'] = 'analyzing'
    
    return new_state

def summarize_packets(state: HoneypotStateReact):
    """Analyze and summarize packet data from tool results"""
    print("Summarizing packet data...")
    
    # Look for packet data in recent tool messages
    packet_data = None
    validated_messages = validate_message_sequence(state.messages)
    for message in reversed(validated_messages):
        if isinstance(message, ToolMessage) and message.name in ['get_packets', 'get_recent_packets']:
            try:
                tool_result = json.loads(message.content)
                if tool_result.get('success') and tool_result.get('data', {}).get('packets'):
                    packet_data = tool_result['data']['packets']
                    break
            except (json.JSONDecodeError, KeyError):
                continue
    
    if packet_data:
        # Create summary using LLM
        summary_response = llm.invoke(
            PACKET_SUMMARY_PROMPT.format(packets=json.dumps(packet_data, indent=2))
        )
        packet_summary = summary_response.content
        print(f"Generated packet summary: {packet_summary[:200]}...")
    else:
        packet_summary = "No packet data available for analysis."
        print("No packet data found for summarization")
    
    tools_called = set()
    for message in validated_messages:
        if isinstance(message, ToolMessage):
            tools_called.add(message.name)

    return {
        "packet_summary": packet_summary,
        "messages": validated_messages,
        "tools_called": tools_called
        }



def should_continue(state: HoneypotStateReact) -> Literal["tools", "summarize", "__end__"]:
    """Determine next action based on the last message with strict limits"""
    validated_messages = validate_message_sequence(state.messages)
    
    if not validated_messages:
        return "__end__"
    
    # Count tool calls to enforce maximum limit
    tool_call_count = sum(1 for msg in validated_messages 
                         if isinstance(msg, ToolMessage))
    logger.info(f"Current tool call count: {tool_call_count}")

    # Maximum 6 tool calls allowed
    if tool_call_count >= 6:
        logger.info("Maximum tool calls reached, ending execution")
        return "__end__"
    
    last_message = validated_messages[-1]
    
    # If the last message has tool calls, execute them
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        return "tools"
    
    # Check what tools have been called
    tools_called = set()
    for message in validated_messages:
        if isinstance(message, ToolMessage):
            tools_called.add(message.name)
    
    required_tools = {'getDockerContainers', 'get_firewall_rules', 'get_recent_packets'}
    missing_tools = required_tools - tools_called
    logger.info(f"Required tools not called yet: {missing_tools}")
    # If we have called all required tools, check if we need to summarize
    if required_tools.issubset(tools_called):
        # Check if we need to summarize packet data
        if any(isinstance(msg, ToolMessage) and msg.name in ['get_packets', 'get_recent_packets'] 
               for msg in validated_messages) and not state.packet_summary:
            return "summarize"
        
        # All required tools called and summary done (if needed), we're done
        logger.info("All required tools called and processed, ending execution")
        return "__end__"
    
    # If we haven't called all required tools yet, continue but don't call duplicates
    return "__end__"  # Let assistant decide what to call next

# Build the graph
def build_react_graph():
    """Build the LangGraph workflow"""
    builder = StateGraph(HoneypotStateReact)
    
    # Add nodes
    builder.add_node("assistant", assistant)
    builder.add_node("tools", tool_node)
    builder.add_node("summarize", summarize_packets)
    
    # Add edges
    builder.add_edge(START, "assistant")
    builder.add_conditional_edges("assistant", should_continue)
    builder.add_edge("tools", "assistant")
    builder.add_edge("summarize", "assistant")
    
    return builder.compile()

# Create the graph
graph = build_react_graph()