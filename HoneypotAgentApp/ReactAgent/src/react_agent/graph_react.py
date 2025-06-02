from langgraph.graph import START, END, StateGraph
from langgraph.prebuilt import ToolNode
from typing import Literal
import json
import os
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional, Tuple
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, ToolMessage
from dataclasses import dataclass, field
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
import docker
import requests
import logging
import openai

openai.api_key = 'YOUR_API_KEY'

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

#
# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
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

    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.packet_summary = kwargs.get('packet_summary', "")
        self.tools_completed = kwargs.get('tools_completed', False)

# System prompts
SYSTEM_PROMPT_GPT_REACT = """
Honeypot Firewall Guardian: AI Agent Specification

Role & Identity
You are a cybersecurity AI agent specializing in dynamic firewall management for honeypot systems. Your primary function is to analyze network traffic and autonomously generate iptables rules that both protect the honeypot and strategically engage potential attackers.

You have access to the following tools:

Network Intelligence Tools:
- check_services_health: Verify firewall and packet monitor APIs are operational
- get_firewall_rules: Retrieve current active firewall rules and configuration
- get_packet_stats: Get packet capture statistics and monitoring status
- get_recent_packets: Get network packets captured in the last 5 minutes
- get_traffic_flows: Get summary of active traffic flows between IPs
- get_packets: Get captured packets with filtering options (protocol, direction, limit)

Firewall Management Tools:
- add_allow_rule: Add ACCEPT rule (source_ip, dest_ip, port=None, protocol="tcp")
- add_block_rule: Add DROP rule (source_ip, dest_ip, port=None, protocol="tcp")
- remove_firewall_rule: Remove existing rule by line number
- get_firewall_stats: Get traffic statistics from firewall counters

Container Information:
- getDockerContainers: Get information about running honeypot containers

Network Context:
- Attacker Network: 192.168.100.0/24 (source of potential threats)
- Agent Network: 192.168.200.0/30 (your operational network)  
- Honeypot Containers: Various private IPs within protected network

Objectives
1. Protect the honeypot from traffic surges and malicious attack patterns.
2. Guide attacker behavior by strategically exposing or filtering ports.
3. Enhance the likelihood of capturing complete attack sequences.
4. Engage attackers in prolonged interactions to collect intelligence.

ReACT Workflow
1. **Thought**: Analyze what information is needed for current situation assessment
2. **Action**: Use appropriate tools to gather network intelligence
3. **Observation**: Process the returned data to understand network state
4. **Thought**: Determine threats, opportunities, and required firewall changes
5. **Action**: Implement firewall rules using management tools if needed
6. **Final Answer**: Provide reasoning and any implemented rule changes

Output Requirements
- Use ReACT format: Thought → Action → Observation → Thought → Action → Final Answer
- Base decisions on actual data gathered from tools
- Provide clear reasoning for each firewall rule decision
- Rules must account for container private IP addresses when targeting honeypots
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
def get_firewall_stats() -> Dict[str, Any]:
    """Get firewall traffic statistics"""
    logger.info("Retrieving firewall statistics...")
    url = f"{FIREWALL_URL}/stats"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved firewall stats")
    else:
        logger.error(f"Failed to get firewall stats: {result['error']}")
        
    return result

@tool
def get_packets(limit: int = 100, protocol: Optional[str] = None, direction: Optional[str] = None, since: Optional[str] = None) -> Dict[str, Any]:
    """Get captured packets with optional filtering"""
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

@tool
def get_recent_packets() -> Dict[str, Any]:
    """Get packets from the last 5 minutes"""
    logger.info("Retrieving recent packets (last 5 minutes)...")
    url = f"{MONITOR_URL}/packets/recent"
    result = _make_request("GET", url)
    
    if result['success']:
        packet_count = len(result['data'].get('packets', []))
        logger.info(f"Successfully retrieved {packet_count} recent packets")
    else:
        logger.error(f"Failed to get recent packets: {result['error']}")
        
    return result

@tool
def get_packet_stats() -> Dict[str, Any]:
    """Get packet capture statistics"""
    logger.info("Retrieving packet statistics...")
    url = f"{MONITOR_URL}/stats"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved packet stats")
    else:
        logger.error(f"Failed to get packet stats: {result['error']}")
        
    return result

@tool
def get_traffic_flows() -> Dict[str, Any]:
    """Get traffic flows summary"""
    logger.info("Retrieving traffic flows...")
    url = f"{MONITOR_URL}/packets/flows"
    result = _make_request("GET", url)
    
    if result['success']:
        logger.info("Successfully retrieved traffic flows")
    else:
        logger.error(f"Failed to get traffic flows: {result['error']}")
        
    return result

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
    get_firewall_stats,
    get_firewall_rules,
    add_allow_rule,
    add_block_rule,
    remove_firewall_rule,
    get_packets,
    get_recent_packets,
    get_packet_stats,
    get_traffic_flows,
    check_services_health,
    getDockerContainers
]

# Bind tools to LLM
llm_with_tools = llm.bind_tools(tools)

# Create tool node
tool_node = ToolNode(tools)

def assistant(state: HoneypotStateReact):
    """Main assistant function that processes the conversation and calls tools"""
    # Create system message with current state context
    system_message = SystemMessage(content=SYSTEM_PROMPT_GPT_REACT)
    
    # Add packet summary context if available
    if state.packet_summary:
        context_message = HumanMessage(content=f"Current packet analysis summary: {state.packet_summary}")
        messages = [system_message, context_message] + state.messages
    else:
        messages = [system_message] + state.messages
    
    # Get response from LLM
    response = llm_with_tools.invoke(messages)
    
    return {"messages": state.messages + [response]}

def summarize_packets(state: HoneypotStateReact):
    """Analyze and summarize packet data from tool results"""
    print("Summarizing packet data...")
    
    # Look for packet data in recent tool messages
    packet_data = None
    for message in reversed(state.messages):
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
    
    return {"packet_summary": packet_summary}

def should_continue(state: HoneypotStateReact) -> Literal["tools", "summarize", "__end__"]:
    """Determine next action based on the last message"""
    last_message = state.messages[-1]
    
    # If the last message has tool calls, execute them
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        return "tools"
    
    # Check if we need to summarize packet data
    if any(isinstance(msg, ToolMessage) and msg.name in ['get_packets', 'get_recent_packets'] 
           for msg in state.messages) and not state.packet_summary:
        return "summarize"
    
    # Otherwise, we're done
    return "__end__"

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