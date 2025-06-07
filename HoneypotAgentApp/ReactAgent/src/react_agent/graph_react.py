from langgraph.graph import START, END, StateGraph
from langgraph.prebuilt import ToolNode
from typing import Literal
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
import json
import os

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
openai.api_key = os.environ["OPENAI_API_KEY"]

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class HoneypotStateReact:
    messages: List[BaseMessage] = field(default_factory=list)
    packet_summary: str = ""
    network_packets : List[Dict[str, Any]] = field(default_factory=list)
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)
    firewall_status: str = ""
    monitor_status: str = ""

    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.network_packets = kwargs.get('network_packets', [])
        self.packet_summary = kwargs.get('packet_summary', "")
        self.firewall_config = kwargs.get('firewall_config', [])
        self.honeypot_config = kwargs.get('honeypot_config', [])
        self.firewall_status = kwargs.get('firewall_status', "")
        self.monitor_status = kwargs.get('monitor_status', "")

# System prompts
from langchain_core.prompts import ChatPromptTemplate

SYSTEM_PROMPT_GPT_REACT_ONLY_RULES_v0 = """
Honeypot Firewall Guardian: AI Agent Specification

Role & Identity
You are a cybersecurity AI agent specializing in dynamic firewall management for honeypot systems. Your primary function is to analyze network traffic and autonomously generate iptables rules that both protect the honeypot and strategically engage potential attackers.
The firewall rules are executed on a firewall that protects the entire network and not on the container itself, hence take into consideration the containers private IP address.

You have granted access to the following tools:

Network Intelligence Tools:
- check_services_health: Verify firewall and packet monitor status
- get_firewall_rules: Retrieve current active firewall rules and configuration
- get_packets: Get captured packets with filtering options (protocol, direction, limit)
- getDockerContainers: get list of available honeypot dockers

Firewall Management Tools:
- get_firewall_rules: Get traffic statistics from firewall counters

Network Context:
- Attacker Network: 192.168.100.0/24 (source of potential threats)
- Agent Network: 192.168.200.0/30 (your operational network)  
- Honeypot Containers: Various private IPs within protected network
- Monitor focuses on traffic to/from attacker network (192.168.100.0/24)

Objectives
1. Protect the honeypot from traffic surges and malicious attack patterns.
2. Guide attacker behavior by strategically exposing or filtering ports.
3. Enhance the likelihood of capturing complete attack sequences.
4. Engage attackers in prolonged interactions to collect intelligence.

Operational Parameters
- Autonomy: Operate without human initiation.
- Environment: Test setting to demonstrate reasoning capabilities.
- Tool Usage: You must gather information systematically:
  1. Check firewall and monitor status first (use the tool check_services_health) MANDATORY!!!
  2. Assess current state (get_firewall_rules, get_packets, getDockerContainers)
  3. Make informed decisions based on collected intelligence
  4. Output the firewall rules tha you would implement and the end the cycle 
- Efficiency: Gather essential information efficiently, avoid redundant tool calls

Tactical Guidelines
- Expose one container at a time based on observed traffic patterns. So if one container is already exposed you must decide what other container expose and close the already opened one.
- Close previously opened ports when opening new ones to maintain control.
- Use DROP rules for clearly malicious IPs showing aggressive scanning or attack behaviors.
- Implement rate-limiting (-m limit) for ports experiencing repeated access attempts.
- Apply ACCEPT, DROP, or REJECT actions appropriately based on traffic analysis.
- Target rules precisely to avoid overblocking legitimate traffic.
- Analyze packet directions (inbound/outbound/internal/external) to understand attack vectors.
- Consider traffic volume, protocols, and timing patterns in decision-making.

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
- Show understanding of traffic patterns and threat analysis

Success Metrics
- Effective mitigation of identified threats through targeted blocking.
- Strategic port management guiding attacker exploration toward valuable honeypots.
- Well-reasoned decisions demonstrating understanding of network traffic patterns.
- Efficient use of available tools to gather actionable intelligence.
- Dynamic adaptation to observed attack patterns and network conditions.
"""

SYSTEM_PROMPT_GPT_REACT_ONLY_RULES = """
Honeypot Firewall Guardian: AI Agent Specification

Role & Identity
You are a cybersecurity AI agent specializing in dynamic firewall management for honeypot systems. Your primary function is to analyze network traffic and autonomously generate iptables rules that both protect the honeypot and strategically engage potential attackers.
The firewall rules are executed on a firewall that protects the entire network and not on the container itself, hence take into consideration the containers private IP address.

You have granted access to the following tools:

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

Network Context:
- Attacker Network: 192.168.100.0/24 (source of potential threats)
- Agent Network: 192.168.200.0/30 (your operational network)  
- Honeypot Containers: Various private IPs within protected network
- Monitor focuses on traffic to/from attacker network (192.168.100.0/24)

Objectives
1. Protect the honeypot from traffic surges and malicious attack patterns.
2. Guide attacker behavior by strategically exposing or filtering ports.
3. Enhance the likelihood of capturing complete attack sequences.
4. Engage attackers in prolonged interactions to collect intelligence.

Operational Parameters
- Autonomy: Operate without human initiation.
- Environment: Test setting to demonstrate reasoning capabilities.
- Tool Usage: You must gather information systematically:
  1. Check system health first (check_services_health)
  2. Assess current state (get_firewall_rules, get_packet_stats)
  3. Analyze recent activity (get_recent_packets, get_traffic_flows)
  4. Make informed decisions based on collected intelligence
  5. Implement rules using firewall management tools as needed
- Efficiency: Gather essential information efficiently, avoid redundant tool calls

Tactical Guidelines
- Expose one container at a time based on observed traffic patterns. So if one container is already exposed you must decide what other container expose and close the already opened one.
- Close previously opened ports when opening new ones to maintain control.
- Use DROP rules for clearly malicious IPs showing aggressive scanning or attack behaviors.
- Implement rate-limiting (-m limit) for ports experiencing repeated access attempts.
- Apply ACCEPT, DROP, or REJECT actions appropriately based on traffic analysis.
- Target rules precisely to avoid overblocking legitimate traffic.
- Analyze packet directions (inbound/outbound/internal/external) to understand attack vectors.
- Consider traffic volume, protocols, and timing patterns in decision-making.

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
- Show understanding of traffic patterns and threat analysis

Success Metrics
- Effective mitigation of identified threats through targeted blocking.
- Strategic port management guiding attacker exploration toward valuable honeypots.
- Well-reasoned decisions demonstrating understanding of network traffic patterns.
- Efficient use of available tools to gather actionable intelligence.
- Dynamic adaptation to observed attack patterns and network conditions.
"""

SUMMARIZE_PROMPT = ChatPromptTemplate.from_template("""
**Network Log Analysis for Firewall Policy Creation**

Analyze these network logs and extract firewall-relevant patterns:
{packets}
                                                    
The summarizing process need to take into account that the logs come from an honeypot which the current configuration comprises the following services: SSH on ip address 172.17.0.2 on port 2222.

Structure findings in these categories using precise technical terms:

1. **IP Threat Indicators**
   - High-frequency sources: `[IP: count]` (Threshold: >15 requests/min)
   - Known malicious IPs: `[IP]` (Cross-referenced with threat DB)
   - Unverified/new IPs: `[IP: first_seen]`

2. **Port/Protocol Risks** 
   - Suspicious port clusters: `[port: protocol: count]` 
     - Focus on: non-standard ports for services (e.g., HTTP on 8080)
     - Uncommon protocol mixes (e.g., SSH over UDP)
   - Baseline comparison: `[Percentage deviation from normal port distribution]`

3. **Geo-Location Threats**
   - Unexpected regions: `[country: percentage of total traffic]` 
     - Flag if: >5% traffic from non-operational regions
   - ASN anomalies: `[autonomous_system: expected? Y/N]`

4. **Behavioral Red Flags**
   - Scan patterns: `[IP: ports_scanned/time_window]`
   - Protocol violations: `[e.g., DNS tunneling attempts]`
   - Session abnormalities: `[short-lived:long-lived ratio]`

The output must be in a json format and should be efficiently structured to be given in input to an LLM to generate firewall rules. Hence, you should summarize the logs but maintaining the information needed to generate the rules.

""")


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
@tool
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

@tool
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

@tool
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

@tool
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

@tool
def get_packets(limit: int = 10000, protocol: Optional[str] = None, direction: Optional[str] = None):
    """
    Get captured packets with basic filtering - simplified for LLM analysis
        
    Returns:
        Dict with success status and packets data:
        - success: Boolean indicating if request succeeded
        - data: Dict containing:
          - packets: List of packet data
          - count: Number of packets returned
          - total_captured: Total packets captured since start
          - timestamp: When the data was retrieved
        - error: Error message if request failed
    """
    
    logger.info(f"Retrieving packets (limit: {limit}, protocol: {protocol}, direction: {direction})")
    url = f"{MONITOR_URL}/packets"
    
    # Build parameters
    params = {'limit': limit}
    
    # Add optional filters
    if protocol:
        params['protocol'] = protocol
    if direction:
        params['direction'] = direction
        
    raw_packets = _make_request("GET", url, params=params)
    
    if not raw_packets['success']:
        logger.error(f"Failed to get packets: {raw_packets['error']}")
        return raw_packets
    

    return {'network_packets' : raw_packets}


# Health Check Functions
@tool
def check_services_health() -> Dict[str, Any]:
    """
    Check health of both firewall and packet monitor services
    
    Returns:
        Dict with health status of both services
    """
    logger.info("Retrieving services status")
    try:
        firewall_health = 'up' if _make_request("GET", f"{FIREWALL_URL}/health")["data"]["status"] == 'healthy' else 'down'
        monitor_health = 'up' if _make_request("GET", f"{MONITOR_URL}/health")["data"]["status"] == 'healthy' else 'down'
        logger.info("Successfully retrieve services health")
    except Exception as e:
        print(f"Error: {e}")
    return {
            'firewall_status': firewall_health,
            'monitor_status': monitor_health
        }

@tool
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

# Initialize LLM
llm = ChatOpenAI(model="gpt-4o")

# Create list of tools
tools = [
    get_firewall_rules,
    #add_allow_rule,
    #add_block_rule,
    #remove_firewall_rule,
    get_packets,
    check_services_health,
    getDockerContainers
]

llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools(tools)

def assistant(state: HoneypotStateReact):
    """Main assistant function that processes the conversation and calls tools"""
    # Create system message with current state context
    print(f"network packets: {state.network_packets}\nfirewall_rules: {state.firewall_config}\nhoneypot_config{state.honeypot_config}\nservices_health: {[state.firewall_status, state.monitor_status]}")
    system_message = SystemMessage(content=SYSTEM_PROMPT_GPT_REACT_ONLY_RULES_v0)

    # Add context messages based on current state
    context_messages = []
    
    # Add packet summary context if available
    if state.packet_summary:
        context_messages.append(
            HumanMessage(content=f"Current packet analysis summary: {state.packet_summary}")
        )
    
    if state.firewall_config:
        context_messages.append(
            HumanMessage(content=f"Current firewall configuration: {state.firewall_config}")
        )

    if state.honeypot_config:
        context_messages.append(
            HumanMessage(content=f"Current honeypot dockers configuration: {state.honeypot_config}")
        )

    if not state.messages:
        initial_message = HumanMessage(
            content="Analyze the current honeypot network security status and update firewall rules as needed"
        )
        messages = [system_message] + [initial_message]
    else :
        messages = [system_message] + context_messages + state.messages

    # Get response from LLM
    response = llm_with_tools.invoke(messages)

    # Track tool calls if any are made
    new_state = {"messages" : state.messages + [response]}
    tool_calls = []
    if hasattr(response, 'tool_calls') and response.tool_calls:
        for tool_call in response.tool_calls:
            tool_calls.append(tool_call)
    
        new_state["pending_tool_calls"] = tool_calls
    return new_state


def execute_tools(state: HoneypotStateReact):
    """Execute pending tool calls and update state"""

    # Get the last message 
    last_message = state.messages[-1]
    
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        tool_node = ToolNode(tools)
        tool_responses = tool_node.invoke({"messages" : [last_message]})
        new_state = {
            "messages" : state.messages + tool_responses["messages"]
        }

        for tool_message in tool_responses["messages"]:
            try:
                result = json.loads(tool_message.content)
                
                if tool_message.name == 'getDockerContainers':
                    new_state["honeypot_config"] = result


                elif tool_message.name == 'get_packets':
                    new_state["network_packets"] = result

                elif tool_message.name == 'get_firewall_rules':
                    new_state["firewall_config"] = result

                elif tool_message.name == 'check_services_health':

                    new_state["firewall_status"] = result['firewall_status']
                    new_state["monitor_status"] = result['monitor_status']

            except Exception as e:
                print(f"Error: {e}\ntool_message: {tool_message}\ntool_responses: {tool_responses}")    
        return new_state
    
    return {"messages" : state.messages}
        


def summarize_packets(state: HoneypotStateReact):
    """Analyze and summarize packet data from tool results"""
    print("Summarizing packet data...")
    
    if state.network_packets:
        # Create summary using LLM
        summary_response = llm.invoke(
            SUMMARIZE_PROMPT.format(packets=json.dumps(state.network_packets, indent=2))
        )
        packet_summary = summary_response.content
    else:
        packet_summary = "No packet data available for analysis."
        print("No packet data found for summarization")
    
    return {"packet_summary": packet_summary}


def tool_list():
    return tools




def should_continue(state: HoneypotStateReact) -> Literal["tools", "summarize", "__end__"]:
    """Determine next action based on the last message"""
    last_message = state.messages[-1]
    
    # If the last message has tool calls, execute them
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        return "tools"
    
    # Check if we need to summarize packet data
    if state.network_packets and not state.packet_summary:
        return "summarize"
    
    # if state.pending_tool_calls:
    #     return "tools"
    
    # Otherwise, we're done
    return "__end__"

# Build the graph
def build_react_graph():
    """Build the LangGraph workflow"""
    builder = StateGraph(HoneypotStateReact)
    
    # Add nodes
    builder.add_node("assistant", assistant)
    builder.add_node("tools", execute_tools)
    builder.add_node("summarize", summarize_packets)
    
    # Add edges
    builder.add_edge(START, "assistant")
    builder.add_conditional_edges("assistant", should_continue)
    builder.add_edge("tools", "assistant")
    builder.add_edge("summarize", "assistant")
    
    return builder.compile()


# Create the graph
graph = build_react_graph()