
from langgraph.graph import START, END, StateGraph
from typing import Literal
import json
import os
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional, Tuple
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from dataclasses import dataclass, field
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import docker

@dataclass
class HoneypotStateReact:

    messages: List[BaseMessage] = field(default_factory=list)
    network_logs: List[Dict[str, Any]] = field(default_factory=list)
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    pending_tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    tools_completed: bool = False
    to_summarize: bool = False
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)

    def __init__(self, **kwargs):
        """
        Custom initializer that can handle both direct field assignment
        and dictionary unpacking.
        """
        # Handle 'messages' input
        self.messages = kwargs.get('messages', [])
        # Convert string message to BaseMessage if needed
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.network_logs = kwargs.get('network_logs', [{}])
        self.summary = kwargs.get('summary', "")
        self.firewall_config = kwargs.get('firewall_config', "")
        self.pending_tool_calls = kwargs.get('pending_tool_calls', [])
        self.tools_completed = kwargs.get('tools_completed', False)
        self.to_summarize = kwargs.get('to_summarize', False)
        self.honeypot_config = kwargs.get('honeypot_config', [{}])

@dataclass
class HoneypotState:

    messages: List[BaseMessage] = field(default_factory=list)
    network_logs: List[Dict[str, Any]] = field(default_factory=list)
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)

    def __init__(self, **kwargs):
        """
        Custom initializer that can handle both direct field assignment
        and dictionary unpacking.
        """
        # Handle 'messages' input
        self.messages = kwargs.get('messages', [])
        # Convert string message to BaseMessage if needed
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.network_logs = kwargs.get('network_logs', [{}])
        self.summary = kwargs.get('summary', "")
        self.firewall_config = kwargs.get('firewall_config', "")
        self.honeypot_config = kwargs.get('honeypot_config', [{}])

SUMMARIZE_PROMPT = ChatPromptTemplate.from_template("""
**Network Log Analysis for Firewall Policy Creation**

Analyze these network logs and extract firewall-relevant patterns:
{logs}
                                                    
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

SYSTEM_PROMPT_GPT = """
Honeypot Firewall Guardian: AI Agent Specification

Role & Identity
You are a cybersecurity AI agent specializing in dynamic firewall management for honeypot systems. Your primary function is to analyze network traffic and autonomously generate iptables rules that both protect the honeypot and strategically engage potential attackers.

Objectives
1. Protect the honeypot from traffic surges and malicious attack patterns.
2. Guide attacker behavior by strategically exposing or filtering ports.
3. Enhance the likelihood of capturing complete attack sequences.
4. Engage attackers in prolonged interactions to collect intelligence.

Operational Parameters
- Autonomy: Operate without human initiation.
- Environment: Test setting to demonstrate reasoning capabilities.
- Inputs: Receive a State object containing:
  - Network logs (JSON format or summarized data).
  - Honeypot service configuration details.
  - Current firewall rule configuration.

Tactical Guidelines
- Expose one container at a time based on observed traffic patterns.
- Close previously opened ports when opening new ones to maintain control.
- Use DROP rules for clearly malicious IPs.
- Implement rate-limiting (-m limit) for ports experiencing repeated access.
- Apply ACCEPT, DROP, or REJECT actions appropriately based on context.
- Target rules precisely to avoid overblocking legitimate traffic.
- Include explanatory comments for each rule generated.

Output Requirements
- Produce valid iptables syntax only.
- Provide strategic justification for each rule.
- Offer a clear explanation of traffic analysis reasoning.
- Explain for each Docker container why it is accessible or not.

Success Metrics
- Effective mitigation of identified threats.
- Strategic port management guiding attacker exploration.
- Well-reasoned rules demonstrating understanding of network traffic patterns.
"""


def getNetworkStatus(file_path="/home/c0ff3k1ll3r/Desktop/Thesis/AI_Agent_for_honeypot_operations/logsSSH/tshark_pcap/ssh_traffic.json") -> dict:
    """
    Retrieve current network activity from parsed logs.
    
    Parameters:
    - file_path (str): Path to the JSON file containing tshark output
    
    Returns:
    - dict: network activity
    """
    
    
    try:
        # Load the JSON data from tshark output
        with open(file_path, 'r') as file:
            raw_data = json.load(file)
        
        
    except Exception as e:
        return {
            "error": "Processing error",
            "details": str(e)
        }
    return json.dumps(raw_data)


def getFirewallConfiguration():
    """Retrieve the list of current firewall rules."""
    return {
        "firewall_rules": []
        }

def getDockerContainers():
    """
    Returns information about running Docker containers using the Docker API,
    including their internal private IP addresses.
    No sudo required as long as the user has proper Docker permissions.
    
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


# Summarizing logs node
def summarize_logs(state: HoneypotState):
    print("Summarizing node")
    summary = llm.invoke(SUMMARIZE_PROMPT.format(logs=state.network_logs))
    return {"network_logs": [summary], "to_summarize": False}

def getPastRules():
    """Retrieve past rules from the database."""
    pass

def firwallUpdate():
    """Update the firewall rules using system commands based on the analysis of network traffic logs."""
    pass



# Load environment variables from .env file
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Initialize the LLM with the model name
llm = ChatOpenAI(model="gpt-4o")

#llm  = llm.bind_tools([getNetworkStatus, getFirewallConfiguration, getDockerContainers])

# Assistant function to handle the state and generate responses
def assistant(state: HoneypotState):
    llm_input = f"""{SYSTEM_PROMPT_GPT}\nState: {state}"""
    message = [SystemMessage(content=llm_input)]
    response = llm.invoke(message)
    if hasattr(response, "tool_calls") and response.tool_calls:
        pending_tool_calls = list(response.tool_calls)
        tools_completed = False
        return {
            "messages": state.messages + [response],
            "pending_tool_calls": pending_tool_calls,
            "tools_completed": tools_completed
        }
    else:
        # No tool calls or all tools completed
        return {
            "messages": state.messages + [response],
            "tools_completed": True
        }

# Retrieving logs node
def NetworkStatusNode(state: HoneypotState):
    # Your actual log retrieval logic here
    print("Network node")
    new_logs = getNetworkStatus()  
    to_summarize = False
    if len(new_logs) > 10:
        to_summarize = True

    return {"network_logs": [new_logs], "to_summarize": to_summarize}


# Retrieving firewall rules node
def FirewallConfigurationNode(state: HoneypotState):
    print("Firewall node")
    rules = getFirewallConfiguration()
    return {"firewall_config": rules}

def HoneypotConfigurationNode(state: HoneypotState):
    """
    Tool function for an agent to retrieve information about running Docker containers.
    """
    containers = getDockerContainers()
    print(f"Containers: {containers}")
    # Handle errors
    if isinstance(containers, dict) and "error" in containers:
        return containers
    
    
    return {"honeypot_config": containers}


def route_message(state: HoneypotState) -> Tuple[Literal["NetworkStatusNode", "FirewallConfigurationNode", "HoneypotConfigurationNode", "summarize", "__end__"], Dict[str, Any]]:
    # Check if we're in final response mode
    if hasattr(state, "tools_completed") and state.tools_completed:
        return END, {}
    
    if hasattr(state, "to_summarize") and state.to_summarize:
        return "summarize", {}

    message = state.messages[-1]

    # Initial tool calls processing
    if not hasattr(state, "pending_tool_calls") or not state.pending_tool_calls:
        if len(message.tool_calls) == 0:
            return END, {}
        pending_tool_calls = list(message.tool_calls)
    else:
        pending_tool_calls = state.pending_tool_calls

    # Process next tool call
    tool_call = pending_tool_calls.pop(0)

    # Determine next node based on tool call
    if tool_call['name'] == "getNetworkStatus":
        next_node = "NetworkStatusNode"
    elif tool_call['name'] == "getFirewallConfiguration":
        next_node = "FirewallConfigurationNode"
    elif tool_call['name'] == "getDockerContainers":
        next_node = "HoneypotConfigurationNode"
    else:
        raise ValueError(f"Unknown tool call: {tool_call['name']}")

    # Determine if all tools have been processed
    tools_completed = not pending_tool_calls

    # Return next node and updated state
    return next_node, {
        "pending_tool_calls": pending_tool_calls,
        "tools_completed": tools_completed
    }

# Graph
builder = StateGraph(HoneypotState)

# # Define nodes: 
def build_graph_react(builder: StateGraph):
    builder=builder
    builder.add_node("assistant", assistant)
    builder.add_node("FirewallConfigurationNode", FirewallConfigurationNode)
    builder.add_node("NetworkStatusNode",NetworkStatusNode)
    builder.add_node("summarize", summarize_logs)
    builder.add_node("HoneypotConfigurationNode", HoneypotConfigurationNode)


    # Build the graph
    builder.add_edge(START, "assistant")
    builder.add_conditional_edges("assistant", route_message)
    builder.add_edge("FirewallConfigurationNode", "assistant")
    builder.add_edge("NetworkStatusNode", "assistant")
    builder.add_edge("HoneypotConfigurationNode", "assistant")
    builder.add_edge("summarize", "assistant")

def build_graph_concurrent(builder:StateGraph):
    # Define nodes: 
    builder.add_node("assistant", assistant)
    builder.add_node("FirewallConfigurationNode", FirewallConfigurationNode)
    builder.add_node("NetworkStatusNode", NetworkStatusNode)
    builder.add_node("summarize", summarize_logs)
    builder.add_node("HoneypotConfigurationNode", HoneypotConfigurationNode)

    # Build the graph
    builder.add_edge(START, "FirewallConfigurationNode")
    builder.add_edge(START, "NetworkStatusNode")
    builder.add_edge(START, "HoneypotConfigurationNode")

    builder.add_edge("NetworkStatusNode", "summarize")
    builder.add_edge(["FirewallConfigurationNode", "HoneypotConfigurationNode","summarize"], "assistant")
    builder.add_edge("assistant", END)

build_graph_concurrent(builder)

graph = builder.compile()

