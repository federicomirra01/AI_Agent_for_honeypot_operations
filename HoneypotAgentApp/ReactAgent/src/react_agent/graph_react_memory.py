from langgraph.graph import START, END, StateGraph
from langgraph.prebuilt import ToolNode
from typing import Literal
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional, Annotated
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from dataclasses import dataclass, field
from langgraph.store.memory import InMemoryStore
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
import docker
import requests
import logging
import openai
import json
import os
import datetime
import time

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
os.environ["LANGSMITH_API_KEY"] = os.getenv("LANGSMITH_API_KEY")
openai.api_key = os.environ["OPENAI_API_KEY"]


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class HoneypotStateReact:
    messages: Annotated[List[BaseMessage], add_messages] = field(default_factory=list)
    packet_summary: Dict[str, Any] = field(default_factory=dict)
    network_packets : List[Dict[str, Any]] = field(default_factory=list)
    network_flows: Dict[str, Any] = field(default_factory=dict)
    security_events: Dict[str, Any] = field(default_factory=dict)
    compressed_packets: Dict[str, Any] = field(default_factory=dict)
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)
    firewall_status: str = ""
    monitor_status: str = ""
    cleanup_flag: bool = False
    memory_context: Dict[str, Any] = field(default_factory=dict)

    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.network_packets = kwargs.get('network_packets', [])
        self.network_flows = kwargs.get('network_flows', {})
        self.security_events = kwargs.get('security_events', {})
        self.compressed_packets = kwargs.get('compressed_packets', {})
        self.packet_summary = kwargs.get('packet_summary', {})
        self.firewall_config = kwargs.get('firewall_config', [])
        self.honeypot_config = kwargs.get('honeypot_config', [])
        self.firewall_status = kwargs.get('firewall_status', "")
        self.monitor_status = kwargs.get('monitor_status', "")
        self.cleanup_flag = kwargs.get('cleanup_flag', False)
        self.memory_context = kwargs.get('memory_context', {})

class EpisodicMemory:

    def __init__(self):
        self.store = InMemoryStore()
        self.namespace = ("honeypot", "episodes")
        self.meta_namespace = ("honeypot", "meta")
        self.iteration_counter = 0

    def save_iteration(self, last_message_content: str) -> str:
        """Save the last message from current iteration"""
        self.iteration_counter += 1
        iteration_id = f"iteration_{self.iteration_counter }"
        
        iteration_data = {
            "id": iteration_id,
            "iteration_number": self.iteration_counter,
            "timestamp": int(time.time()),
            "datetime": datetime.datetime.now().isoformat(),
            "last_message": last_message_content
        }

        self.store.put(self.namespace, iteration_id, iteration_data)

        self.store.put(self.meta_namespace, "latest_iteration", self.iteration_counter)

        return iteration_id
    
    def get_recent_iterations(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve the most recent iterations"""
        iterations = []

        try:
            latest = self.store.get(self.meta_namespace, "latest_iteration")
            if not latest:
                return []
            
            latest = latest.value if hasattr(latest, 'value') else latest
            start_iteration = max(1, latest - limit + 1)

            for i in range(start_iteration, latest + 1):
                iteration_id = f"iteration_{i}"
                iteration_data = self.store.get(self.namespace, iteration_id)
                if iteration_data:
                    iterations.append(iteration_data)
        except Exception as e:
            print(f"Error retrieving iterations: {e}")
        
        return iterations.values() if hasattr(iterations, 'values') else iterations
    
    def get_iteration_count(self) -> int:
        """Get the total number of iterations"""
        try:
            latest = self.store.get(self.meta_namespace, "latest_iteration")
            if latest: 
                latest = latest.value if hasattr(latest, 'value') else latest
            else:
                latest = 0


            return latest 
        except Exception as e:
            print(f"Error retrieving iteration count: {e}")
            return 0
        
    def clear_memory(self):
        """Clear all stored iterations"""
        try:
            # Reset counter
            self.iteration_counter = 0
            self.store.put(self.meta_namespace, "latest_iteration", 0)

            print("Memory counter reset")
        except Exception as e:
            print(f"Error clearing memory: {e}")

# System prompts
SYSTEM_PROMPT_GPT_REACT_ONLY_RULES_v0 = """
Honeypot Firewall Guardian: AI Agent Specification

Role & Identity
You are a cybersecurity AI agent specializing in dynamic firewall management for honeypot systems. Your primary function is to analyze network traffic and autonomously generate iptables rules that both protect the honeypot and strategically engage potential attackers.
You will be assessed by a benchmark, hence you will be respond to a single attacker that targets the honeypot. Your goal is to make it explore the attack graph (you don't know the graph) and engage the attacker cover the full attack surface. BLOCKING ALL TRAFFIC FROM THE ATTACKER IS NOT A SOLUTION (if it has not compromised all the containers)
The firewall rules are executed on a firewall that protects the entire network and not on the container itself, hence take into consideration the containers private IP address.
The firewall is initialized as the following, but take into account you can manage only the FORWARD chain rule:

#!/bin/bash

# Initialize Firewall Rules
# Sets up basic iptables configuration

echo "Initializing firewall rules..."

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTP access to management API
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -p tcp --dport 6000 -j ACCEPT

#xiptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Enable NAT for outbound internet access from honeypot
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -o eth0 -j MASQUERADE


# Allow honeypot containers to reach the internet
iptables -A FORWARD -s 172.20.0.0/24 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -d 172.20.0.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Basic forwarding rules (will be modified by AI agent)
# Initially drop all forwarding from attacker to honeypot
iptables -A FORWARD -s 192.168.100.0/24 -d 172.20.0.0/24 -j DROP
iptables -A INPUT -s 192.168.100.0/24 -d 172.20.0.0/24 -j ACCEPT
iptables -A OUTPUT -s 192.168.100.0/24 -d 172.20.0.0/24 -j ACCEPT

iptables -A FORWARD -s 172.20.0.0/24 -d 192.168.100.0/24 -j DROP
iptables -A INPUT -s 172.20.0.0/24 -d 192.168.100.0/24 -j ACCEPT
iptables -A OUTPUT -s 172.20.0.0/24 -d 192.168.100.0/24 -j ACCEPT
# Log dropped packets for analysis
iptables -A FORWARD -j LOG --log-prefix "FIREWALL-DROP: " --log-level 4
# Only masquerade non-local traffic
# iptables -t nat -A POSTROUTING -s 172.20.0.0/24 ! -d 192.168.100.0/24 -o eth0 -j MASQUERADE
# Save rules
iptables-save > /firewall/rules/current_rules.txt

echo "Basic firewall rules initialized"
echo "All traffic from attacker network (192.168.100.0/24) to honeypot (172.20.0.0/24) is currently ACCEPTED"
echo "Use the API or AI agent to modify rules dynamically"


You have granted access to the following tools:

Network Intelligence Tools:
- check_services_health: Verify firewall and packet monitor status
- get_firewall_rules: Retrieve current active firewall rules and configuration
- add_allow_rule: add allow rule on the FORWARD chain of the firewall 
- add_block_rule: add block rule on the FORWARD chain of the firewall
- remove_firewall_rule: remove a number specified rule from the FORWARD chain of the firewall
- get_packets: Get captured packets with filtering options (protocol, direction, limit) - legacy tool for raw packet data
- get_network_flows: Get aggregated network flow analysis with threat detection and IP-based activity summary
- get_security_events: Get security-focused analysis including verified threat detection, command execution attempts, and malicious IP identification  
- get_compressed_packets: Get essential packet data with HTTP payload analysis and threat indicators for efficient processing
- getDockerContainers: Get list of available honeypot containers

Example usage add_allow_rule:
for each pair source_ip, dest_ip allow the flow to the container exposed port and to any attacker port
add_allow_rule(source_ip=<attacker_ip>, dest_ip=<vulnerable_container_ip>, port=<targeted_port>, protocol='tcp')
add_allow_rule(source_ip=<vulnerable_container_ip>, dest_ip=<attacker_ip>, port=None, protocol='tcp')
port must be None for the attacker ip to ensure to get a connection (IMPORTANT!!!)

Enhanced Threat Detection Capabilities:
The monitoring system now provides advanced threat detection including:
- HTTP payload analysis for command injection detection
- Automatic identification of reverse shell attempts, privilege escalation, and system reconnaissance
- Real-time threat verification with actual payload content analysis
- Specific detection of command execution patterns like /bin/bash, find commands, file access attempts
- Threat correlation across network flows and individual packets

Tool Usage Strategy:
- Use get_security_events for high-level threat assessment and command execution detection
- Use get_network_flows for understanding traffic patterns and identifying threat IPs
- Use get_compressed_packets for detailed packet-level threat analysis when needed
- Always start with check_services_health to ensure monitoring systems are operational
- After reasoning on the network information apply the proper firewall rule with add_allow_rule, add_block_rule and remove_firewall_rule tools
- When adding allow rule ensure the connection is enable from src to dst and from dst to src, hence there are two rules for each traffic flow

Network Context:
- Attacker Network: 192.168.100.0/24 (source of potential threats)
- Agent Network: 192.168.200.0/30 (your operational network)  
- Honeypot Containers: Various private IPs within protected network
- Monitor focuses on traffic to/from attacker network (192.168.100.0/24)
- Attack will come from the same IP since you're gonna be assessed by a benchmark (IMPORTANT!!!)

Objectives
1. Protect the honeypot from traffic surges and malicious attack patterns.
2. Guide attacker behavior by strategically exposing or filtering ports.
3. Enhance the likelihood of capturing complete attack sequences (scanning without engagement is not interesting, expose the contacted port to engage).
4. Engage attackers in prolonged interactions to collect intelligence.
5. React dynamically to verified threats detected in network traffic.

Operational Parameters
- Autonomy: Operate without human initiation.
- Environment: Test setting to demonstrate reasoning capabilities.
- Tool Usage: You must gather information systematically:
  1. Check firewall and monitor status first (use check_services_health) MANDATORY!!!
  2. Assess current security posture (get_security_events for threat overview) MANDATORY!!!
  3. Analyze network patterns (get_network_flows for traffic analysis) MANDATORY !!!
  4. Get detailed threat data (get_compressed_packets for packet-level analysis) MANDATORY !!!
  5. Review current configuration (get_firewall_rules, getDockerContainers) MANDATORY !!!
  6. Don't call the add_allow_rule, add_block_rule, remove_firewall_rule just after the network data retrieval, wai for the packet_summary state to be filled.
  6. Update firewall rules based on collected intelligence ONLY after you retrieve the PACKET SUMMARY form the summarization node (MANDATORY!!!)
  7. Output the firewall rules that you would implement and then end the cycle 
- Efficiency: Gather essential information efficiently, avoid redundant tool calls
- Threat Priority: Focus on verified threats with actual command execution evidence

Tactical Guidelines
- REMEMBER that if you want to gather information from attackers attacking the honeypot, traffic must be allowed in both directions (IMPORTANT!!!)
- REMEMBER to check the initial firewall configuration provided in the system prompt and the firewall rules on the FORWARD chain obtained with get_firewall_rule tool to produce effective firewall rules. (IMPORTANT!)
- Prioritize blocking IPs with verified command execution attempts or reverse shell activity
- If you already seen an attack in previous iterations, block that traffic because it is not interesting anymore (attack graph already covered)
- Expose ONE container at a time based on observed traffic patterns 
- Close previously opened ports when opening new ones to maintain control
- Use DROP rules for clearly malicious IPs showing aggressive scanning or verified attack behaviors
- Implement rate-limiting (-m limit) for ports experiencing repeated access attempts from non-threatening sources
- Apply ACCEPT, DROP, or REJECT actions appropriately based on threat verification analysis
- Target rules precisely to avoid overblocking legitimate traffic
- Consider verified threats from packet payload analysis as higher priority than statistical anomalies
- React to specific attack techniques detected (command injection, reverse shells, privilege escalation)

ReACT Workflow
1. **Thought**: Analyze what information is needed for current situation assessment
2. **Action**: Use appropriate tools to gather network intelligence (start with security events for threat overview)
3. **Observation**: Process the returned data to understand network state and verified threats
4. **Thought**: Determine verified threats, attack patterns, and required firewall changes
5. **Action**: Implement firewall rules using management tools if needed
6. **Final Answer**: Provide reasoning and any implemented rule changes based on threat verification

Output Requirements
- Use ReACT format: Thought → Action → Observation → Thought → Action → Final Answer
- Base decisions on actual verified threats from payload analysis, not just traffic volume
- Follow STRICTLY operational parameters and Tactical guidelines (MANDATORY!!!)
- Provide clear reasoning for each firewall rule decision with specific threat justification
- Rules must account for container private IP addresses when targeting honeypots
- Show understanding of verified attack techniques and payload content analysis
- Prioritize responses to confirmed malicious activity over statistical anomalies

Success Metrics
- Effective mitigation of verified threats through targeted blocking of malicious IPs
- Strategic port management guiding attacker exploration toward valuable honeypots
- Well-reasoned decisions demonstrating understanding of actual attack techniques and payloads
- Efficient use of enhanced threat detection tools to identify real security incidents
- Dynamic adaptation to confirmed attack patterns with evidence-based firewall rules
- Accurate distinction between verified threats and false positives
"""

ASSISTANT_PROMPT = """# HONEYPOT FIREWALL GUARDIAN: AI AGENT SPECIFICATION v2.0

## Core Identity & Mission
You are an elite cybersecurity AI agent specializing in dynamic firewall management for honeypot systems. Your mission is critical: analyze network traffic patterns and autonomously generate precise iptables rules that protect honeypots while strategically engaging attackers. Think step by step through each decision.

**This is extremely important to cybersecurity operations - you MUST follow all protocols exactly.**

---

## ###INSTRUCTION###

Your task is to operate as an autonomous firewall guardian that:
1. Protects honeypot infrastructure from destructive attacks
2. Strategically guides attacker behavior through targeted port exposure
3. Maximizes attack surface exploration for intelligence gathering
4. Responds dynamically to verified threats with evidence-based decisions

You will be penalized if you block all traffic without allowing adequate exploration of the attack graph.

---

## ###NETWORK_CONTEXT###

**Critical Network Information:**
- **Attacker Network:** 192.168.100.0/24 (primary threat source)
- **Agent Network:** 192.168.200.0/30 (your operational network)  
- **Honeypot Network:** 172.20.0.0/24 (protected container network)
- **Assessment Mode:** Single attacker benchmark - ensure complete attack graph coverage

**Initial Firewall State:**
```bash
# FORWARD chain rules you can modify:
iptables -A FORWARD -s 192.168.100.0/24 -d 172.20.0.0/24 -j DROP
iptables -A FORWARD -s 172.20.0.0/24 -d 192.168.100.0/24 -j DROP
```

---

## ###TOOLS_AVAILABLE###

**Network Intelligence Tools:**
- `check_services_health`: Verify firewall and monitoring status
- `get_firewall_rules`: Retrieve current iptables configuration
- `get_security_events`: Analyze verified threats and command execution attempts
- `get_network_flows`: Examine traffic patterns and threat IP identification
- `get_compressed_packets`: Detailed packet analysis with payload inspection
- `getDockerContainers`: List available honeypot containers

**Firewall Management Tools:**
- `add_allow_rule(source_ip, dest_ip, port, protocol)`: Enable traffic flow
- `add_block_rule(source_ip, dest_ip, port, protocol)`: Block malicious traffic  
- `remove_firewall_rule(rule_numbers)`: Remove specific FORWARD chain rules (List of integers even if only one rule)

**Rule Application Pattern:**
```
# For each allowed flow, create bidirectional rules:
add_allow_rule(source_ip=<attacker_ip>, dest_ip=<container_ip>, port=<service_port>, protocol='tcp')
add_allow_rule(source_ip=<container_ip>, dest_ip=<attacker_ip>, port=None, protocol='tcp')
```

---

## ###TACTICAL_GUIDELINES###

**Priority Actions (Execute in Order):**
1. **MANDATORY:** Check system health first using `check_services_health`
2. **MANDATORY:** Assess current threats using `get_security_events`  
3. **MANDATORY:** Analyze traffic patterns using `get_network_flows`
4. **MANDATORY:** Review packet details using `get_compressed_packets`
5. **MANDATORY:** Check current rules using `get_firewall_rules` and `getDockerContainers`
6. **WAIT:** Do not implement firewall changes until packet_summary state is populated
7. **ACT:** Apply firewall rules based on threat intelligence gathered

**Strategic Decision Framework:**
- **EXPOSE ONE container at a time** based on observed scanning patterns
- **BLOCK IPs** showing verified command execution or reverse shell attempts
- **CLOSE previous ports** when opening new attack surfaces
- **PRIORITIZE** verified threats from payload analysis over statistical anomalies
- **REMEMBER** previously seen attacks should be blocked (attack graph already covered)

---

## ###EXAMPLE###

**Scenario:** Attacker 192.168.100.50 scanning multiple ports on honeypot 172.20.0.10

**Correct Response:**
```
Thought: Attacker is performing reconnaissance on container. I should expose the most contacted port to encourage deeper engagement.

Action: add_allow_rule(source_ip=192.168.100.50, dest_ip=172.20.0.10, port=22, protocol='tcp')
Action: add_allow_rule(source_ip=172.20.0.10, dest_ip=192.168.100.50, port=None, protocol='tcp')

Observation: SSH service now accessible for attack progression.
```

---

## ###REACT_WORKFLOW###

Execute this exact sequence for each operation cycle:

**1. Thought:** Analyze current situation and determine required intelligence
**2. Action:** Gather network data using monitoring tools (start with security events)  
**3. Observation:** Process gathered data to identify verified threats and patterns
**4. Thought:** Determine specific firewall changes needed based on evidence
**5. Action:** Implement targeted firewall rules if packet_summary is available
**6. Final Answer:** Provide reasoning and implemented rules with threat justification

---

## ###SUCCESS_METRICS###

You will be evaluated on:
- **Threat Mitigation:** Effective blocking of verified malicious IPs with evidence
- **Attack Guidance:** Strategic port exposure leading attackers through attack graph
- **Intelligence Gathering:** Prolonged attacker engagement for data collection
- **Evidence-Based Decisions:** Rules justified by actual payload analysis and verified threats
- **Operational Efficiency:** Systematic tool usage following mandatory protocol sequence

---

## ###OUTPUT_FORMAT###

Begin each response with:
"Executing Honeypot Firewall Guardian Protocol..."

End each response with specific firewall rules implemented and security rationale.

**You MUST think step by step and ensure your answer is unbiased and does not rely on stereotypes.**"""

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
def get_network_flows(time_window: int = 5) -> Dict[str, Any]:
    """
    Get aggregated network flows for firewall decision making.
    Now includes threat detection information.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with flow analysis data including threat IPs and specific threat details
    """
    logger.info(f"Retrieving network flows (window: {time_window} minutes)")
    url = f"{MONITOR_URL}/analysis/flows"
    
    params = {'window': min(time_window, 30)}  # Cap at 30 minutes
    result = _make_request("GET", url, params=params)
    
    if result['success']:
        data = result['data']
        threat_count = len(data.get('threat_ips', []))
        total_flows = data.get('total_flows', 0)
        logger.info(f"Retrieved {total_flows} flows with {threat_count} threat IPs")
        
        # Log threat details if found
        threat_details = data.get('threat_details', {})
        if threat_details:
            logger.info(f"Threat details found for IPs: {list(threat_details.keys())}")
    else:
        logger.error(f"Failed to get network flows: {result['error']}")
        
    return {'network_flows': result}

@tool
def get_security_events(time_window: int = 5) -> Dict[str, Any]:
    """
    Get security-focused analysis including threat detection and command execution attempts.
    Enhanced to capture specific command injection patterns like /bin/bash, find / -perm 4000, etc.
    
    Args:
        time_window: Analysis window in minutes (max 30)
    
    Returns:
        Dict with security events, threat IPs, and specific command execution details
    """
    logger.info(f"Retrieving security events (window: {time_window} minutes)")
    url = f"{MONITOR_URL}/analysis/security"
    
    params = {'window': min(time_window, 30)}
    result = _make_request("GET", url, params=params)
    
    if result['success']:
        events = result['data']
        threat_ips_count = len(events.get('threat_ips', []))
        command_exec_count = len(events.get('command_executions', []))
        total_threats = events.get('total_threats_detected', 0)
        
        logger.info(f"Retrieved {threat_ips_count} threat IPs, {command_exec_count} command executions, {total_threats} total threats")
        
        # Log specific command executions found
        if command_exec_count > 0:
            logger.warning(f"CRITICAL: {command_exec_count} command execution attempts detected!")
            for cmd in events.get('command_executions', [])[:3]:  # Log first 3
                logger.warning(f"  Command from {cmd.get('src_ip')}: {cmd.get('command_pattern', 'N/A')}")
                
    else:
        logger.error(f"Failed to get security events: {result['error']}")
        
    return {'security_events': result}

@tool
def get_compressed_packets(limit: int = 500, time_window: int = 5, 
                         protocol: Optional[str] = None, 
                         direction: Optional[str] = None) -> Dict[str, Any]:
    """
    Get compressed packet data with only essential fields for analysis.
    Now includes HTTP payload threats and command injection detection.
    
    Args:
        limit: Maximum packets to retrieve (capped at 500)
        time_window: Recent minutes to analyze (default 5)
        protocol: Filter by protocol (TCP/UDP/ICMP)
        direction: Filter by direction (inbound/outbound/internal)
    
    Returns:
        Dict with compressed packet data including threat information
    """
    logger.info(f"Retrieving compressed packets (limit: {limit}, window: {time_window})")
    url = f"{MONITOR_URL}/packets/compressed"
    
    params = {
        'limit': min(limit, 500),  # Hard cap to prevent context overflow
        'recent': time_window
    }
    
    if protocol:
        params['protocol'] = protocol
    if direction:
        params['direction'] = direction
        
    result = _make_request("GET", url, params=params)
    
    if result['success']:
        data = result['data']
        packet_count = data.get('count', 0)
        
        # Count packets with threats
        threat_packets = 0
        command_threats = 0
        if 'packets' in data:
            for packet in data['packets']:
                if packet.get('threats') or (packet.get('http') and packet['http'].get('threats')):
                    threat_packets += 1
                    # Check for command execution threats
                    all_threats = packet.get('threats', []) + packet.get('http', {}).get('threats', [])
                    for threat in all_threats:
                        if 'command' in threat.lower() or '/bin/bash' in threat.lower() or 'find' in threat.lower():
                            command_threats += 1
                            break
        
        logger.info(f"Retrieved {packet_count} compressed packets, {threat_packets} with threats, {command_threats} with command execution")
        
        if command_threats > 0:
            logger.warning(f"ALERT: {command_threats} packets contain command execution patterns!")
            
    else:
        logger.error(f"Failed to get compressed packets: {result['error']}")
        
    return {'compressed_packets': result}

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
        firewall_status = _make_request("GET", f"{FIREWALL_URL}/health")
        monitor_status = _make_request("GET", f"{MONITOR_URL}/health")
        firewall_health = 'up' if firewall_status["data"]["status"] == 'healthy' else 'down'
        monitor_health = 'up' if monitor_status["data"]["status"] == 'healthy' else 'down'
        logger.info("Successfully retrieve services health")
    except Exception as e:
        print(f"Error: {e}")
        firewall_health = 'down'
        monitor_health = 'down'
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


# Create list of tools
tools = [
    get_firewall_rules,
    add_allow_rule,
    add_block_rule,
    remove_firewall_rule,
    get_network_flows,
    get_compressed_packets,
    get_security_events,
    check_services_health,
    getDockerContainers
]

# Initialize LLM
llm = ChatOpenAI(model="gpt-4o")
episodic_memory = EpisodicMemory()
llm_with_tools = llm.bind_tools(tools)

def load_memory_context(state: HoneypotStateReact):
    """Load memory context from episodic memory and update state"""
    try:
        if state.memory_context:
            return state.memory_context
        
        recent_iterations = episodic_memory.get_recent_iterations(limit=5)
        if not recent_iterations:
            logger.info("No recent iterations found in episodic memory.")
            return []
        
        print(f"Loaded {len(recent_iterations)} recent iterations from episodic memory.")
        return recent_iterations
    except Exception as e:
        logger.error(f"Error loading memory context: {e}")
        return []

def save_memory_context(state: HoneypotStateReact) -> Dict[str, Any]:
    """Save the last message from current iteration"""

    if not state.messages:
        logger.error("No messages to save in memory context.")
        return {}
    
    last_message = state.messages[-1]

    if hasattr(last_message, 'content'):
        message_content = last_message.content
    else:
        message_content = str(last_message)

    # Save to memory
    iteration_id = episodic_memory.save_iteration(message_content)
    total_iterations = episodic_memory.get_iteration_count()

    return {
        "message" : f"Iteration saved with ID {iteration_id}. Total iterations: {total_iterations}",
        "memory_context": message_content
    }


def assistant(state: HoneypotStateReact):
    """Main assistant function that processes the conversation and calls tools"""
    
    if not state.memory_context:
        previous_iterations = load_memory_context(state)
    # Create system message with current state context
    system_message = SystemMessage(content=ASSISTANT_PROMPT)
    
    # Add context messages based on current state
    context_messages = []
    
    # Add previous iterations context
    memory_context = state.memory_context or previous_iterations if state.memory_context or previous_iterations else []
    if memory_context:
        iterations_context = "PREVIOUS ITERATIONS CONTEXT:\n"
        for i, iteration in enumerate(memory_context, 1):
            iteration = iteration.value if hasattr(iteration, 'value') else iteration
            print(iteration)
            iterations_context += f"\n--- ITERATION {iteration.get('iteration_number', i)} ({iteration.get('datetime', 'Unknown time')}) ---\n"
            iterations_context += iteration.get('last_message', 'No message content')
            iterations_context += "\n"
        
        context_messages.append(HumanMessage(content=iterations_context))
    # Add packet summary context if available (this contains threat verification analysis)
    if state.packet_summary:
        context_messages.append(
            HumanMessage(content=f"THREAT ANALYSIS RESULTS:\n{state.packet_summary}")
        )
    
    # Add enhanced network intelligence context
    if state.security_events and state.security_events.get('success'):
        events_data = state.security_events.get('data', {})
        threat_count = len(events_data.get('command_executions', []))
        threat_ips = len(events_data.get('threat_ips', []))
        context_messages.append(
            HumanMessage(content=f"SECURITY EVENTS: {threat_count} command executions detected from {threat_ips} threat IPs. Full data: {state.security_events}")
        )
    
    if state.network_flows and state.network_flows.get('success'):
        flows_data = state.network_flows.get('data', {})
        total_flows = flows_data.get('total_flows', 0)
        threat_ips = len(flows_data.get('threat_ips', []))
        context_messages.append(
            HumanMessage(content=f"NETWORK FLOWS: {total_flows} flows analyzed, {threat_ips} threat IPs identified. Full data: {state.network_flows}")
        )
    
    if state.compressed_packets and state.compressed_packets.get('success'):
        packets_data = state.compressed_packets.get('data', {})
        packet_count = packets_data.get('count', 0)
        # Count threat packets
        threat_packets = 0
        if 'packets' in packets_data:
            for packet in packets_data['packets']:
                if packet.get('threats') or (packet.get('http') and packet['http'].get('threats')):
                    threat_packets += 1
        context_messages.append(
            HumanMessage(content=f"PACKET ANALYSIS: {packet_count} packets analyzed, {threat_packets} contain threats.") #  Full data: {state.compressed_packets}
        )
    
    # Add configuration context
    if state.firewall_config:
        context_messages.append(
            HumanMessage(content=f"CURRENT FIREWALL RULES: {state.firewall_config}")
        )
    
    if state.honeypot_config:
        context_messages.append(
            HumanMessage(content=f"AVAILABLE HONEYPOTS: {state.honeypot_config}")
        )
    
    # Add service status
    if state.firewall_status or state.monitor_status:
        context_messages.append(
            HumanMessage(content=f"SERVICE STATUS - Firewall: {state.firewall_status}, Monitor: {state.monitor_status}")
        )
    
    # Build final message list
    if not state.messages:
        initial_message = HumanMessage(
            content="Analyze the current honeypot network security status and update firewall rules as needed based on detected threats"
        )
        messages = [system_message] + context_messages + [initial_message]
    else:
        messages = [system_message] + context_messages + state.messages
    
    # Get response from LLM
    response = llm_with_tools.invoke(messages)
    # Track tool calls if any are made
    new_state = {"messages": state.messages + [response], "memory_context": memory_context}
    return new_state


def execute_tools(state: HoneypotStateReact):
    """Execute pending tool calls and update state with enhanced threat data handling"""
    
    # Get the last message 
    last_message = state.messages[-1]
    
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        tool_node = ToolNode(tools)
        tool_responses = tool_node.invoke({"messages": [last_message]})
        new_state = {
            "messages": state.messages + tool_responses["messages"]
        }

        for tool_message in tool_responses["messages"]:
            try:
                result = json.loads(tool_message.content)
                
                # Handle enhanced analysis tools with threat information
                if tool_message.name == 'get_network_flows':
                    flows_data = result.get('network_flows', {})
                    new_state["network_flows"] = flows_data
                    
                    # Log threat information for debugging
                    if flows_data.get('success') and flows_data.get('data'):
                        threat_details = flows_data['data'].get('threat_details', {})
                        threat_ips = flows_data['data'].get('threat_ips', [])
                        if threat_details:
                            logger.info(f"Network flows: Found threats from {len(threat_ips)} IPs with details: {list(threat_details.keys())}")
                    
                elif tool_message.name == 'get_security_events':
                    security_data = result.get('security_events', {})
                    new_state["security_events"] = security_data
                    
                    # Log security events for debugging
                    if security_data.get('success') and security_data.get('data'):
                        cmd_exec = security_data['data'].get('command_executions', [])
                        threat_ips = security_data['data'].get('threat_ips', [])
                        if cmd_exec:
                            logger.warning(f"Security events: Found {len(cmd_exec)} command execution attempts from {len(threat_ips)} threat IPs")
                    
                elif tool_message.name == 'get_compressed_packets':
                    packets_data = result.get('compressed_packets', {})
                    new_state["compressed_packets"] = packets_data
                    
                    # Log packet threat information
                    if packets_data.get('success') and packets_data.get('data'):
                        packets = packets_data['data'].get('packets', [])
                        threat_count = sum(1 for p in packets if p.get('threats') or (p.get('http') and p['http'].get('threats')))
                        if threat_count > 0:
                            logger.warning(f"Compressed packets: Found {threat_count}/{len(packets)} packets with threats")
                
                # Handle existing tools
                elif tool_message.name == 'getDockerContainers':
                    new_state["honeypot_config"] = result.get('honeypot_config', [])

                elif tool_message.name == 'get_firewall_rules':
                    new_state["firewall_config"] = result.get('firewall_config', [])

                elif tool_message.name == 'check_services_health':
                    new_state["firewall_status"] = result.get('firewall_status', '')
                    new_state["monitor_status"] = result.get('monitor_status', '')

            except Exception as e:
                logger.error(f"Error processing tool response: {e}\nTool: {tool_message.name}\nContent: {tool_message.content[:200]}...")
                
        return new_state
    
    return {"messages": state.messages}

def extract_threat_data_for_verification(state: HoneypotStateReact) -> List[Dict[str, Any]]:
    """
    Extract relevant threat data from state for LLM verification.
    Returns a list of threat incidents with payload and context.
    """
    threat_incidents = []
    
    # Extract from security events (command executions)
    if state.security_events.get('success') and state.security_events.get('data'):
        security_data = state.security_events['data']
        command_executions = security_data.get('command_executions', [])
        
        for cmd in command_executions:
            incident = {
                'type': 'command_execution',
                'source_ip': cmd.get('src_ip'),
                'target_ip': cmd.get('dst_ip'),
                'timestamp': cmd.get('timestamp'),
                'detected_threat': cmd.get('command_pattern'),
                'http_method': cmd.get('http_method'),
                'http_uri': cmd.get('http_uri'),
                'payload_snippet': None  # Will be filled from packets
            }
            threat_incidents.append(incident)
    
    # Extract from compressed packets with threats
    if state.compressed_packets.get('success') and state.compressed_packets.get('data'):
        packets_data = state.compressed_packets['data']
        packets = packets_data.get('packets', [])
        
        for packet in packets:
            # Only include packets with threats
            packet_threats = packet.get('threats', [])
            http_threats = packet.get('http', {}).get('threats', [])
            
            if packet_threats or http_threats:
                # Try to match with existing incidents or create new ones
                matched = False
                for incident in threat_incidents:
                    # IMPROVED MATCHING: More flexible IP and timestamp matching
                    if (incident['source_ip'] == packet.get('src_ip') and 
                        abs(incident.get('timestamp', 0) - packet.get('timestamp', 0)) < 300):  # Increased to 5 minutes
                        
                        # CRITICAL FIX: Enhanced payload extraction with fallbacks
                        payload_content = None
                        
                        # Priority 1: HTTP body snippet (most specific)
                        if packet.get('http', {}).get('body_snippet'):
                            payload_content = packet['http']['body_snippet']
                        
                        # Priority 2: Raw payload (contains full command content)
                        elif packet.get('raw_payload'):
                            payload_content = packet['raw_payload']
                        
                        # Priority 3: Any available payload data
                        elif packet.get('http', {}).get('uri'):
                            payload_content = f"HTTP {packet.get('http', {}).get('method', 'GET')} {packet['http']['uri']}"
                        
                        if payload_content:
                            incident['payload_snippet'] = payload_content
                        
                        # Also update URI if available
                        if packet.get('http', {}).get('uri'):
                            incident['http_uri'] = packet['http']['uri']
                            
                        matched = True
                        break
                
                if not matched:
                    # Create new incident from packet
                    all_threats = packet_threats + http_threats
                    
                    # CRITICAL FIX: Enhanced payload extraction for new incidents
                    payload_content = None
                    if packet.get('http', {}).get('body_snippet'):
                        payload_content = packet['http']['body_snippet']
                    elif packet.get('raw_payload'):
                        payload_content = packet['raw_payload']
                    elif packet.get('http', {}).get('uri'):
                        payload_content = f"HTTP {packet.get('http', {}).get('method', 'GET')} {packet['http']['uri']}"
                    
                    incident = {
                        'type': 'packet_threat',
                        'source_ip': packet.get('src_ip'),
                        'target_ip': packet.get('dst_ip'),
                        'timestamp': packet.get('timestamp'),
                        'detected_threat': all_threats,
                        'http_method': packet.get('http', {}).get('method'),
                        'http_uri': packet.get('http', {}).get('uri'),
                        'payload_snippet': payload_content,  # Now properly extracted
                        'protocol': packet.get('protocol'),
                        'port': packet.get('dst_port')
                    }
                    threat_incidents.append(incident)
    
    # LOGIC FIX: For security events without matching packets, try to find ANY packet from same IP
    if state.compressed_packets.get('success') and state.compressed_packets.get('data'):
        packets_data = state.compressed_packets['data']
        packets = packets_data.get('packets', [])
        
        for incident in threat_incidents:
            # If this incident has no payload but came from security events
            if incident['type'] == 'command_execution' and not incident.get('payload_snippet'):
                # Find the most recent packet from the same source IP
                matching_packets = [p for p in packets if p.get('src_ip') == incident['source_ip']]
                if matching_packets:
                    # Sort by timestamp and get the closest one
                    matching_packets.sort(key=lambda x: abs(x.get('timestamp', 0) - incident.get('timestamp', 0)))
                    closest_packet = matching_packets[0]
                    
                    # Extract payload from closest packet
                    if closest_packet.get('raw_payload'):
                        incident['payload_snippet'] = closest_packet['raw_payload']
                    elif closest_packet.get('http', {}).get('body_snippet'):
                        incident['payload_snippet'] = closest_packet['http']['body_snippet']
    
    # Filter out incidents without payload content for verification
    threat_incidents_with_payload = []
    incidents_without_payload = []
    
    for incident in threat_incidents:
        if incident.get('payload_snippet'):
            threat_incidents_with_payload.append(incident)
        else:
            incidents_without_payload.append(incident)
    
    # Log incidents without payload for debugging
    if incidents_without_payload:
        logger.warning(f"Found {len(incidents_without_payload)} threat incidents without payload content:")
        for inc in incidents_without_payload:
            logger.warning(f"  - {inc.get('source_ip')} -> {inc.get('detected_threat')}")
    
    # Sort by timestamp for chronological analysis
    threat_incidents_with_payload.sort(key=lambda x: x.get('timestamp', 0))
    
    logger.info(f"Extracted {len(threat_incidents_with_payload)} threat incidents with payload for verification")
    return threat_incidents_with_payload

def format_threat_data_for_llm(threat_incidents: List[Dict[str, Any]]) -> str:
    """
    Format threat incidents for LLM analysis in a structured way.
    """
    if not threat_incidents:
        return "No threat incidents to analyze."
    
    formatted_data = []
    
    for i, incident in enumerate(threat_incidents, 1):
        timestamp_str = 'N/A'
        if incident.get('timestamp'):
            try:
                timestamp_str = datetime.date.fromtimestamp(incident['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                timestamp_str = str(incident.get('timestamp', 'N/A'))
        
        incident_text = f"""
INCIDENT #{i}:
- Source IP: {incident.get('source_ip', 'N/A')}
- Target IP: {incident.get('target_ip', 'N/A')}
- Timestamp: {timestamp_str}
- Detection Type: {incident.get('type', 'N/A')}
- Protocol: {incident.get('protocol', 'N/A')}
- Target Port: {incident.get('port', 'N/A')}

HTTP CONTEXT:
- Method: {incident.get('http_method', 'N/A')}
- URI: {incident.get('http_uri', 'N/A')}

DETECTED THREATS:
{json.dumps(incident.get('detected_threat', []), indent=2)}

ACTUAL PAYLOAD CONTENT:
{incident.get('payload_snippet', 'No payload captured')}

---"""
        formatted_data.append(incident_text)
    
    return "\n".join(formatted_data)

def chunk_threat_data(threat_incidents: List[Dict[str, Any]], max_chunk_size: int = 3000) -> List[List[Dict[str, Any]]]:
    """
    Split threat incidents into chunks to avoid context window limits.
    Groups by source IP and time proximity for coherent analysis.
    """
    if not threat_incidents:
        return []
    
    chunks = []
    current_chunk = []
    current_size = 0
    
    for incident in threat_incidents:
        # Estimate size (rough JSON length)
        incident_size = len(json.dumps(incident))
        
        # If adding this incident would exceed chunk size, start new chunk
        if current_size + incident_size > max_chunk_size and current_chunk:
            chunks.append(current_chunk)
            current_chunk = [incident]
            current_size = incident_size
        else:
            current_chunk.append(incident)
            current_size += incident_size
    
    # Add final chunk if not empty
    if current_chunk:
        chunks.append(current_chunk)
    
    logger.info(f"Split {len(threat_incidents)} incidents into {len(chunks)} chunks")
    return chunks

def create_threat_verification_prompt(formatted_incidents: str, chunk_info: str = "") -> str:
    
    prompt = f"""You are a cybersecurity expert analyzing network traffic for potential security threats. Your task is to verify whether the automated threat detection system correctly identified real security incidents by examining the actual network payload content. Take into account that you're in a honeypot context, so it is intended that the containers are vulnerable.
    It is desirable to estimate the level of compromise that the attacker gained on the containers (user or root access).

{chunk_info}

## YOUR ANALYSIS FRAMEWORK:

### Step 1: Payload Analysis
For each incident, examine the actual payload content and identify:
- What commands or scripts are being executed
- What attack techniques are being used
- Whether the content represents legitimate or malicious activity

### Step 2: Threat Verification  
Compare the detected threats with the actual payload content:
- Are the detected threat patterns accurate?
- Are there additional threats not detected by the system?
- Are there false positives (benign content flagged as threats)?

### Step 3: Attack Classification
Classify each verified threat using standard cybersecurity taxonomy:
- Command Injection / Code Execution
- Reverse Shell / Remote Access
- Privilege Escalation
- Data Exfiltration
- System Reconnaissance
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Other (specify)

### Step 4: Risk Assessment
Evaluate the severity and potential impact:
- CRITICAL: Active exploitation with system compromise
- HIGH: Attempted exploitation with clear malicious intent  
- MEDIUM: Suspicious activity requiring investigation
- LOW: Potentially benign but flagged activity
- FALSE POSITIVE: Legitimate activity incorrectly flagged

## INCIDENTS TO ANALYZE:

{formatted_incidents}

## YOUR RESPONSE FORMAT:

For each incident, provide:

**INCIDENT #X ANALYSIS:**
- **Payload Summary:** [Brief description of what's actually in the payload]
- **Actual Commands/Techniques:** [List the specific commands, scripts, or techniques found]
- **Threat Verification:** [CONFIRMED/PARTIAL/FALSE POSITIVE - with explanation]
- **Additional Threats Found:** [Any threats missed by automated detection]
- **Attack Classification:** [Primary attack type from taxonomy above]
- **Risk Level:** [CRITICAL/HIGH/MEDIUM/LOW/FALSE POSITIVE with justification]
- **Indicators of Compromise:** [Key artifacts that confirm malicious activity]

**OVERALL ASSESSMENT:**
- **Total Verified Threats:** [Count]
- **Detection Accuracy:** [Percentage or qualitative assessment]
- **Most Critical Findings:** [Top 2-3 most concerning verified threats]
- **Attack graph exploration:** Try to evaluate if the vulnerable honeypot container has been fully compromised or not

## IMPORTANT GUIDELINES:

1. **Be Objective:** Base your analysis only on the evidence in the payload content
2. **Consider Context:** Evaluate commands/scripts in the context they appear
3. **Look Beyond Automation:** Your expertise should catch nuances the automated system might miss
4. **Flag Uncertainty:** If payload content is unclear or incomplete, state this limitation
5. **Think Like an Attacker:** Consider what the attacker's goals and methods might be
6. **Consider Evasion:** Look for obfuscated, encoded, or disguised malicious content

Begin your analysis:"""

    return prompt

def analyze_threats_with_llm(llm, threat_incidents: List[Dict[str, Any]], chunk_info: str = "") -> str:
    """
    Send threat data to LLM for verification and analysis.
    """
    if not threat_incidents:
        return "No threat incidents to analyze."
    
    formatted_incidents = format_threat_data_for_llm(threat_incidents)
    prompt = create_threat_verification_prompt(formatted_incidents, chunk_info)
    
    try:
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        logger.error(f"Error invoking LLM for threat analysis: {e}")
        return f"Error during LLM analysis: {str(e)}"

def summarize_packets(state: HoneypotStateReact, use_chunking: bool = True, max_chunk_size: int = 3000):
    """
    Enhanced packet summarization with threat verification.
    
    Args:
        state: Current honeypot state with packet and threat data
        use_chunking: Whether to split data into chunks for large datasets
        max_chunk_size: Maximum size per chunk in characters
    """
    print("Analyzing packets and verifying detected threats...")
    
    # Extract threat data for verification
    threat_incidents = extract_threat_data_for_verification(state)
    
    if not threat_incidents:
        return {"packet_summary": "No threat detected"}
        
    # Decide whether to chunk based on data size and user preference
    if use_chunking and len(threat_incidents) > 5:  # Chunk if more than 5 incidents
        chunks = chunk_threat_data(threat_incidents, max_chunk_size)
        
        if len(chunks) == 1:
            # Small enough for single analysis
            analysis_result = analyze_threats_with_llm(llm, chunks[0])
            packet_summary = f"## THREAT VERIFICATION ANALYSIS\n\n{analysis_result}"
        else:
            # Multiple chunks - analyze each and combine
            print(f"Processing {len(chunks)} chunks for comprehensive analysis...")
            
            chunk_analyses = []
            for i, chunk in enumerate(chunks, 1):
                chunk_info = f"**CHUNK {i} of {len(chunks)}** - Analyzing incidents {i*len(chunk)-len(chunk)+1} to {i*len(chunk)}"
                print(f"Analyzing chunk {i}/{len(chunks)}...")
                
                chunk_analysis = analyze_threats_with_llm(llm, chunk, chunk_info)
                chunk_analyses.append(f"### CHUNK {i} ANALYSIS\n\n{chunk_analysis}")
            
            # Combine all chunk analyses
            combined_analysis = "\n\n".join(chunk_analyses)
            
            # Create final summary prompt
            summary_prompt = f"""Based on the following chunked threat analyses, provide a comprehensive executive summary:

{combined_analysis}

Provide a consolidated summary covering:
1. **Total Verified Threats:** Overall count and breakdown
2. **Highest Priority Threats:** Most critical findings across all chunks  
3. **Attack Patterns:** Common techniques or coordinated activities observed
4. **Honeypot evaluation:** Evaluate the probability of the attack graph explored by the attacker

Format as a clear executive summary for security decision-making."""

            try:
                summary_response = llm.invoke(summary_prompt)
                packet_summary = f"""## COMPREHENSIVE THREAT VERIFICATION ANALYSIS

### EXECUTIVE SUMMARY
{summary_response.content}

### DETAILED ANALYSIS BY CHUNK
{combined_analysis}"""
            except Exception as e:
                logger.error(f"Error creating summary: {e}")
                packet_summary = f"""## THREAT VERIFICATION ANALYSIS

**Analysis Status:** Completed with {len(chunks)} chunks
**Total Incidents:** {len(threat_incidents)}

### DETAILED ANALYSIS
{combined_analysis}"""
    else:
        # Analyze all incidents together (no chunking)
        print("Analyzing all threat incidents in single pass...")
        analysis_result = analyze_threats_with_llm(llm, threat_incidents)
        packet_summary = f"## THREAT VERIFICATION ANALYSIS\n\n{analysis_result}"
    return {"packet_summary": packet_summary}

def save_iteration_node(state: HoneypotStateReact):
    """Save the last message from current iteration to episodic memory"""
    result = save_memory_context(state)
    print(f"Memory: {result.get('message', 'Iteration save failed')}")
    return {}

def cleanup_messages(state: HoneypotStateReact):
    """Clean up ALL messages and data, keeping only essential state for next iteration"""
    print("Performing complete cleanup before ending iteration...")
    
    if state.messages:
        print("Flushing all messages and resetting state for next iteration")
        
        return {
            "messages": [],  # Flush all messages
            "packet_summary": {},  # Clear packet summary
            "network_flows": {},  # Clear network flows
            "security_events": {},  # Clear security events
            "compressed_packets": {},  # Clear compressed packets
            "firewall_config": [],  # Will be reloaded in next iteration
            "previous_iterations": [],  # Will be reloaded in next iteration
            "cleanup_flag": True
        }
    else:
        print("No messages to cleanup")
        return {}

def should_continue(state: HoneypotStateReact) -> Literal["tools", "threat_verification", "save_iteration", "cleanup", "__end__"]:
    """Determine next action based on the last message"""
    last_message = state.messages[-1]
    
    # If the last message has tool calls, execute them
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        return "tools"
    
    # Check if we need to summarize packet data
    if state.network_flows and state.security_events and state.compressed_packets and not state.packet_summary:
        return "threat_verification"

    # NEW: Before cleanup, save the iteration if we have analyzed data and final response
    if (len(state.packet_summary) > 1 and len(state.messages) > 1 and 
        not state.cleanup_flag and hasattr(last_message, 'tool_calls') and last_message.tool_calls == []):
        return "save_iteration"
    
    # After saving iteration, do cleanup
    if not state.cleanup_flag and len(state.messages) > 1:
        return "cleanup"

    return END

# Build the graph

def build_react_graph():
    builder = StateGraph(HoneypotStateReact)
    
    # Add nodes
    builder.add_node("assistant", assistant)
    builder.add_node("tools", execute_tools)
    builder.add_node("threat_verification", summarize_packets)
    builder.add_node("save_iteration", save_iteration_node)  # NEW: Save iteration node
    builder.add_node("cleanup", cleanup_messages)  # Modified cleanup
    
    # Add edges
    builder.add_edge(START, "assistant")
    builder.add_conditional_edges("assistant", should_continue)
    builder.add_edge("tools", "assistant")
    builder.add_edge("threat_verification", "assistant")
    builder.add_edge("save_iteration", "cleanup")  # NEW: Save iteration then cleanup
    builder.add_edge("cleanup", "__end__")  # Cleanup then end
        
    return builder.compile(store=episodic_memory)

# Create the graph
graph = build_react_graph()