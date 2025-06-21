from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
from langgraph.prebuilt import ToolNode
from typing import Dict, List,  Any
import logging
import os
import json
import datetime
import prompts
import tools
import state
import memory

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Create list of tools
tools = [
    tools.get_firewall_rules,
    tools.add_allow_rule,
    tools.add_block_rule,
    tools.remove_firewall_rule,
    tools.get_compressed_packets,
    tools.get_network_flows,
    tools.get_security_events,
    tools.check_services_health,
    tools.getDockerContainers
]


llm = ChatOpenAI(model="gpt-4o")
episodic_memory = memory.EpisodicMemory()

def load_memory_context(state: state.HoneypotStateReact):
    """Load memory context from episodic memory and update state"""
    
    if state.memory_context:
        return state.memory_context
    
    recent_iterations = episodic_memory.get_recent_iterations(limit=5)
    if not recent_iterations:
        logger.info("No recent iterations found in episodic memory.")
        return []
    
    print(f"Loaded {len(recent_iterations)} recent iterations from episodic memory.")
    return recent_iterations

def save_memory_context(state: state.HoneypotStateReact) -> Dict[str, Any]:
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

llm_with_tools = llm.bind_tools(tools)

def assistant(state: state.HoneypotStateReact):
    """Main assistant function that processes the conversation and calls tools"""
    
    if not state.memory_context:
        previous_iterations = load_memory_context(state)
    # Create system message with current state context
    system_message = SystemMessage(content=prompts.ASSISTANT_PROMPT)
    
    # Add context messages based on current state
    context_messages = []
    
    # Add previous iterations context
    memory_context = state.memory_context or previous_iterations if state.memory_context or previous_iterations else []
    if memory_context:
        iterations_context = "PREVIOUS ITERATIONS CONTEXT:\n"
        for i, iteration in enumerate(memory_context, 1):
            iteration = iteration.value if hasattr(iteration, 'value') else iteration
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

def execute_tools(state: state.HoneypotStateReact):
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

def extract_threat_data_for_verification(state: state.HoneypotStateReact) -> List[Dict[str, Any]]:
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

def summarize_packets(state: state.HoneypotStateReact, use_chunking: bool = True, max_chunk_size: int = 3000):
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

def save_iteration_node(state: state.HoneypotStateReact):
    """Save the last message from current iteration to episodic memory"""
    result = save_memory_context(state)
    print(f"Memory: {result.get('message', 'Iteration save failed')}")
    return {"memory_context": result.get("memory_context", "")}


def tool_list():
    return tools

