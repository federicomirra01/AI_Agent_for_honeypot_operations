from tools import get_firewall_stats, get_firewall_rules, add_allow_rule, add_block_rule, remove_firewall_rule, get_packets, get_recent_packets, get_packet_stats, get_traffic_flows, check_services_health, getDockerContainers
from state import HoneypotStateReact
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from prompts import SYSTEM_PROMPT_GPT_REACT_ONLY_RULES, SUMMARIZE_PROMPT
import json
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
import os


# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

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


llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools(tools)

def assistant(state: HoneypotStateReact):
    """Main assistant function that processes the conversation and calls tools"""
    # Create system message with current state context
    system_message = SystemMessage(content=SYSTEM_PROMPT_GPT_REACT_ONLY_RULES)
    
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

def tool_list():
    return tools