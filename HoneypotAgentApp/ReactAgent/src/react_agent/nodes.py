from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
from langgraph.prebuilt import ToolNode
from typing import Dict, List,  Any
import logging
import os
import json
from . import prompts
from . import tools
from . import state

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Create list of tools
tools = [
    tools.get_firewall_rules,
    #add_allow_rule,
    #add_block_rule,
    #remove_firewall_rule,
    tools.get_packets,
    tools.check_services_health,
    tools.getDockerContainers
]


llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools(tools)

def assistant(state: state.HoneypotStateReact):
    """Main assistant function that processes the conversation and calls tools"""
    # Create system message with current state context
    print(f"network packets: {state.network_packets}\nfirewall_rules: {state.firewall_config}\nhoneypot_config{state.honeypot_config}\nservices_health: {[state.firewall_status, state.monitor_status]}")
    system_message = SystemMessage(content=prompts.SYSTEM_PROMPT_GPT_REACT_ONLY_RULES_v0)

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


def execute_tools(state: state.HoneypotStateReact):
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
        


def summarize_packets(state: state.HoneypotStateReact):
    """Analyze and summarize packet data from tool results"""
    print("Summarizing packet data...")
    
    if state.network_packets:
        # Create summary using LLM
        summary_response = llm.invoke(
            prompts.SUMMARIZE_PROMPT.format(packets=json.dumps(state.network_packets, indent=2))
        )
        packet_summary = summary_response.content
    else:
        packet_summary = "No packet data available for analysis."
        print("No packet data found for summarization")
    
    return {"packet_summary": packet_summary}


def tool_list():
    return tools

