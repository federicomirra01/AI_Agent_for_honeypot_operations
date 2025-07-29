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
    tools.get_fast_alerts,
    #tools.check_services_health,
    tools.get_docker_containers,
    tools.save_iteration_summary
]


llm = ChatOpenAI(model="gpt-4.1")

def load_memory_context(state: state.HoneypotStateReact, episodic_memory):
    """Load memory context from episodic memory and update state"""
    
    if state.memory_context:
        return state.memory_context
    
    recent_iterations = episodic_memory.get_recent_iterations(limit=10)
    if not recent_iterations:
        return []
    
    print(f"Loaded {len(recent_iterations)} recent iterations from episodic memory.")
    return recent_iterations

llm_with_tools = llm.bind_tools(tools)

def assistant(state: state.HoneypotStateReact, config):
    """Main assistant function that processes the conversation and calls tools"""
    episodic_memory = config.get("configurable", {}).get("store")
    prompt_type = config.get("configurable", {}).get("promptAssistant", "Default")
    if "AttackGraphInference" in prompt_type:
        prompt = prompts.ASSISTANT_PROMPT_RQ1
        logger.info("Using Attack Graph Inference prompt")
    else:
        prompt = prompts.ASSISTANT_PROMPT
        logger.info("Using default assistant prompt")
    if not state.memory_context:
        previous_iterations = load_memory_context(state, episodic_memory)
    # Create system message with current state context
    system_message = SystemMessage(content=prompt)
    
    # Add context messages based on current state
    context_messages = []
    # Add previous iterations context
    memory_context = state.memory_context or previous_iterations if state.memory_context or previous_iterations else []
    if memory_context:
        iterations_context = "PREVIOUS ITERATIONS CONTEXT:\n"
        for i, iteration in enumerate(memory_context, 1):
            iteration = iteration.value if hasattr(iteration, 'value') else iteration
            iterations_context += f"\n--- {iteration}\n"
        context_messages.append(HumanMessage(content=iterations_context))
    # Add security events summary context if available (this contains threat verification analysis)
    if len(state.security_events_summary) > 1:
        context_messages.append(
            HumanMessage(content=f"SECURITY EVENTS ANALYSIS RESULTS:\n{state.security_events_summary}")
        )
    else:
        context_messages.append(
            HumanMessage(content=f"THREAT ANALYSIS from SECURITY EVENTS SUMMARY not available yet, DO NOT PRODUCE ITERATION SUMMARY\n")
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
    rules_added = []
    rules_removed = []
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        tool_node = ToolNode(tools)
        tool_responses = tool_node.invoke({"messages": [last_message]})
        new_state = {
            "messages": state.messages + tool_responses["messages"]
        }

        for tool_message in tool_responses["messages"]:
            try:
                result = json.loads(tool_message.content)
                
               
                if tool_message.name == 'get_fast_alerts':
                    new_state["security_events"] = result.get('security_events', {})

                elif tool_message.name == 'get_docker_containers':
                    new_state["honeypot_config"] = result.get('honeypot_config', [])

                elif tool_message.name == 'get_firewall_rules':
                    new_state["firewall_config"] = result.get('firewall_config', [])

                elif tool_message.name == 'check_services_health':
                    new_state["firewall_status"] = result.get('firewall_status', '')
                    new_state["monitor_status"] = result.get('monitor_status', '')
                
                elif tool_message.name == 'add_allow_rule':
                    rules_added.append(result.get('rules_added_current_epoch', []))
                    new_state["rules_added_current_epoch"] = rules_added
                elif tool_message.name == 'add_block_rule':
                    rules_added.append(result.get('rules_added_current_epoch', []))
                    new_state["rules_added_current_epoch"] = rules_added
                elif tool_message.name == 'remove_firewall_rule':
                    rules_removed.append(result.get('rules_removed_current_epoch', []))
                    new_state["rules_removed_current_epoch"] = rules_removed
                elif tool_message.name == 'save_iteration_summary':
                    new_state["currently_exposed"] = result.get('currently_exposed', [])
                    new_state["honeypots_exploitation"] = result.get('honeypots_exploitation', [])
                    new_state["decision_rationale"] = result.get('decision_rationale', [])
                    new_state["lockdown_status"] = result.get('lockdown_status', [])
                    new_state["evidence_summary"] = result.get('evidence_summary', [])
                    new_state["justification"] = result.get('justification', [])
                    new_state["next_iteration_guidance"] = result.get('next_iteration_guidance', [])
                    new_state["inferred_attack_graph"] = result.get('inferred_attack_graph', {})

            except Exception as e:
                logger.error(f"Error processing tool response: {e}\nTool: {tool_message.name}\nContent: {tool_message.content[:200]}...")
                
        return new_state
    
    return {"messages": state.messages}

def summarize_security_events(state: state.HoneypotStateReact) -> Dict[str, Any]:
    """
    Output security events summary regarding the honeypot's network activity.

    Args:
        state: Current honeypot state with all relevant data
    
    Returns:
        Dict with security events summary information
    """

    prompt = prompts.SUMMARY_PROMPT_FAST + "\n" + "IDS data: \n" + json.dumps(state.security_events, indent=1) + "\n"

    response = llm.invoke(prompt)
    security_events_summary = f"## SECURITY EVENTS SUMMARY:\n{response.content}"

    return {"security_events_summary": security_events_summary}

def save_iteration(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    """
    Save iteration summary with structured data for benchmark metrics collection.
    
    Args:
        state: Current honeypot state with all relevant data
        config: Configuration dictionary with episodic memory store
    
    Returns:
        Dict with success status and iteration info
    """
    iteration_data = {
        "currently_exposed": state.currently_exposed,
        "rules_added": state.rules_added_current_epoch if state.rules_added_current_epoch else [],
        "honeypots_exploitation": state.honeypots_exploitation,
        "decision_rationale": state.decision_rationale,
        "lockdown_status": state.lockdown_status,
        "rules_removed": state.rules_removed_current_epoch if state.rules_removed_current_epoch else [],
        "inferred_attack_graph": state.inferred_attack_graph,

        "evidence_summary": state.evidence_summary,
        "justification": state.justification,
        "next_iteration_guidance": state.next_iteration_guidance,
    }
    episodic_memory = config.get("configurable", {}).get("store")
    # Save to episodic memory
    iteration_id = episodic_memory.save_iteration(iteration_data)
    total_iterations = episodic_memory.get_iteration_count()

    logger.info(f"Iteration saved with ID {iteration_id}. Total iterations: {total_iterations}")
    
    return {
        "success": True,
        "iteration_id": iteration_id,
        "total_iterations": total_iterations,
    }


def tool_list():
    return tools

