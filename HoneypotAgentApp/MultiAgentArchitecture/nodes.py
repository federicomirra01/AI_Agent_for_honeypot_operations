from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
from langgraph.prebuilt import ToolNode
from typing import Dict,  Any
import logging
import os
import json
import prompts
import tools
import state
from openai import BadRequestError 


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv('../.env')
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")


supervisor_tools = [
    tools.get_fast_alerts,
    tools.get_docker_containers,
    tools.get_firewall_rules,
]

firewall_tools = [
    tools.add_allow_rule,
    tools.add_block_rule,
    tools.remove_firewall_rule
]

llm = ChatOpenAI(model="gpt-4.1")
llm_firewall = llm.bind_tools(firewall_tools)
llm_supervisor = llm.bind_tools(supervisor_tools)

def load_memory_context(state: state.HoneypotStateReact, episodic_memory):
    """Load memory context from episodic memory and update state"""
    
    if state.memory_context:
        return state.memory_context
    
    recent_iterations = episodic_memory.get_recent_iterations(limit=10)
    if not recent_iterations:
        return []
    
    print(f"Loaded {len(recent_iterations)} recent iterations from episodic memory.")
    return recent_iterations


async def network_gathering(state: state.HoneypotStateReact) -> Dict[str, Any]:
    logger.info("Network gathering Node")
    """
    Network Gathering Node:
    Fetch IDS alerts, Docker containers, and firewall rules.
    """
    # Call tools directly
    alerts_response = await tools.get_fast_alerts()
    containers_response = tools.get_docker_containers()
    firewall_response = await tools.get_firewall_rules()
    
    # Parse results (assuming each tool returns a dict with the right keys)
    # You may need to adapt keys based on your actual tool output!
    security_events = alerts_response.get('security_events', {})
    honeypot_config = containers_response.get('honeypot_config', {})
    firewall_config = firewall_response.get('firewall_config', {})
    
    # Update state
    return {
        "security_events": security_events,
        "honeypot_config": honeypot_config,
        "firewall_config": firewall_config,
    }

async def memory_summarizer(state, config, window=5):
    logger.info("Memory Agent")
    episodic_memory = config.get("configurable", {}).get("store")
    last_epochs = episodic_memory.get_recent_iterations(limit=window)
    summary_prompt = prompts.MEMORY_SUMMARIZER_PROMPT.format(
        episodic_memory=last_epochs
    )
    summary_response = await llm.ainvoke(summary_prompt)
    return {"memory_context": summary_response.content}

async def event_summarizer(state: state.HoneypotStateReact) -> Dict[str, Any]:
    """
    Output security events summary regarding the honeypot's network activity.
    """
    logger.info("Summarizer Agent")
    prompt = prompts.SUMMARY_PROMPT_FAST.format(security_events=state.security_events)
    try:
        response = await llm.ainvoke(prompt)
    except BadRequestError as e:
        logger.error(f"Error in calling Summarizer Agent: {e}")
    return {"security_events_summary": response.content}

async def attack_graph_inference(state: state.HoneypotStateReact):
    """
    Infers/Update the attack graph from event summaries
    """
    logger.info("Inference Agent")
       
    prompt = prompts.ATTACK_GRAPH_INFERENCE_PROMPT.format(
        security_events_summary=state.security_events_summary,
        available_honeypots=state.honeypot_config,
        memory_context=state.memory_context
        ) 
    
    try:
        response = await llm.ainvoke(prompt)
        content = response.content
        substring = content.split("Attack Graph:")
        substring = substring[1] if len(substring) > 1 else substring
        inferred_attack_graph, substring1 = substring.split("Honeypots exploitation:")
        honeypot_exploitation, reasoning = substring1.split("Reasoning:")
        inferred_attack_graph = json.loads(inferred_attack_graph)
        honeypot_exploitation = json.loads(honeypot_exploitation)
        return {
            "messages": state.messages + [response],
            "inferred_attack_graph":inferred_attack_graph, 
            "reasoning_inference":reasoning, 
            "honeypots_exploitation":honeypot_exploitation
            }
    except BadRequestError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"Error parsing json in attack graph inference:\n{e}")
    return {
        "messages":state.messages + [response],
        "inferred_attack_graph":f"Inferred graph\n{response.content}",
        }

async def exploitation_manager(state: state.HoneypotStateReact):
    """
    Decides which honeypot(s) to expose next based on current attack graph
    """
    logger.info("Exploitation Agent")
    
    prompt = prompts.EXPLOITATION_MANAGER_PROMPT.format(
        available_honeypots=state.honeypot_config,
        firewall_config=state.firewall_config,
        honeypots_exploitations=state.honeypots_exploitation,
        memory_context=state.memory_context
    )
    
    try:
        response = await llm.ainvoke(prompt) 
        content = response.content
        substring = content.split("Plan:")
        substring = substring[1] if len(substring) > 1 else substring
        plan, substring1 = substring.split("Reasoning:")
        reasoning, substring2 = substring1.split("Exposed Honeypots:")
        currently_exposed, lockdown = substring2.split("Lockdown:")
        plan = json.loads(plan)
        currently_exposed = json.loads(currently_exposed)
        lockdown = "ACTIVE" if "true" in lockdown.lower() else "INACTIVE"
        return {
            "messages":state.messages + [response],
            "exploitation_strategy": plan,
            "reasoning_exploitation": [reasoning],
            "currently_exposed":currently_exposed,
            "lockdown_status":lockdown
            }
    except BadRequestError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"Error during json parsing of response in Exploitation Manager\n{e}")

    return {
        "messages":state.messages + [response],
        "exploitation_strategy": f"Exploitation Strategy\n{response.content}",
        "reasoning_exploitation": f"{response.content}"
        }
    

async def firewall_executor(state:state.HoneypotStateReact):
    logger.info("Firewall Agent")
    prompt = prompts.FIREWALL_EXECUTOR_PROMPT.format(
        exposure_plan=state.exploitation_strategy,
        firewall_config=state.firewall_config,
        available_honeypots=state.honeypot_config
    )
    
    try:
        response = await llm_firewall.ainvoke(prompt)
        content = response.content
        substring = content.split('Reasoning:')
        reasoning = substring[1] if len(substring)> 0 else substring
        return {
            "messages":state.messages + [response],
            "firewall_reasoning":reasoning 
        }
    except BadRequestError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"Error splitting reasoning in firewall executor:\n{e}")
    return {"messages":state.messages + [response]}



async def tools_firewall(state: state.HoneypotStateReact):
    """Execute pending tool calls and update state with enhanced threat data handling"""
    
    # Get the last message 
    last_message = state.messages[-1]
    rules_added = []
    rules_removed = []
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        tool_node = ToolNode(firewall_tools)
        tool_responses = await tool_node.ainvoke({"messages": [last_message]})
        new_state = {
            "messages": state.messages + tool_responses["messages"]
        }
        

        for tool_message in tool_responses["messages"]:
            try:
                result = json.loads(tool_message.content)
                
                if tool_message.name == 'add_allow_rule':
                    rules_added.append(result.get('rules_added_current_epoch', []))
                    new_state["rules_added_current_epoch"] = rules_added
                elif tool_message.name == 'add_block_rule':
                    rules_added.append(result.get('rules_added_current_epoch', []))
                    new_state["rules_added_current_epoch"] = rules_added
                elif tool_message.name == 'remove_firewall_rule':
                    rules_removed.append(result.get('rules_removed_current_epoch', []))
                    new_state["rules_removed_current_epoch"] = rules_removed
            except Exception as e:
                logger.error(f"Error processing tool response: {e}\nTool: {tool_message.name}\nContent: {tool_message.content[:200]}...")
                
        return new_state
    
    return {"messages": state.messages}



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
        **state
        # "currently_exposed": state.currently_exposed,
        # "rules_added": state.rules_added_current_epoch if state.rules_added_current_epoch else [],
        # "honeypots_exploitation": state.honeypots_exploitation,
        # "lockdown_status": state.lockdown_status,
        # "rules_removed": state.rules_removed_current_epoch if state.rules_removed_current_epoch else [],
        # "firewall_reasoning": state.firewall_reasoning,
        # "inferred_attack_graph": state.inferred_attack_graph,
        # "reasoning_inference": state.reasoning_inference,
        # "reasoning_exploitation":state.reasoning_exploitation
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



