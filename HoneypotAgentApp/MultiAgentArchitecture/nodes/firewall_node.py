import state
from .node_utils import llm_firewall
from openai import BadRequestError
from langgraph.prebuilt import ToolNode
from prompts import firewall_executor_prompt
from .node_utils import fw_tools
import json
from dotenv import load_dotenv
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

async def firewall_executor(state:state.HoneypotStateReact):
    logger.info("Firewall Agent")
    prompt = firewall_executor_prompt.FIREWALL_EXECUTOR_PROMPT.format(
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
        tool_node = ToolNode(fw_tools)
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

