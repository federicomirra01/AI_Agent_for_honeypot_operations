import state
from .node_utils import llm_firewall
from openai import BadRequestError
from langgraph.prebuilt import ToolNode
from prompts import firewall_executor_prompt
from .node_utils import fw_tools, OPEN_AI_KEY
from tools import firewall_tools
import json
import logging
from pydantic import BaseModel, Field
from typing import Optional, Union, List
import instructor
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AddAllowRule(BaseModel):
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    port: Optional[int] = Field(None, description="Port Number (optional)")
    protocol: Optional[int] = Field("tcp", description="Protocol (default: tcp)")

class AddBlockRule(BaseModel):
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    port: Optional[int] = Field(None, description="Port Number (optional)")
    protocol: Optional[int] = Field("tcp", description="Protocol (default: tcp)")

class RemoveFirewallRule(BaseModel):
    rule_numbers: List[int] = Field(..., description="List of firewall rule numbers to remove")

class StructuredOutput(BaseModel):
    reasoning: str
    action: List[Union[AddAllowRule, AddBlockRule, RemoveFirewallRule]] = []


tools = [AddAllowRule, AddBlockRule, RemoveFirewallRule]

async def firewall_executor(state:state.HoneypotStateReact):
    logger.info("Firewall Agent")
    prompt = firewall_executor_prompt.FIREWALL_EXECUTOR_PROMPT.format(
        exposure_plan=state.exploitation_strategy,
        firewall_config=state.firewall_config,
        available_honeypots=state.honeypot_config
    )
    messages = {"role":"system", "content":prompt}
    try:
        agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
        response = agent.chat.completions.create(
            model='gpt-4.1',
            response_model=StructuredOutput,
            messages=[messages]
        )

        return {"firewall_resoning":response.reasoning, "firewall_action": response.action}

    except Exception as e:
        logger.error(f"Error splitting reasoning in firewall executor:\n{e}")
    



async def tools_firewall(state: state.HoneypotStateReact):
    """Execute pending tool calls and update state with enhanced threat data handling"""
    agent_output = state.firewall_action
    logger.info(f"Tools handler: {agent_output}")

    rules_added = []
    rules_removed = []
    new_state = {}
    try:
        if agent_output:
    
            for action in agent_output:
                if isinstance(action, AddAllowRule):
                    resp = await firewall_tools.add_allow_rule(
                        source_ip=action.source_ip,
                        dest_ip=action.dest_ip,
                        port=action.port,
                        protocol=action.protocol
                    )
                    rules_added.append(resp)
                    
                elif isinstance(action, AddBlockRule):
                    resp = await firewall_tools.add_block_rule(
                        source_ip=action.source_ip,
                        dest_ip=action.dest_ip,
                        port=action.port,
                        protocol=action.protocol
                    )
                    rules_added.append(resp)
                
                elif isinstance(action, RemoveFirewallRule):
                    resp = await firewall_tools.remove_firewall_rule(
                        rule_numbers=action.rule_numbers
                    )
                    rules_removed.append(resp)
            new_state["rules_added_current_epoch"] = rules_added
            new_state["rules_removed_current_epoch"] = rules_removed
    except Exception as e:
        logger.error(f"Exception in tools handling: {e}") 

    return new_state

