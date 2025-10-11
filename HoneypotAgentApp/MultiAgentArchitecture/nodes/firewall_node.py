from langchain_core.messages import AIMessage
from configuration import state
from prompts import firewall_executor_prompt
from .node_utils import OPEN_AI_KEY, BOFFA_KEY, OPENROUTER_URL, DEEPSEEK_STRING
from tools import firewall_tools
import logging
from pydantic import BaseModel, Field, ValidationError
from typing import Union, List
import instructor
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AddAllowRule(BaseModel):
    """Model for adding an allow rule to the firewall."""
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    #port: Optional[int] = Field(None, description="Port Number (optional)")
    protocol: str = Field("tcp", description="Protocol (default: tcp)")

class AddBlockRule(BaseModel):
    """Model for adding a block rule to the firewall."""
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    #port: Optional[int] = Field(None, description="Port Number (optional)")
    protocol: str = Field("tcp", description="Protocol (default: tcp)")

class RemoveFirewallRule(BaseModel):
    rule_numbers: List[int] = Field(..., description="List of firewall rule numbers to remove")

class StructuredOutput(BaseModel):
    reasoning: str = ""
    action: List[Union[AddAllowRule, AddBlockRule, RemoveFirewallRule]] = []

ACTION_PRIORITY = {
    RemoveFirewallRule: 0,
    AddAllowRule: 1,
    AddBlockRule: 2
}


async def firewall_executor(state:state.HoneypotStateReact, config):
    logger.info("Firewall Agent")
    configuration = config.get("configurable", {}).get("model_config", "large:4.1")
    size, version = configuration.split(':')
    if size == "small":
        model_name = f"gpt-{version}-mini"
    else:
        model_name = f"gpt-{version}"

    logger.info(f"Using: {model_name}")

    prompt = firewall_executor_prompt.FIREWALL_EXECUTOR_PROMPT.format(
        selected_honeypot=state.currently_exposed,
        firewall_config=state.firewall_config,
        available_honeypots=state.honeypot_config
    )
    messages = {"role":"system", "content":prompt}
    try:
        response = StructuredOutput()
        if version == '5':
            valid_json = False
            while(not valid_json):
                logger.info(f"Using gpt5 minimal effort")
                schema = StructuredOutput.model_json_schema()
                client = OpenAI()
                raw = client.responses.create( # type: ignore
                    model="gpt-5",
                    input=f"{prompt}\n\nReturn valid JSON matching this schema:\n{schema}",
                    reasoning={"effort":"minimal"},
                    
                )
                content = raw.output_text
                try:
                    response = StructuredOutput.model_validate_json(content)
                    valid_json = True
                except ValidationError as e:
                    logger.error(f"Schema validation failed: \n{e}")
                    response = StructuredOutput()
        elif version == "4.1":
            agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
            response: StructuredOutput = agent.chat.completions.create(
                model=model_name,
                response_model=StructuredOutput,
                temperature=0.6,
                messages=[messages] # type: ignore
            )
        
        else:
            logger.info(f"Using OpenRouter model")
        
            client = instructor.from_openai(OpenAI(api_key=BOFFA_KEY, base_url=OPENROUTER_URL))
            response = client.chat.completions.create(
                model=DEEPSEEK_STRING,
                response_model=StructuredOutput,
                extra_body={"provider": {"require_parameters": True}},
                messages=messages #type: ignore
            )
        message = f"Reasoning:" + str(response.reasoning)
        message += f"\nAction: {str(response.action)}"
        message = AIMessage(content=message)

        return {"messages": [message], "firewall_resoning":response.reasoning, "firewall_action": response.action}

    except Exception as e:
        logger.error(f"Error splitting reasoning in firewall executor:\n{e}")
    

async def tools_firewall(state: state.HoneypotStateReact):
    """Execute pending tool calls and update state with enhanced threat data handling"""
    agent_output = state.firewall_action

    agent_output_sorted = sorted(
        agent_output,
        key=lambda action : ACTION_PRIORITY.get(type(action), 99)
    )

    rules_added = []
    rules_removed = []
    new_state = {}
    try:
        if agent_output_sorted:
    
            for action in agent_output_sorted:
                if isinstance(action, AddAllowRule):
                    resp = await firewall_tools.add_allow_rule(
                        source_ip=action.source_ip,
                        dest_ip=action.dest_ip,
                        #port=action.port,
                        protocol=action.protocol
                    )
                    rules_added.append(resp)
                    
                elif isinstance(action, AddBlockRule):
                    resp = await firewall_tools.add_block_rule(
                        source_ip=action.source_ip,
                        dest_ip=action.dest_ip,
                        #port=action.port,
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

