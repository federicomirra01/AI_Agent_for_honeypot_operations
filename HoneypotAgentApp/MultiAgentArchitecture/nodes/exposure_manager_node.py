from configuration import state
from prompts import exposure_manager_prompt
from .node_utils import OPEN_AI_KEY
from openai import BadRequestError
import logging
from pydantic import BaseModel
import instructor
from openai import OpenAI
from typing import List, Dict, Any

class StructuredOutput(BaseModel):
    reasoning: str
    selected_honeypot: dict
    why_not_expose: List[Dict]
    lockdown: bool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _extract_exposure_registry(last_epochs: List[Any]) -> Dict[str, Dict[str, Any]]:
    registry = {}
    for epoch in last_epochs or []:
        data = epoch.value if hasattr(epoch, "value") else epoch
        reg = data.get("exposure_registry")
       
        if reg:
            registry.update(reg)
    return registry


async def exposure_manager(state: state.HoneypotStateReact, config):
    """
    Decides which honeypot(s) to expose next based on current attack graph
    """
    logger.info("Exploitation Agent")

    episodic_memory = config.get("configurable", {}).get("store")

    last_epochs = episodic_memory.get_recent_iterations(limit=10)
    exposure_registry = _extract_exposure_registry(last_epochs)

    prompt = exposure_manager_prompt.EXPLOITATION_PLAN_PROMPT.substitute(
        available_honeypots=state.honeypot_config,
        firewall_config=state.firewall_config,
        honeypots_exploitations=state.honeypots_exploitation,
        inferred_attack_graph=state.inferred_attack_graph,
        memory_context=state.memory_context,
        exposure_registry=exposure_registry

    )

    try:
        messages = {"role":"system", "content": prompt}
        agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
        response = agent.chat.completions.create(
            model='gpt-4.1',
            response_model=StructuredOutput,
            messages=[messages]
        )
        message = ""
        message += f"Reasoning: {str(response.reasoning)}" + "\n"
        message += f"Selected Honeypot: {str(response.selected_honeypot)}" + "\n"
        message += f"Why not expose: {str(response.why_not_expose)}" + "\n"
        message += f"Lockdown: {str(response.lockdown)}"

        return {
            "messages":state.messages + [message],
            "reasoning_exploitation": response.reasoning,
            "currently_exposed":response.selected_honeypot,
            "lockdown_status":response.lockdown
            }
    except BadRequestError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"Error during json parsing of response in Exposure Manager\n{e}")

    return {
        "messages":state.messages + [message],
        }
    
