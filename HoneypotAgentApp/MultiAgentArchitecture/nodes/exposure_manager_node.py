from langchain_core.messages import AIMessage
from configuration import state
from prompts import exposure_manager_prompt
from .node_utils import OPEN_AI_KEY, BOFFA_KEY, OPENROUTER_URL, DEEPSEEK_STRING
from openai import BadRequestError
import logging
from pydantic import BaseModel, ValidationError
import instructor
from openai import OpenAI
from typing import List, Dict, Any

class StructuredOutput(BaseModel):
    reasoning: str 
    selected_honeypot: dict
    lockdown: bool = False

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
    model_config = config.get("configurable", {}).get("model_config", "large:4.1")

    last_epochs = episodic_memory.get_recent_iterations(limit=20)
    exposure_registry = _extract_exposure_registry(last_epochs)
    logger.info(f"Exposure registry: {exposure_registry}")
    prompt = exposure_manager_prompt.EXPLOITATION_PLAN_PROMPT.substitute(
        available_honeypots=state.honeypot_config,
        honeypots_exploitations=state.honeypots_exploitation,
        exposure_registry=exposure_registry

    )
    size, version = model_config.split(':')
  
    model_name = f"gpt-{version}" if "4.1" in model_config or "5" in model_config else "deepseek"
    logger.info(f"Using: {model_name}")
    message = ""
    try:
        response = StructuredOutput(reasoning="", selected_honeypot={})
        messages = [
            {"role":"system", "content": prompt},
        ]
        if version == '5':
            valid_json = False
            while(not valid_json):
                logger.info(f"Using gpt5 low effort")
                schema = StructuredOutput.model_json_schema()
                client = OpenAI()
                raw = client.responses.create( # type: ignore
                    model="gpt-5",
                    input=f"{prompt}\n\nReturn valid JSON matching this schema:\n{schema}",
                    reasoning={"effort":"low"},
                    
                )
                content = raw.output_text
                try:
                    response = StructuredOutput.model_validate_json(content)
                    valid_json = True
                except ValidationError as e:
                    logger.error(f"Schema validation failed: \n{e}")
                    response = StructuredOutput(reasoning="", selected_honeypot={})
        elif version == '4.1':
            agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
            response: StructuredOutput = agent.chat.completions.create(
                model=model_name,
                response_model=StructuredOutput,
                temperature=0.3,
                messages=messages # type: ignore
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
        
        message += f"Reasoning: {str(response.reasoning)}" + "\n"
        message += f"Selected Honeypot: {str(response.selected_honeypot)}" + "\n"
        message += f"Lockdown: {str(response.lockdown)}"
        message = AIMessage(content=message)
        return {
            "messages": [message],
            "reasoning_exploitation": response.reasoning,
            "currently_exposed":response.selected_honeypot,
            "lockdown_status":response.lockdown
            }
    except BadRequestError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"Error during json parsing of response in Exposure Manager\n{e}")

    return {
        "messages": [message],
        }
    
