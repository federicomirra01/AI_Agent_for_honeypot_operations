from langchain_core.messages import AIMessage
from configuration import state
from typing import Dict, Any, List
from prompts import eve_summary_prompt, fast_summary_prompt
from .node_utils import OPEN_AI_KEY, POLITO_CLUSTER_KEY, POLITO_URL, DEEPSEEK_STRING 
from openai import BadRequestError 
import logging
from pydantic import BaseModel
import instructor
from openai import OpenAI

class StructuredOutput(BaseModel):
    security_summary: str 


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _build_prompt(configuration: str, state: state.HoneypotStateReact, last_summary: str, last_exposed: dict) -> str:
    if "fast" in configuration:
        return fast_summary_prompt.SUMMARY_PROMPT_FAST.substitute(
            security_events=state.security_events,
            honeypot_config=state.honeypot_config,
            last_summary=last_summary,
            last_exposed=last_exposed
            )
    else:
        return eve_summary_prompt.SUMMARIZER_PROMPT.substitute(
            last_summary=last_summary,
            last_exposed=last_exposed,
            security_events=state.security_events,
            honeypot_config=state.honeypot_config
        )

def _build_model_config(model_config: str):

    version = model_config.split(':')[1]
    if "small" in model_config:
        model_name = f"gpt-{version}-mini"
    else:
        model_name = f"gpt-{version}"
    return model_name, version

def _build_response(model_name: str, version: str, prompt: str, messages: List[Dict]) -> StructuredOutput:
    response = StructuredOutput(security_summary="")
    if version == '5':
        logger.info(f"Using gpt5 minimal effort")
        client = OpenAI()
        raw = client.responses.create( 
            model=model_name,
            temperature=0.3,
            input=messages,  # type: ignore
            reasoning={"effort":"minimal"},
            
        )
        response = StructuredOutput.model_validate_json(raw.output_text)
    elif version == '4.1':
        logger.info(f"Using {model_name}")
        agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
        response: StructuredOutput = agent.chat.completions.create(
            model=model_name,
            response_model=StructuredOutput,
            temperature=0.3,
            messages=messages # type: ignore
        )
    
   
    return response

async def event_summarizer(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    """
    Output security events summary regarding the honeypot's network activity.
    """
    logger.info("Summarizer Agent")
    configuration = config.get("configurable", {}).get("prompt", "Default")
    model_config = config.get("configurable", {}).get("model_config", "small:4.1")
    memory = config.get("configurable", {}).get("store")
    last_iteration = memory.get_recent_iterations(limit=1)
    last_summary = ""
    last_exposed = {}
    if last_iteration:
        last_summary = last_iteration[0].value.get("security_events_summary", "")
        last_exposed = last_iteration[0].value.get("currently_exposed", {})
    # Initialize the prompt from configuration: eve.json or fast.log analysis
    prompt = _build_prompt(configuration, state, last_summary, last_exposed)


    messages = [
        # {"role":"system", "content": eve_summary_prompt.SYSTEM_PROMPT},
        {"role" : "system", "content" : eve_summary_prompt.SUMMARIZER_PROMPT.substitute(
            last_summary=last_summary,
            last_exposed=last_exposed,
            security_events=state.security_events,
            honeypot_config=state.honeypot_config
            )
        }
    ]
    
    model_name, version = _build_model_config(model_config)

    if state.security_events and len(state.security_events.get('alerts', [])) > 0:    
        response = StructuredOutput(security_summary="")
        try:
            
            response = _build_response(model_name=model_name, version=version, prompt=prompt, messages=messages)
            
            message = ""
            message += "Security Summary: " + str(response.security_summary) + "\n" if version == '4.1' else str(response)

            return {
            "messages": [message],
            "security_events_summary": response.security_summary if version == '4.1' else response
            }

        except BadRequestError as e:
            logger.error(f"Error in calling Summarizer Agent: {e}")
            return {
                "messages": state.messages
                }
    else:
        return {
            "messages": AIMessage(content="No alerts retrieved"),
            "security_events_summary": "No alerts retrieved"
        }
