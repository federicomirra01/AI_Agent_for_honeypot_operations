import state
from typing import Dict,  Any
from prompts import eve_summary_prompt, fast_summary_prompt
from .node_utils import OPEN_AI_KEY
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

async def event_summarizer(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    """
    Output security events summary regarding the honeypot's network activity.
    """
    logger.info("Summarizer Agent")
    configuration = config.get("configurable", {}).get("prompt", "Default")
    # Initialize the prompt from configuration: eve.json or fast.log analysis
    if "fast" in configuration:
        prompt = fast_summary_prompt.SUMMARY_PROMPT_FAST.format(
            security_events=state.security_events,
            honeypot_config=state.honeypot_config
            )
    else:
        prompt = eve_summary_prompt.SUMMARY_PROMPT_EVE.format(
            security_events=state.security_events,
            honeypot_config=state.honeypot_config
        )
    messages = {"role":"system", "content": prompt}

    try:
        agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
        response = agent.chat.completions.create(
            model='gpt-4.1',
            response_model=StructuredOutput,
            messages=[messages]
        )
        message = ""
        message += str(response.security_summary)

        return {
        "messages": [message],
        "security_events_summary": response.security_summary
        }


    except BadRequestError as e:
        logger.error(f"Error in calling Summarizer Agent: {e}")
        return {
            "messages": state.messages
            }
