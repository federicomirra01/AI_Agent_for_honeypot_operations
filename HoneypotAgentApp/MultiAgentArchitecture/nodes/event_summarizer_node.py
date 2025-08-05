import state
from typing import Dict,  Any
from prompts import eve_summary_prompt, fast_summary_prompt
from .node_utils import llm
from openai import BadRequestError 
import os 
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def event_summarizer(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    """
    Output security events summary regarding the honeypot's network activity.
    """
    logger.info("Summarizer Agent")
    configuration = config.get("configurable", {}).get("prompt", "Default")
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
    try:
        response = await llm.ainvoke(prompt)
    except BadRequestError as e:
        logger.error(f"Error in calling Summarizer Agent: {e}")
    return {
        "messages": [response],
        "security_events_summary": response.content
        }
