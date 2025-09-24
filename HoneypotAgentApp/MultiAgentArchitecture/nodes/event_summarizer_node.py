from langchain_core.messages import AIMessage
from configuration import state
from typing import Dict, Any, List
from prompts import eve_summary_prompt, fast_summary_prompt
from .node_utils import OPEN_AI_KEY, POLITO_CLUSTER_KEY, POLITO_URL, MISTRAL_STRING
from openai import BadRequestError 
import logging
from pydantic import BaseModel
import instructor
from openai import OpenAI

class StructuredOutput(BaseModel):
    security_summary: str = ""

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
        return eve_summary_prompt.SUMMARY_PROMPT_EVE.substitute(
            last_summary=last_summary,
            last_exposed=last_exposed,
            security_events=state.security_events,
            honeypot_config=state.honeypot_config
        )

def _build_model_config(model_config: str):
    if "mistral" in model_config:

        model_name = MISTRAL_STRING
        version = '0.1'
    
    else:
        version = model_config.split(':')[1]
        if "small" in model_config:
            model_name = f"gpt-{version}-mini"
        else:
            model_name = f"gpt-{version}"
    return model_name, version

def _build_response(model_name: str, version: str, prompt: str, messages: List[Dict], prompt_data: dict = {}) -> StructuredOutput:
    response = StructuredOutput()
    if version == '5':
        logger.info(f"Using gpt5 minimal effort")
        schema = StructuredOutput.model_json_schema()
        client = OpenAI()
        raw = client.responses.create( # type: ignore
            model=model_name,
            input=f"{prompt}\n\nReturn valid JSON matching this schema:\n{schema}",
            reasoning={"effort":"minimal"},
            
        )
        response.security_summary = raw.output_text
    elif version == '4.1':
        logger.info(f"Using {model_name}")
        agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
        response: StructuredOutput = agent.chat.completions.create(
            model=model_name,
            response_model=StructuredOutput,
            messages=messages # type: ignore
        )
    
    else:
        logger.info(f"Using Mistral model")
        messages = [
            {"role" : "system", "content" : eve_summary_prompt.EVE_SUMMARY_PROMPT_MISTRAL},
            {"role" : "user", "content" : f"Input Data:\
                \nSecurity Events: {prompt_data["state"].security_events}\
                \nHoneypot Config: {prompt_data["state"].honeypot_config}\
                \nLast Summary: {prompt_data["last_summary"]}\
                \nLast Exposed: {prompt_data["last_exposed"]}"}
        ]
        client = OpenAI(api_key=POLITO_CLUSTER_KEY, base_url=POLITO_URL)
        raw = client.chat.completions.create(
            model=model_name,
            messages=messages #type: ignore
        )
        response.security_summary = str(raw.choices[0].message.content)
    
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
        {"role":"system", "content": prompt},
        {"role":"user", "content": "Summarize the security events clearly and concisely"}
    ]
    
    model_name, version = _build_model_config(model_config)

    if state.security_events and len(state.security_events.get('alerts', [])) > 0:    
        response = StructuredOutput()
        try:
            prompt_data = {
                "state" : state,
                "last_summary" : last_summary,
                "last_exposed" : last_exposed
            }

            response = _build_response(model_name=model_name, version=version, prompt=prompt, messages=messages, prompt_data=prompt_data)

            message = ""
            message += str(response.security_summary if version == '4.1' else response)

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
