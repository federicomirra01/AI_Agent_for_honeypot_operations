from prompts import memory_summarizer_prompt
from .node_utils import OPEN_AI_KEY
import state
import logging
from pydantic import BaseModel
import instructor
from openai import OpenAI

class StructuredOutput(BaseModel):
    memory_context: str

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def memory_summarizer(state: state.HoneypotStateReact, config):
    logger.info("Memory Agent")
    episodic_memory = config.get("configurable", {}).get("store")
    last_epochs = episodic_memory.get_recent_iterations(limit=1)
    if not last_epochs:
        last_epoch_summary, last_epoch_memory = ([], [])
    else:
        last_epoch_summary, last_epoch_memory = get_last_epoch_fields(last_epochs[0].value)

    prompt = memory_summarizer_prompt.MEMORY_SUMMARIZER_PROMPT.format(
        episodic_memory=last_epoch_memory,
        previous_summary=last_epoch_summary
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
        message += str(response.memory_context)
        
    except Exception as e:
        logger.error(f"Exception: {e}")
    return {"messages": state.messages + [message], "memory_context": response.memory_context}

def get_last_epoch_fields(last_epochs):
    last_epoch_summary = last_epochs.get('memory_context', "")
    currently_exposed = last_epochs.get('currently_exposed', {})
    rules_added = last_epochs.get('rules_added',[])
    honeypots_exploitation = last_epochs.get('honeypots_exploitation', {})
    lockdown_status = last_epochs.get('lockdown_status', False)
    rules_removed = last_epochs.get('rules_removed', [])
    firewall_reasoning = last_epochs.get('firewall_reasoning', "")
    inferred_attack_graph = last_epochs.get('inferred_attack_graph', {})
    reasoning_inference = last_epochs.get('reasoning_inference', "")
    reasoning_exploitation = last_epochs.get('reasoning_exploitation', "")

    last_epoch_memory = {
        "currently_exposed": currently_exposed,
        "rules_added": rules_added,
        "honeypots_exploitation": honeypots_exploitation,
        "lockdown_status": lockdown_status,
        "rules_removed": rules_removed,
        "firewall_reasoning": firewall_reasoning,
        "inferred_attack_graph": inferred_attack_graph,
        "reasoning_inference": reasoning_inference,
        "reasoning_exploitation":reasoning_exploitation
    }

    return last_epoch_summary, last_epoch_memory