from prompts import memory_summarizer_prompt
from .node_utils import OPEN_AI_KEY
from configuration import state
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
    model_name = config.get("configurable", {}).get("model_name", "gpt-4.1")
    epoch_num = config.get("configurable", {}).get("epoch_num")
    last_epochs = episodic_memory.get_recent_iterations(limit=1)
    logger.info(epoch_num)
    if not last_epochs:
        last_epoch_summary, last_epoch_memory = ([], [])
    else:
        last_epoch_summary, last_epoch_memory = get_last_epoch_fields(last_epochs[0].value)

    prompt = memory_summarizer_prompt.MEMORY_PLAN_SUMMARIZER_PROMPT.substitute(
        episodic_memory=last_epoch_memory,
        previous_summary=last_epoch_summary,
        epoch_num=epoch_num
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
    reasoning_exploitation = last_epochs.get('reasoning_exploitation', "")
    exploitation_strategy = last_epochs.get('exploitation_strategy', "")

    last_epoch_memory = {
        "exploitation_strategy":exploitation_strategy,
        "reasoning_exploitation":reasoning_exploitation
    }

    return last_epoch_summary, last_epoch_memory