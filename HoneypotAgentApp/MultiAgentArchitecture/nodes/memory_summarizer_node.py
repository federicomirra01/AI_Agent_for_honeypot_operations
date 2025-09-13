from prompts import memory_summarizer_prompt
from .node_utils import OPEN_AI_KEY
from configuration import state
import logging
from pydantic import BaseModel
import instructor
from openai import OpenAI
from langchain_core.messages import AIMessage
class StructuredOutput(BaseModel):
    memory_context: str

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_last_epoch_fields(last_epochs):
    last_epoch_summary = last_epochs.get('memory_context', "")
    reasoning_exploitation = last_epochs.get('reasoning_exploitation', "")
    exploitation_strategy = last_epochs.get('exploitation_strategy', "")

    last_epoch_memory = {
        "exploitation_strategy":exploitation_strategy,
        "reasoning_exploitation":reasoning_exploitation
    }

    return last_epoch_summary, last_epoch_memory


async def memory_summarizer(state: state.HoneypotStateReact, config):
    logger.info("Memory Agent")
    episodic_memory = config.get("configurable", {}).get("store")
    model_config = config.get("configurable", {}).get("model_config", "small:4.1")
    epoch_num = config.get("configurable", {}).get("epoch_num")
    last_epochs = episodic_memory.get_recent_iterations(limit=1)
    message = ""
    
    if last_epochs:
        last_epoch_summary, last_epoch_memory = get_last_epoch_fields(last_epochs[-1].value)

        logger.info(f"Last epoch summary: {last_epoch_summary}")
        prompt = memory_summarizer_prompt.MEMORY_PLAN_SUMMARIZER_PROMPT.substitute(
            episodic_memory=last_epoch_memory,
            previous_summary=last_epoch_summary,
            epoch_num=epoch_num
        )

        version = model_config.split(':')[1]
        if "small" in model_config:
            model_name = f"gpt-{version}-mini"
        else:
            model_name = f"gpt-{version}"
        logger.info(f"Using: {model_name}")
        try:
            messages = {"role":"system", "content": prompt}
            agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
            if version == '5':
                logger.info(f"Using gpt5 minimal effort")
                response = agent.chat.completions.create(
                model=model_name,
                response_model=StructuredOutput,
                messages=[messages], # type: ignore
                reasoning={"effort":"minimal"}
                )
            else:    
                response = agent.chat.completions.create(
                    model=model_name,
                    response_model=StructuredOutput,
                    messages=[messages] # type: ignore
                )
            message += str(response.memory_context)
            logger.info(f"Summary produced: {message}")
            message = AIMessage(content=message)
        except Exception as e:
            logger.error(f"Exception: {e}")
        return {"messages": [message], "memory_context": [message]}
    else:

        last_epoch_summary, last_epoch_memory = ([], [])
        return {"messages": [message], "memory_context": ["No previous memory context available"]}