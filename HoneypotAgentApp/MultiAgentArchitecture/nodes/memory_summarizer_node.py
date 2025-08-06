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

async def memory_summarizer(state: state.HoneypotStateReact, config, window=5):
    logger.info("Memory Agent")
    episodic_memory = config.get("configurable", {}).get("store")
    last_epochs = episodic_memory.get_recent_iterations(limit=window)
    prompt = memory_summarizer_prompt.MEMORY_SUMMARIZER_PROMPT.format(
        episodic_memory=last_epochs
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
