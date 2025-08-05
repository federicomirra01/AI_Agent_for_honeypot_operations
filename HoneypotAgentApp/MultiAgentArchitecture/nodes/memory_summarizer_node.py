from prompts import memory_summarizer_prompt
from .node_utils import llm
import state
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def memory_summarizer(state: state.HoneypotStateReact, config, window=5):
    logger.info("Memory Agent")
    episodic_memory = config.get("configurable", {}).get("store")
    last_epochs = episodic_memory.get_recent_iterations(limit=window)
    summary_prompt = memory_summarizer_prompt.MEMORY_SUMMARIZER_PROMPT.format(
        episodic_memory=last_epochs
    )
    summary_response = await llm.ainvoke(summary_prompt)
    return {"messages": state.messages + [summary_response], "memory_context": summary_response.content}
