from configuration import state
import logging
import os
from dotenv import load_dotenv
# Load environment variables
load_dotenv()
OPEN_AI_KEY = os.getenv("OPENAI_API_KEY")
POLITO_CLUSTER_KEY = os.getenv("POLITO_CLUSTER_KEY")
MISTRAL_STRING = "mistralai/Mistral-7B-Instruct-v0.1"
POLITO_URL = "https://kubernetes.polito.it/vllm/v1"
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_memory_context(state: state.HoneypotStateReact, episodic_memory):
    """Load memory context from episodic memory and update state"""
    
    if state.memory_context:
        return state.memory_context
    
    recent_iterations = episodic_memory.get_recent_iterations(limit=10)
    if not recent_iterations:
        return []
    
    logger.info(f"Loaded {len(recent_iterations)} recent iterations from episodic memory.")
    return recent_iterations

