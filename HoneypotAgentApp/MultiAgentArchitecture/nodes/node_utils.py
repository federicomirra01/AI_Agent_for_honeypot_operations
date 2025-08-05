from langchain_openai import ChatOpenAI
from tools import firewall_tools
import state


fw_tools = [
    firewall_tools.add_allow_rule,
    firewall_tools.add_block_rule,
    firewall_tools.remove_firewall_rule
]

llm = ChatOpenAI(model="gpt-4.1")
llm_firewall = llm.bind_tools(fw_tools)

def load_memory_context(state: state.HoneypotStateReact, episodic_memory):
    """Load memory context from episodic memory and update state"""
    
    if state.memory_context:
        return state.memory_context
    
    recent_iterations = episodic_memory.get_recent_iterations(limit=10)
    if not recent_iterations:
        return []
    
    print(f"Loaded {len(recent_iterations)} recent iterations from episodic memory.")
    return recent_iterations