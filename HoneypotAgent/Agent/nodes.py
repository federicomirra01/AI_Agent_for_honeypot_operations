import prompts
import os
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage
from state import HoneypotState
from langchain_openai import ChatOpenAI
from tools import getNetworkStatus, getFirewallStatus


# Load environment variables from .env file
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Initialize the LLM with the model name
llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools([getNetworkStatus, getFirewallStatus])

# Assistant function to handle the state and generate responses
def assistant(state: HoneypotState):
    print(f"state.messages: {state.messages}")
    print(f"State summary: {state.summary}")
    print(f"State firewall rules {state.firewall_config}")
    llm_input = f"""Role: {prompts.SYSTEM_PROMPT_V1_ONLY_RULES}\nFirewall configuration: {state.firewall_config}\nNetwork summary: {state.summary if state.summary else state.network_logs}"""
    message = [SystemMessage(content=llm_input)]
    response = llm_with_tools.invoke(message)
    
    return {"messages": [response]}

# Retrieving logs node
def retrieve_logs(state: HoneypotState):
    # Your actual log retrieval logic here
    print("Network node")
    new_logs = getNetworkStatus()  
    return {"network_logs": [new_logs]}

# Summarizing logs node
def summarize_logs(state: HoneypotState):
    recent_logs = state.network_logs[-1000:]  # Last 1000 entries
    print("Summarizing node")
    summary = llm.invoke(prompts.SUMMARIZE_PROMPT.format(logs=recent_logs))
    return {"summary": [summary]}

# Retrieving firewall rules node
def retrieve_rules(state: HoneypotState):
    print("Firewall node")
    rules = getFirewallStatus()
    return {"firewall_config": rules}



