import prompts_concurrent
import os
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage
from state_concurrent import HoneypotState
from langchain_openai import ChatOpenAI
from tools import getNetworkStatus, getFirewallConfiguration, getDockerContainers


# Load environment variables from .env file
load_dotenv("/home/c0ff3k1ll3r/Desktop/Thesis/AI_Agent_for_honeypot_operations/HoneypotAgentApp/src/react_agent/.env")
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Initialize the LLM with the model name
llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools([getNetworkStatus, getFirewallConfiguration, getDockerContainers])

# Assistant function to handle the state and generate responses
def assistant(state: HoneypotState):
    print("Assistant node")
    llm_input = f"""Role: {prompts_concurrent.SYSTEM_PROMPT_GPT}\nState: {state}"""
    message = [SystemMessage(content=llm_input)]
    response = llm_with_tools.invoke(message)
    
    return {"messages": state.messages + [response]}

# Retrieving logs node
def NetworkStatusNode(state: HoneypotState):
    # Your actual log retrieval logic here
    print("Network node")
    new_logs = getNetworkStatus()  

    return {"network_logs": [new_logs]}


# Retrieving firewall rules node
def FirewallConfigurationNode(state: HoneypotState):
    print("Firewall node")
    rules = getFirewallConfiguration()
    return {"firewall_config": rules}

def HoneypotConfigurationNode(state: HoneypotState):
    """
    Tool function for an agent to retrieve information about running Docker containers.
    """
    print("Honeypot node")

    containers = getDockerContainers()
    # Handle errors
    if isinstance(containers, dict) and "error" in containers:
        return containers
    
    return {"honeypot_config": containers}

# Summarizing logs node
def summarize_logs(state: HoneypotState):
    print("Summarizing node")
    summary = llm.invoke(prompts_concurrent.SUMMARIZE_PROMPT.format(logs=state.network_logs))
    return {"network_logs": [summary]}



