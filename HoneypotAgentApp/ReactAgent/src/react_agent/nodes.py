import prompts
import os
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage
from state import HoneypotStateReact
from langchain_openai import ChatOpenAI
from tools import getNetworkStatus, getFirewallConfiguration, getDockerContainers


# Load environment variables from .env file
load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Initialize the LLM with the model name
llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools([getNetworkStatus, getFirewallConfiguration, getDockerContainers])

# Assistant function to handle the state and generate responses
def assistant(state: HoneypotStateReact):
    prompt = prompts.SYSTEM_PROMPT_GPT_REACT_ONLY_RULES if state.only_rules else prompts.SYSTEM_PROMPT_GPT_REACT
    llm_input = f"""Role: {prompt}\nState: {state}"""
    message = [SystemMessage(content=llm_input)]
    response = llm_with_tools.invoke(message)
    if hasattr(response, "tool_calls") and response.tool_calls:
        pending_tool_calls = list(response.tool_calls)
        tools_completed = False
        return {
            "messages": state.messages + [response],
            "pending_tool_calls": pending_tool_calls,
            "tools_completed": tools_completed
        }
    else:
        # No tool calls or all tools completed
        print("No tool calls or all tools completed")
        return {
            "messages": state.messages + [response],
            "tools_completed": True
        }

# Retrieving logs node
def NetworkStatusNode(state: HoneypotStateReact):
    # Your actual log retrieval logic here
    print("Network node")
    new_logs = getNetworkStatus()  
    to_summarize = False
    if len(new_logs) > 10:
        print("Setting summarize flag")
        to_summarize = True

    return {"network_logs": [new_logs], "to_summarize": to_summarize}


# Retrieving firewall rules node
def FirewallConfigurationNode(state: HoneypotStateReact):
    print("Firewall node")
    rules = getFirewallConfiguration()
    return {"firewall_config": rules}

def HoneypotConfigurationNode(state: HoneypotStateReact):
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
def summarize_logs(state: HoneypotStateReact):
    print("Summarizing node")
    summary = llm.invoke(prompts.SUMMARIZE_PROMPT.format(logs=state.network_logs))
    return {"network_logs": [summary], "to_summarize": False}



