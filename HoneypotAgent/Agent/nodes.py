import prompts
import os
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from state import HoneypotState
from langchain_openai import ChatOpenAI
from tools import getNetworkStatus, getFirewallStatus

load_dotenv()

# Load environment variables from .env file
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")


llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools([getNetworkStatus, getFirewallStatus])


def assistant(state: HoneypotState):
    print(f"state.messages: {state.messages}")
    print(f"State summary: {state.summary}")
    print(f"State firewall rules {state.firewall_config}")
    llm_input = f"""Role: {prompts.SYSTEM_PROMPT_V1}\nFirewall configuration: {state.firewall_config}\nNetwork summary: {state.summary if state.summary else state.network_logs}"""
    message = [SystemMessage(content=llm_input)]
    response = llm_with_tools.invoke(message)
    
    return {"messages": [response]}




SUMMARIZE_PROMPT = ChatPromptTemplate.from_template("""
**Network Log Analysis for Firewall Policy Creation**

Analyze these network logs and extract firewall-relevant patterns:
{logs}

Structure findings in these categories using precise technical terms:

1. **IP Threat Indicators**
   - High-frequency sources: `[IP: count]` (Threshold: >15 requests/min)
   - Known malicious IPs: `[IP]` (Cross-referenced with threat DB)
   - Unverified/new IPs: `[IP: first_seen]`

2. **Port/Protocol Risks** 
   - Suspicious port clusters: `[port: protocol: count]` 
     - Focus on: non-standard ports for services (e.g., HTTP on 8080)
     - Uncommon protocol mixes (e.g., SSH over UDP)
   - Baseline comparison: `[Percentage deviation from normal port distribution]`

3. **Geo-Location Threats**
   - Unexpected regions: `[country: percentage of total traffic]` 
     - Flag if: >5% traffic from non-operational regions
   - ASN anomalies: `[autonomous_system: expected? Y/N]`

4. **Behavioral Red Flags**
   - Scan patterns: `[IP: ports_scanned/time_window]`
   - Protocol violations: `[e.g., DNS tunneling attempts]`
   - Session abnormalities: `[short-lived:long-lived ratio]`

The output must be in a json format and should be efficiently structured to be given in input to an LLM to generate firewall rules. Hence, you should summarize the logs but maintaining the information needed to generate the rules.

""")

def retrieve_logs(state: HoneypotState):
    # Your actual log retrieval logic here
    print("Network node")
    new_logs = getNetworkStatus()  
    return {"network_logs": [new_logs]}

def summarize_logs(state: HoneypotState):
    recent_logs = state.network_logs[-1000:]  # Last 1000 entries
    print("Summarizing node")
    summary = llm.invoke(SUMMARIZE_PROMPT.format(logs=recent_logs))
    return {"summary": [summary]}

def retrieve_rules(state: HoneypotState):
    print("Firewall node")
    rules = getFirewallStatus()
    return {"firewall_config": rules}



