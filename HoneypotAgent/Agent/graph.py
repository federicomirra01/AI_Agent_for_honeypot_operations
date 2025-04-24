import sys
sys.path.append('/home/c0ff3k1ll3r/Desktop/Thesis/AI_Agent_for_honeypot_operations/AgentApp/src')
from langgraph.graph import START, END, StateGraph
from nodes import assistant, retrieve_rules, retrieve_logs, summarize_logs
from state import HoneypotState

   
    # Graph
builder = StateGraph(HoneypotState)

# Define nodes: 
builder.add_node("assistant", assistant)
builder.add_node("retrieve_rules", retrieve_rules)
builder.add_node("retrieve_logs", retrieve_logs)
builder.add_node("summarize", summarize_logs)

# Define decision points
def should_summarize(state: HoneypotState):
    if len(state.network_logs) % 10 == 0:  # Summarize every 1000 logs
        return "summarize"
    return "assistant"

# Build the graph
builder.add_edge(START, "retrieve_rules")
builder.add_edge(START, "retrieve_logs")

# builder.add_conditional_edges("retrieve_logs", should_summarize, {
#         "summarize": "summarize",
#         "assistant": "assistant"
#     })
builder.add_edge("retrieve_logs", "summarize")
builder.add_edge(["retrieve_rules", "summarize"], "assistant")
builder.add_edge("assistant", END)

graph = builder.compile()
