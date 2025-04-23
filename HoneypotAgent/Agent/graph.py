import os
from langchain_openai import ChatOpenAI
import prompts
import importlib
importlib.reload(prompts)
from langgraph.graph import MessagesState
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import START, END, StateGraph
from langgraph.prebuilt import tools_condition
from langgraph.prebuilt import ToolNode
from IPython.display import Image, display
from dotenv import load_dotenv
from langchain_core.runnables.graph import MermaidDrawMethod
import nest_asyncio
from tools import getNetworkStatus, getFirewallStatus


nest_asyncio.apply()
load_dotenv()

# Load environment variables from .env file
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
#os.environ["LANGCHAIN_API_KEY"] = os.getenv("LANGCHAIN_API_KEY")

def display_graph(graph, width=250, height=300):

    png_bytes = graph.get_graph().draw_mermaid_png(draw_method=MermaidDrawMethod.PYPPETEER)

    display(Image(data=png_bytes, format="png") #, width=width, height=height)
)

tools = [getFirewallStatus, getNetworkStatus]

llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools(tools)

def assistant(state: MessagesState):
   return {"messages": [llm_with_tools.invoke([prompts.SYSTEM_PROMPT] + state["messages"])]}


# Graph
builder = StateGraph(MessagesState)

# Define nodes: these do the work
builder.add_node("assistant", assistant)
builder.add_node("tools", ToolNode(tools))

# Define edges: these determine how the control flow moves
builder.add_edge(START, "assistant")
builder.add_conditional_edges(
   "assistant",
   tools_condition
)
builder.add_edge("tools", "assistant")

graph = builder.compile()

#