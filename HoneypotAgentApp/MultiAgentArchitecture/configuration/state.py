from typing import List, Dict, Any, Annotated, Union
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from dataclasses import field

def messages_reducer(current: List[BaseMessage], update: Union[List[BaseMessage], str]) -> List[BaseMessage]:
    """Safe custom reducer that preserves tool call integrity"""
    if update == "CLEAR_ALL":
        # Only clear if no pending tool calls
        if current:
            last_msg = current[-1]
            if isinstance(last_msg, AIMessage) and hasattr(last_msg, 'tool_calls') and last_msg.tool_calls:
                print("Cannot clear: pending tool calls exist")
                return current
        return []
    
    else:
        # Normal append operation
        return add_messages(current, update)
    
class HoneypotStateReact:
    # Agents fields
    messages: Annotated[List[BaseMessage], messages_reducer] = field(default_factory=list)
    # Memory Agent
    memory_context : str = ""
    # Summarize Agent
    security_events: Dict[str, Any] = field(default_factory=dict)
    security_events_summary: Dict[str, Any] = field(default_factory=dict)  
    # Inference Agent
    inferred_attack_graph: Dict[str, Any] = field(default_factory=dict)
    currently_exposed: List[dict] = field(default_factory=list)
    reasoning_inference: str = ""
    # Exploitation Agent
    exploitation_strategy: List[dict] = field(default_factory=list) 
    honeypots_exploitation: Dict[str, Dict[str, Any]] = field(default_factory=dict) 
    reasoning_exploitation: str = ""
    # Firewall Agent
    firewall_reasoning: str = ""
    firewall_action : List[Any] = field(default_factory=list)
    
    # Configuration fields
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)
   
    # Benchmark fields
    rules_added_current_epoch: List[str] = field(default_factory=list)
    rules_removed_current_epoch: List[str] = field(default_factory=list)
    lockdown_status: bool = False
    
    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        # Memory Field
        self.memory_context = kwargs.get('memory_context', "")
        # Configuration Field
        self.firewall_config = kwargs.get('firewall_config', [])
        self.honeypot_config = kwargs.get('honeypot_config', [])
        # Summarize Agent Field
        self.security_events = kwargs.get('security_events', {})
        self.security_events_summary = kwargs.get('security_events_summary', {})
        # Inference Agent Field
        self.reasoning_inference = kwargs.get('reasoning_inference', "")
        self.honeypots_exploitation = kwargs.get('honeypots_exploitation', {})
        self.inferred_attack_graph = kwargs.get('inferred_attack_graph', {})
        # Exploitation Agent Field
        self.reasoning_exploitation = kwargs.get('reasoning_exploitation', "")
        self.currently_exposed = kwargs.get('currently_exposed', [])
        self.exploitation_strategy = kwargs.get('exploitation_strategy', {})
        self.lockdown_status = kwargs.get('lockdown_status', False)
        #Firewall Agent Field
        self.firewall_reasoning = kwargs.get('firewall_reasoning', "")
        self.firewall_action = kwargs.get('firewall_action', [])
        # Benchmark Fields 
        self.rules_added_current_epoch = kwargs.get('rules_added_current_epoch', [])
        self.rules_removed_current_epoch = kwargs.get('rules_removed_current_epoch', [])
        
        
    
