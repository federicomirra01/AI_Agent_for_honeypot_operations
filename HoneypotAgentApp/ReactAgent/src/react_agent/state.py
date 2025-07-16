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
    messages: Annotated[List[BaseMessage], messages_reducer] = field(default_factory=list)
    packet_summary: Dict[str, Any] = field(default_factory=dict)
    network_packets : List[Dict[str, Any]] = field(default_factory=list)
    network_flows: Dict[str, Any] = field(default_factory=dict)
    security_events: Dict[str, Any] = field(default_factory=dict)
    compressed_packets: Dict[str, Any] = field(default_factory=dict)
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)
    firewall_status: str = ""
    monitor_status: str = ""
    cleanup_flag: bool = False
    memory_context: Dict[str, Any] = field(default_factory=dict)

    rules_added_current_epoch: List[str] = field(default_factory=list)
    rules_removed_current_epoch: List[str] = field(default_factory=list)
    currently_exposed: List[str] = field(default_factory=list)
    attack_graph_progressions: List[str] = field(default_factory=list)
    decision_rationale: List[str] = field(default_factory=list)
    lockdown_status: List[str] = field(default_factory=list)

    evidence_summary: List[str] = field(default_factory=list)
    justification: List[str] = field(default_factory=list)
    next_iteration_guidance: List[str] = field(default_factory=list)

    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.network_packets = kwargs.get('network_packets', [])
        self.network_flows = kwargs.get('network_flows', {})
        self.security_events = kwargs.get('security_events', {})
        self.compressed_packets = kwargs.get('compressed_packets', {})
        self.packet_summary = kwargs.get('packet_summary', {})
        self.firewall_config = kwargs.get('firewall_config', [])
        self.honeypot_config = kwargs.get('honeypot_config', [])
        self.firewall_status = kwargs.get('firewall_status', "")
        self.monitor_status = kwargs.get('monitor_status', "")
        self.cleanup_flag = kwargs.get('cleanup_flag', False)
        self.memory_context = kwargs.get('memory_context', {})
        self.rules_added_current_epoch = kwargs.get('rules_added_current_epoch', [])
        self.rules_removed_current_epoch = kwargs.get('rules_removed_current_epoch', [])
        self.currently_exposed = kwargs.get('currently_exposed', [])
        self.attack_graph_progressions = kwargs.get('attack_graph_progressions', [])
        self.decision_rationale = kwargs.get('decision_rationale', [])
        self.lockdown_status = kwargs.get('lockdown_status', [])
        self.evidence_summary = kwargs.get('evidence_summary', [])
        self.justification = kwargs.get('justification', [])
        self.next_iteration_guidance = kwargs.get('next_iteration_guidance', [])
