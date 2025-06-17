from typing import List, Dict, Any, Optional, Annotated
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage
from dataclasses import field

class HoneypotStateReact:
    messages: Annotated[List[BaseMessage], add_messages] = field(default_factory=list)
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

