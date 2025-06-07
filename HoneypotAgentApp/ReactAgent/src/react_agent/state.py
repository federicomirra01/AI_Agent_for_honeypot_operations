from typing import List, Dict, Any, Optional
from langchain_core.messages import BaseMessage, HumanMessage
from dataclasses import dataclass, field

@dataclass
class HoneypotStateReact:
    messages: List[BaseMessage] = field(default_factory=list)
    packet_summary: str = ""
    network_packets : List[Dict[str, Any]] = field(default_factory=list)
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)
    firewall_status: str = ""
    monitor_status: str = ""

    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.network_packets = kwargs.get('network_packets', [])
        self.packet_summary = kwargs.get('packet_summary', "")
        self.firewall_config = kwargs.get('firewall_config', [])
        self.honeypot_config = kwargs.get('honeypot_config', [])
        self.firewall_status = kwargs.get('firewall_status', "")
        self.monitor_status = kwargs.get('monitor_status', "")

