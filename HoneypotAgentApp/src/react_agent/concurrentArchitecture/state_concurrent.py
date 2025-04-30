from typing import List, Dict, Any
from langchain_core.messages import BaseMessage, HumanMessage
from dataclasses import dataclass, field

@dataclass
class HoneypotState:

    messages: List[BaseMessage] = field(default_factory=list)
    network_logs: List[Dict[str, Any]] = field(default_factory=list)
    firewall_config: List[Dict[str, Any]] = field(default_factory=list)
    honeypot_config: List[Dict[str, Any]] = field(default_factory=list)

    def __init__(self, **kwargs):
        """
        Custom initializer that can handle both direct field assignment
        and dictionary unpacking.
        """
        # Handle 'messages' input
        self.messages = kwargs.get('messages', [])
        # Convert string message to BaseMessage if needed
        if isinstance(self.messages, str):
            self.messages = [HumanMessage(content=self.messages)]
        elif not isinstance(self.messages, list):
            self.messages = []
        
        self.network_logs = kwargs.get('network_logs', [{}])
        self.summary = kwargs.get('summary', "")
        self.firewall_config = kwargs.get('firewall_config', "")
        self.honeypot_config = kwargs.get('honeypot_config', [{}])