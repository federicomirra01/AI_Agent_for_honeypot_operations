from typing import List, Dict, Any, Optional
from langchain_core.messages import BaseMessage, HumanMessage
from dataclasses import dataclass, field
import operator
from typing import Annotated

@dataclass
class HoneypotState:

    messages: List[BaseMessage] = field(default_factory=list)
    network_logs: List[Dict[str, Any]] = field(default_factory=list)
    summary: Optional[str] = ""
    firewall_config: Optional[str] = ""

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
