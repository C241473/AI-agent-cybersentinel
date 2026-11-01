"""
CyberSentinel AI - Agent Incident & Conversation Memory Store
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional

class SecurityMemory:
    """Manages conversational history, detected findings, and incident state."""

    def __init__(self, max_messages: int = 30):
        self.max_messages = max_messages
        self.messages: List[Dict[str, str]] = []
        self.active_incident: Optional[Dict[str, Any]] = None
        self.past_scans: List[Dict[str, Any]] = []

    def add_message(self, role: str, content: str):
        """Add a role-based message to the conversation context."""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]

    def get_messages(self) -> List[Dict[str, str]]:
        """Return conversational history formatted for LLM consumption."""
        return [{"role": m["role"], "content": m["content"]} for m in self.messages]

    def record_scan_result(self, scan_type: str, target: str, result: Dict[str, Any]):
        """Persist a scan finding to incident memory."""
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": scan_type,
            "target": target,
            "result": result
        }
        self.past_scans.append(record)
        self.active_incident = record

    def get_last_scan(self) -> Optional[Dict[str, Any]]:
        """Retrieve most recent scan."""
        return self.active_incident

    def clear(self):
        """Reset memory context."""
        self.messages.clear()
        self.past_scans.clear()
        self.active_incident = None
