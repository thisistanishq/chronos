"""
CHRONOS COMPLIANCE AUDITOR
Logs all critical system actions to a secure, append-only log file.
Ensures accountability for all operator actions.
"""

import logging
import os
from datetime import datetime
import rich

AUDIT_FILE = "chronos_audit.log"

class AuditLogger:
    def __init__(self, log_file=AUDIT_FILE):
        self.log_file = log_file
        self._setup_logger()

    def _setup_logger(self):
        # Create a dedicated logger for auditing
        self.logger = logging.getLogger("CHRONOS_AUDIT")
        self.logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = logging.FileHandler(self.log_file)
            formatter = logging.Formatter('%(asctime)s - [AUDIT] - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, action: str, user: str, details: str, status: str = "SUCCESS"):
        """
        Logs a compliance event.
        action: The type of action (e.g., "SYSTEM_START", "USER_LOGIN", "DATA_EXPORT")
        user: The actor (e.g., "admin", "system", "worker_1")
        details: Specifics about the action
        status: SUCCESS / FAILURE / WARNING
        """
        # 1. Write to secure log file
        log_message = f"ACTION={action} | USER={user} | STATUS={status} | DETAILS={details}"
        self.logger.info(log_message)
        
        # 2. Visual feedback for the operator (if strictly secure, this might be hidden, 
        # but for this tool, visibility is good)
        color = "green" if status == "SUCCESS" else "red"
        if status == "WARNING": color = "yellow"
        
        rich.print(f"[bold {color}]🛡️  [AUDIT] {action}: {details}[/bold {color}]")

# Global Instance
audit_log = AuditLogger()
