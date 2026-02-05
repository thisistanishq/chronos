"""
CHRONOS IMMUTABLE LEDGER
Implements a "Blockchain-Lite" system to ensure data integrity of discovered keys.
Each record is cryptographically linked to the previous one.
"""

import hashlib
import json
import os
import time
from datetime import datetime
import rich

LEDGER_FILE = "chronos_ledger.json"

class BlockchainLedger:
    def __init__(self, ledger_path=LEDGER_FILE):
        self.ledger_path = ledger_path
        self.chain = self._load_chain()

    def _load_chain(self):
        if not os.path.exists(self.ledger_path):
            return [self._create_genesis_block()]
        
        try:
            with open(self.ledger_path, 'r') as f:
                chain = json.load(f)
                return chain
        except (json.JSONDecodeError, IOError):
            rich.print("[bold red]⚠️  LEDGER CORRUPTED. REINITIALIZING CHAIN.[/bold red]")
            return [self._create_genesis_block()]

    def _create_genesis_block(self):
        """Creates the first block in the chain."""
        return {
            "index": 0,
            "timestamp": time.time(),
            "data": "GENESIS_BLOCK_CHRONOS_SYSTEM_INIT",
            "previous_hash": "0" * 64,
            "hash": self._calculate_hash(0, time.time(), "GENESIS_BLOCK_CHRONOS_SYSTEM_INIT", "0" * 64)
        }

    def _calculate_hash(self, index, timestamp, data, previous_hash):
        """SHA-256 Hashing of block content."""
        payload = f"{index}{timestamp}{json.dumps(data, sort_keys=True)}{previous_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def add_block(self, data):
        """
        Adds a new record (block) to the chain.
        data: Dict containing the key findings (e.g. {'key': 'sk-...'}).
        """
        last_block = self.chain[-1]
        
        index = last_block['index'] + 1
        timestamp = time.time()
        previous_hash = last_block['hash']
        
        new_hash = self._calculate_hash(index, timestamp, data, previous_hash)
        
        new_block = {
            "index": index,
            "timestamp": timestamp,
            "data": data,
            "previous_hash": previous_hash,
            "hash": new_hash
        }
        
        self.chain.append(new_block)
        self._save_chain()
        return new_hash

    def _save_chain(self):
        try:
            with open(self.ledger_path, 'w') as f:
                json.dump(self.chain, f, indent=4)
        except Exception as e:
            rich.print(f"[bold red]❌ FAILED TO SAVE LEDGER: {str(e)}[/bold red]")

    def verify_integrity(self):
        """
        Verifies that the chain has not been tampered with.
        Returns: True if valid, False if compromised.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # 1. Check if previous_hash matches the actual hash of the previous block
            if current['previous_hash'] != previous['hash']:
                rich.print(f"[bold red]🚨 INTEGRITY BREACH AT BLOCK {current['index']}: PREVIOUS HASH MISMATCH[/bold red]")
                return False
                
            # 2. Check if the current hash is valid for the current data
            recalulated_hash = self._calculate_hash(current['index'], current['timestamp'], current['data'], current['previous_hash'])
            if current['hash'] != recalulated_hash:
                rich.print(f"[bold red]🚨 INTEGRITY BREACH AT BLOCK {current['index']}: DATA TAMPERING DETECTED[/bold red]")
                return False
                
        rich.print("[bold green]✅ LEDGER INTEGRITY VERIFIED. SYSTEM SECURE.[/bold green]")
        return True

# Global Instance
chronos_ledger = BlockchainLedger()
