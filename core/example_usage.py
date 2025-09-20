import hashlib
import time
import secrets
from typing import Callable, Dict, List, Optional
import logging
from dataclasses import dataclass
from enum import Enum

# Alert Severity Levels
class AlertSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Alert:
    severity: AlertSeverity
    message: str
    block_index: int
    timestamp: float
    details: Dict

class SecurityException(Exception):
    pass

class ChainGuardian:
    def __init__(self):
        self.alert_handlers: List[Callable] = []
        self.pattern_memory: Dict = {}
        self.suspicious_patterns: List[str] = []
        self.quarantine_blocks: List = []
        
    def register_alert_handler(self, handler: Callable):
        self.alert_handlers.append(handler)
        
    def raise_alert(self, severity: AlertSeverity, message: str, block_index: int, details: Dict = None):
        alert = Alert(
            severity=severity,
            message=message,
            block_index=block_index,
            timestamp=time.time(),
            details=details or {}
        )
        
        for handler in self.alert_handlers:
            handler(alert)
            
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            raise SecurityException(message)

class Block:
    def __init__(self, index: int, prev_hash: str, timestamp: float, data: str, nonce: str):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce
        self.hash = self.calculate_hash()
        self.validation_score = 0.0
        
    def calculate_hash(self) -> str:
        block_string = f"{self.index}{self.prev_hash}{self.timestamp}{self.data}{self.nonce}"
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

class SmartBlockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.guardian = ChainGuardian()
        self.create_genesis_block()
        
    def create_genesis_block(self):
        genesis_block = Block(0, "0", time.time(), "Genesis Block", secrets.token_hex(16))
        self.chain.append(genesis_block)
        
    def add_block(self, data: str):
        # Basis-Validierung
        if not self.is_chain_valid():
            self.guardian.raise_alert(
                AlertSeverity.CRITICAL,
                "Blockchain integrity violation detected!",
                len(self.chain)
            )
            
        prev_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            prev_hash=prev_block.hash,
            timestamp=time.time(),
            data=data,
            nonce=secrets.token_hex(16)
        )
        
        # Smart Pattern Detection
        if self._detect_suspicious_patterns(new_block):
            self.guardian.raise_alert(
                AlertSeverity.HIGH,
                "Suspicious pattern detected in block data",
                new_block.index,
                {"pattern_type": "anomaly"}
            )
        
        self.chain.append(new_block)
        
    def _detect_suspicious_patterns(self, block: Block) -> bool:
        # Implementiere hier deine Pattern-Detection-Logik
        # Dies ist nur ein Beispiel
        suspicious_keywords = ["hack", "exploit", "overflow", "injection"]
        return any(keyword in block.data.lower() for keyword in suspicious_keywords)
        
    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            if current.prev_hash != previous.hash:
                return False
            if current.hash != current.calculate_hash():
                return False
                
        return True
