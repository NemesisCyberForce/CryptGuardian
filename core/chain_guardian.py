# chain_guardian test idee
# Dieser erweiterte Code führt folgende neue Funktionen ein:

# ChainGuardian: Eine dedizierte Klasse zur Überwachung der Blockchain
# ValidationPattern: Definiert Muster, nach denen gesucht werden soll
# Erweiterte Analysefunktionen: Erkennt verschiedene Muster in den Blockchain-Daten
#  Severity Levels: Verschiedene Wichtigkeitsstufen für gefundene Muster
import hashlib
import time
import re
from typing import List, Optional

class ValidationPattern:
    def __init__(self, pattern_name: str, pattern_regex: str, severity: str = "INFO"):
        self.pattern_name = pattern_name
        self.pattern_regex = pattern_regex
        self.severity = severity

class ChainGuardian:
    def __init__(self):
        self.patterns = []
        self._initialize_default_patterns()
    
    def _initialize_default_patterns(self):
        # Standard-Überwachungsmuster
        self.patterns.extend([
            ValidationPattern(
                "Verschlüsselungsvalidierung", 
                r"Hash-[A-Za-z0-9]+",
                "CRITICAL"
            ),
            ValidationPattern(
                "Verbindungsschlüssel", 
                r"Schlüssel-\d+",
                "WARNING"
            ),
            ValidationPattern(
                "Sicherheitsaudit", 
                r"Audit-[A-Za-z0-9\-]+",
                "INFO"
            )
        ])
    
    def add_pattern(self, pattern: ValidationPattern):
        self.patterns.append(pattern)
    
    def analyze_block(self, block) -> List[dict]:
        findings = []
        for pattern in self.patterns:
            if re.search(pattern.pattern_regex, block.data):
                findings.append({
                    "block_index": block.index,
                    "pattern_name": pattern.pattern_name,
                    "severity": pattern.severity,
                    "timestamp": block.timestamp,
                    "matched_data": block.data
                })
        return findings

class Block:
    def __init__(self, index: int, prev_hash: str, timestamp: float, data: str, hash: str):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash
        self.validation_results = []

class EnhancedBlockchain:
    def __init__(self):
        self.chain = []
        self.guardian = ChainGuardian()
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(
            0, "0", time.time(), 
            "Genesis Block: KettenWächter initialisiert", 
            self._calculate_hash("0", time.time(), "Genesis Block: KettenWächter initialisiert")
        )
        self.chain.append(genesis_block)

    def _calculate_hash(self, prev_hash: str, timestamp: float, data: str) -> str:
        block_string = f"{prev_hash}{timestamp}{data}"
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def add_block(self, data: str):
        prev_block = self.chain[-1]
        timestamp = time.time()
        hash = self._calculate_hash(prev_block.hash, timestamp, data)
        
        new_block = Block(
            index=len(self.chain),
            prev_hash=prev_block.hash,
            timestamp=timestamp,
            data=data,
            hash=hash
        )
        
        # Führe Analyse durch
        findings = self.guardian.analyze_block(new_block)
        new_block.validation_results = findings
        
        self.chain.append(new_block)
        return findings

# Beispiel zur Verwendung
if __name__ == "__main__":
    blockchain = EnhancedBlockchain()
    
    # Füge einige Test-Blöcke hinzu
    findings1 = blockchain.add_block("Verschlüsselungsvalidierung: Hash-XYZ123")
    findings2 = blockchain.add_block("Verbindungsvalidierung: Schlüssel-9876")
    findings3 = blockchain.add_block("Sicherheitsaudit: Audit-2023-001")
    
    # Zeige die Ergebnisse
    print("\n=== KettenWächter Analyse ===")
    for block in blockchain.chain[1:]:  # Skip genesis block
        print(f"\nBlock #{block.index}:")
        print(f"Data: {block.data}")
        if block.validation_results:
            print("Gefundene Muster:")
            for result in block.validation_results:
                print(f"- {result['pattern_name']} ({result['severity']})")
        else:
            print("Keine Muster gefunden")
