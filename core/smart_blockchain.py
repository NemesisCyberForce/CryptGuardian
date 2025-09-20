# Erweiterung der Blockchain-Klasse mit Guardian-Integration

from chain_guardian import ChainGuardian, ChainPattern

class SmartBlockchain(Blockchain):
    def __init__(self):
        super().__init__()
        self.guardian = ChainGuardian()
        self._setup_patterns()
        
    def _setup_patterns(self):
        # Standard-Pattern registrieren
        self.guardian.register_pattern(
            "timing",
            ChainPattern("timing", threshold=0.8)
        )
        self.guardian.register_pattern(
            "data_similarity",
            ChainPattern("data_similarity", threshold=0.85)
        )
        
    def add_block(self, data):
        prev_block = self.chain[-1]
        index = prev_block.index + 1
        timestamp = time.time()
        nonce = generate_nonce()

        # Block erstellen
        temp_block = Block(index, prev_block.hash, timestamp, data, nonce, "")
        hash = calculate_hash(temp_block)
        new_block = Block(index, prev_block.hash, timestamp, data, nonce, hash)
        
        # Guardian-Analyse durchführen
        analysis = self.guardian.analyze_block(new_block, self)
        
        if not analysis["valid"]:
            raise SecurityException(
                f"Block wurde abgelehnt: {analysis['anomalies']}"
            )
            
        if analysis["action"] == "warn":
            print(f"WARNUNG: Verdächtiger Block erkannt: {analysis['anomalies']}")
            
        self.chain.append(new_block)
        self.nonces.add(nonce)

class SecurityException(Exception):
    pass
