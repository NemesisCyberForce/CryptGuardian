# Nonce im Block speichern
class Block:
    def __init__(self, index, prev_hash, timestamp, data, nonce, hash):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce
        self.hash = hash
# Nonce generieren
import secrets

def generate_nonce():
    return secrets.token_hex(16)
# Implement of  Nonce-based transaction validation
# File: CryptGurdian/nonce_based.py
# Nonce in Hash-Berechnung aufnehmen
def calculate_hash(block):
    block_string = f"{block.index}{block.prev_hash}{block.timestamp}{block.data}{block.nonce}"
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

#  Nonce beim Hinzufügen eines Blocks verwenden
def add_block(self, data):
    prev_block = self.chain[-1]
    index = prev_block.index + 1
    timestamp = time.time()
    nonce = generate_nonce()
    temp_block = Block(index, prev_block.hash, timestamp, data, nonce, "")
    hash = calculate_hash(temp_block)
    new_block = Block(index, prev_block.hash, timestamp, data, nonce, hash)
    self.chain.append(new_block)

#Nonce-Validierung
class Blockchain:
    def __init__(self):
        self.chain = []
        self.nonces = set()
        self.create_genesis_block()

    def add_block(self, data):
        ...
        if nonce in self.nonces:
            raise Exception("Replay detected: Nonce already used!")
        self.nonces.add(nonce)
        ...

