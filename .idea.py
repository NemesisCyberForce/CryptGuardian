import hashlib
import time

class Block:
    def __init__(self, index, prev_hash, timestamp, data, hash):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def calculate_hash(block):
    block_string = f"{block.index}{block.prev_hash}{block.timestamp}{block.data}"
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", time.time(), "Genesis Block", calculate_hash(Block(0, "0", time.time(), "Genesis Block", "")))
        self.chain.append(genesis_block)

    def add_block(self, data):
        prev_block = self.chain[-1]
        index = prev_block.index + 1
        timestamp = time.time()
        hash = calculate_hash(Block(index, prev_block.hash, timestamp, data, ""))
        new_block = Block(index, prev_block.hash, timestamp, data, hash)
        self.chain.append(new_block)

# Beispiel-Blockchain zur Validierung von Verschlüsselungen
blockchain = Blockchain()
blockchain.add_block("Validierung der Verschlüsselung: Hash-XYZ")
blockchain.add_block("Validierung der Verbindung: Schlüssel-12345")

for block in blockchain.chain:
    print(f"Block #{block.index} - {block.data}")
