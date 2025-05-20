import hashlib
import time
import secrets

class Block:
    def __init__(self, index, prev_hash, timestamp, data, nonce, hash):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce
        self.hash = hash

def generate_nonce():
    return secrets.token_hex(16)

def calculate_hash(block):
    block_string = f"{block.index}{block.prev_hash}{block.timestamp}{block.data}{block.nonce}"
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.nonces = set()
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_nonce = generate_nonce()
        genesis_block = Block(0, "0", time.time(), "Genesis Block", genesis_nonce, "")
        genesis_block.hash = calculate_hash(genesis_block)
        self.chain.append(genesis_block)
        self.nonces.add(genesis_nonce)

    def add_block(self, data):
        prev_block = self.chain[-1]
        index = prev_block.index + 1
        timestamp = time.time()
        nonce = generate_nonce()

        if nonce in self.nonces:
            raise Exception("Replay detected: Nonce already used!")

        temp_block = Block(index, prev_block.hash, timestamp, data, nonce, "")
        hash = calculate_hash(temp_block)
        new_block = Block(index, prev_block.hash, timestamp, data, nonce, hash)

        self.chain.append(new_block)
        self.nonces.add(nonce)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i-1]

            if curr.prev_hash != prev.hash:
                return False
            if curr.hash != calculate_hash(curr):
                return False
            if curr.nonce in list(b.nonce for b in self.chain[:i]):
                return False
        return True
