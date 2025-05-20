from core.nonce_based import Blockchain

bc = Blockchain()
bc.add_block("Vertrauliche Nachricht #1")
bc.add_block("Vertrauliche Nachricht #2")

for b in bc.chain:
    print(f"Block {b.index} | Nonce: {b.nonce} | Hash: {b.hash}")
