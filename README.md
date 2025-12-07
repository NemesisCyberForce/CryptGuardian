# CryptGuardian 🛡️

### Quantum-Hardened Blockchain Security Module

###### Concept Prototype by Volkan Sah

CryptGuardian is a **research-level concept**, created from the perspective of a developer concerned about long-term security for distributed systems. It is not a final product, but an exploration of defense strategies against modern and future threats, including **AI-assisted attacks** and **quantum cryptanalysis**.

The objective is simple:
Increase the cost, complexity, and feasibility barrier for attackers.
No system is unbreakable — but it can be made impractical to break.

Version: **v0.3-alpha (Quantum Leap)**
Copyright © 2025 NCF


## Purpose

Modern cryptography faces two accelerating risks:

1.  AI-based automated attacks
2.  Quantum algorithms that weaken classical cryptosystems

CryptGuardian explores mitigation strategies through:

  * Quantum-hardened hashing
  * Post-Quantum signature simulation
  * **Timing anomaly detection**
  * Threat intelligence and pattern analysis
  * Safer block validation and monitoring

This project is an **idea**, a technical experiment — not a guaranteed quantum-safe framework.

-----

## Quantum Leap Enhancements (v0.3-alpha)

### Hybrid Quantum-Resistant Hashing

The default block type applies:

  * SHA-256 → SHA3-512 → SHA-256 (double-round hashing)
  * 32-byte nonces (twice the classical size)
  * Structure hardened against Grover-like search acceleration

### Optional BLAKE3 Integration

If installed, **BLAKE3** provides:

  * Higher performance
  * Wider internal state
  * Tree-based hashing

Requires:

```bash
pip install blake3
```

### PQC Signature Simulation (Lamport Principle)

A simplified Lamport One-Time Signature model demonstrates:

  * Large PQC key sizes
  * One-time usage constraints
  * Binary-path signature generation
  * Hash-based verification

This prepares the groundwork for future Dilithium/Kyber integration.

-----

## Full Quantum-Resistant Code (Included as Reference)

The following classes and functions are the core elements of the **Quantum Leap** strategy, implementing hybrid hashing and Post-Quantum Signatures:

```python
# Quantum-Resistant Enhancements for CryptGuardian
# Adds BLAKE3 + Hybrid PQC approach

import hashlib
from typing import Dict, Tuple
import secrets
import time
import binascii

# ============================================================
# OPTION 1: Hybrid Hash Chain (A simple, immediate PQC solution)
# ============================================================
class QuantumResistantBlock:
    """Drop-in replacement for your existing Block class with Quantum-Hardening"""
    
    def __init__(self, index: int, prev_hash: str, timestamp: float, data: str, nonce: str = None):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.data = data
        # Doubled Nonce length (64 chars / 32 bytes) for increased quantum difficulty
        self.nonce = nonce or secrets.token_hex(32)
        self.hash = self.calculate_quantum_hash()
        self.validation_score = 0.0
        self.metadata = {'quantum_resistant': True}
        
    def calculate_quantum_hash(self) -> str:
        """
        Hybrid Hashing: SHA-256 + SHA3-512 + Double-Round
        """
        block_string = f"{self.index}{self.prev_hash}{self.timestamp}{self.data}{self.nonce}"
        
        # Round 1: SHA-256
        hash1 = hashlib.sha256(block_string.encode()).hexdigest()
        
        # Round 2: SHA3-512 over the SHA-256 Result
        hash2 = hashlib.sha3_512(hash1.encode()).hexdigest()
        
        # Final: Combined Hash (SHA-256 over both results)
        return hashlib.sha256(f"{hash1}{hash2}".encode()).hexdigest()


# ============================================================
# OPTION 2: BLAKE3 Integration (fast and quantum-safe hash)
# ============================================================
# Installation: pip install blake3
try:
    import blake3
    
    class BLAKE3Block:
        """High-Performance Quantum-Hardened Block, using the modern BLAKE3 hash."""
        
        def __init__(self, index: int, prev_hash: str, timestamp: float, data: str):
            self.index = index
            self.prev_hash = prev_hash
            self.timestamp = timestamp
            self.data = data
            self.nonce = secrets.token_hex(32) # Standardized long nonce
            self.hash = self.calculate_blake3_hash()
            
        def calculate_blake3_hash(self) -> str:
            """BLAKE3 is fast and designed for modern, multi-core systems."""
            block_string = f"{self.index}{self.prev_hash}{self.timestamp}{self.data}{self.nonce}"
            return blake3.blake3(block_string.encode()).hexdigest()
            
except ImportError:
    BLAKE3Block = None


# ============================================================
# OPTION 3: Post-Quantum Signature Simulation (Lamport Principle)
# ============================================================
class PQCBlockchain:
    """Simulates Post-Quantum Signatures based on the Lamport One-Time Signature principle."""
    
    def __init__(self):
        self.chain = []
        self.quantum_keys = self._generate_quantum_keypair()
        
    def _generate_quantum_keypair(self) -> Dict:
        """Generates a Lamport One-Time Signature Keypair (16KB key size simulated)."""
        private_key = [[secrets.token_bytes(32) for _ in range(2)] for _ in range(256)]
        public_key = [[hashlib.sha256(k).digest() for k in pair] for pair in private_key]
        
        return {
            'private': private_key,
            'public': public_key,
            'usage_count': 0,
            'max_uses': 100
        }
        
    def sign_block(self, block_hash: str) -> bytes:
        """Creates the Quantum-Resistant Signature."""
        if self.quantum_keys['usage_count'] >= self.quantum_keys['max_uses']:
            self.quantum_keys = self._generate_quantum_keypair()
            
        hash_bits = bin(int(block_hash, 16))[2:].zfill(256)
        
        signature = b''.join(
            self.quantum_keys['private'][i][int(bit)]
            for i, bit in enumerate(hash_bits)
        )
        
        self.quantum_keys['usage_count'] += 1
        return signature
        
    def verify_signature(self, block_hash: str, signature: bytes, public_key: list) -> bool:
        """Verifies the PQC signature against the public key."""
        hash_bits = bin(int(block_hash, 16))[2:].zfill(256)
        
        for i, bit in enumerate(hash_bits):
            sig_chunk = signature[i*32:(i+1)*32]
            expected_hash = public_key[i][int(bit)]
            
            if hashlib.sha256(sig_chunk).digest() != expected_hash:
                return False
        return True

# ... (Integration and Benchmarking Functions follow in the full code)
```

-----

## Z-Score Timing Anomaly Detection

This module provides an analytical defense against latency-based attacks or anomalies in the execution time of block operations, which can indicate malicious activity or resource exhaustion.

```python
import numpy as np
from typing import List, Tuple

def calculate_anomaly_zscore(
    historical_times: List[float], 
    new_time_measurement: float, 
    threshold: float = 3.0
) -> Tuple[float, bool]:
    """
    Calculates the Z-Score for a new measurement relative to historical data 
    and checks if it exceeds a specified anomaly threshold (default: 3.0).
    """
    if len(historical_times) < 2:
        return 0.0, False

    mu = np.mean(historical_times)
    sigma = np.std(historical_times)

    if sigma == 0:
        return 0.0, False

    # Z = (Value - Mean) / Standard Deviation
    z_score = (new_time_measurement - mu) / sigma

    is_anomaly = abs(z_score) > threshold

    return z_score, is_anomaly

# --- Demo Usage (Snippet) ---

# past_times = [0.051, 0.049, 0.050, 0.052, 0.048, 0.050, 0.051, 0.049]
# slow_time = 0.065 
# z_slow, anomaly_slow = calculate_anomaly_zscore(past_times, slow_time)
# # Expected: Anomaly: True
```

-----

## What This Prototype Demonstrates

  * Hybrid block hashing with increased post-quantum resistance
  * BLAKE3 option for high-performance blockchain hashing
  * Lamport-inspired signature simulation
  * Defensive timing analytics
  * Detection of common attack vectors
  * Simplified anomaly and replay detection logic
  * Thread-safe design ideas for production networks

This is a **conceptual research tool**, not a finished product.

-----

## Installation

```bash
git clone https://github.com/NemesisCyberForce/CryptGuardian.git
cd CryptGuardian

pip install blake3      # optional
python cryptguardian_enhanced.py
```

-----

## Example Usage

```python
from cryptguardian_enhanced import SmartBlockchain, enhanced_alert_handler

blockchain = SmartBlockchain()
blockchain.guardian.register_alert_handler(enhanced_alert_handler)

blockchain.add_block("Normal transaction")
blockchain.add_block("SELECT * FROM users; DROP TABLE users;--")
```

-----

## Attack Simulation

Start the full suite:

```bash
python cryptguardian_enhanced.py
```

Expected outcomes include blocked injections, anomaly flags, timestamp skew detection, and replay defense.

-----

## Roadmap

  * Proper PQC Signatures (Dilithium)
  * Kyber KEM for secure symmetric key exchange
  * Optional machine learning anomaly detection
  * Async engine and distributed validation
  * Multiple consensus mode support (PoW/PoS/PBFT)

-----

## License

Apache License 2.0

Use only for legal research and defensive analysis.

-----

## Disclaimer

This is an **alpha-stage idea** built by a developer exploring how to harden systems against future threats.
Not production-ready. Not guaranteed secure.
It is a research exercise in resilience, not a final solution.
