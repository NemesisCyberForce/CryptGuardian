# CryptGuardian
#### Advanced Blockchain Security Module & Quantum-Hardened Ledger
###### an idea
CryptGuardian is a consideration for optimizing defenses. We view security as an ongoing process because, in the face of new technologies like AI and quantum computers, there is **no unbreakable encryption**. Our goal is to make compromise as unlikely, difficult, and costly as possible.


**Version:** **v0.3-alpha (Quantum Leap)**
> **Copyright:** 2025 NCF (Volkan Sah)

### Overview


> "No encryption is unbreakable—especially when new threats, catalyzed by **fast-paced AI development and the looming reality of quantum computing**, emerge faster than our defenses. This challenge—the ever-accelerating pace of digital compromise—drove the creation of CryptGuardian. Why just patch, when you can monitor and secure your ledger with something truly resilient?"

CryptGuardian is an advanced blockchain security module designed to **detect, analyze, and mitigate threats in real-time**. It integrates robust threat intelligence, statistical anomaly detection, and **Post-Quantum Cryptography (PQC) hardening**, making it a future-proof tool for monitoring and securing blockchain data integrity.

This module is **thread-safe**, built to automatically test and block suspicious or malicious patterns, and offers **configurable cryptographic resilience**.

-----

### What's New in v0.3-alpha (The Quantum Leap)

#### 1\. Quantum-Resistant Cryptography (PQC Hardening)

The core `Block` structure has been refactored to provide resilience against classical and potential quantum attacks (Grover's and Shor's algorithms).

  * **Hybrid Hashing (Default):** Implements a double-round, multi-algorithm hash chain: **SHA-256 $\rightarrow$ SHA3-512 $\rightarrow$ SHA-256** finalization.
  * **BLAKE3 Integration (Optional):** Supports the state-of-the-art **BLAKE3** hash function for superior speed and PQC resistance (requires `pip install blake3`).
  * **Extended Nonces:** Nonce size doubled from 16 to **32 bytes** to increase complexity against brute-force attacks.

#### 2\. Statistical Timing Attack Detection (Z-Score)

The legacy variance check has been replaced with a more precise statistical method for improved detection of network manipulation.

  * **Z-Score Anomaly Detection:** Uses **Z-Scores** (Standard Deviations) to measure block interval times, immediately flagging any statistically significant deviation (e.g., $Z \ge 3.0$) which suggests network manipulation or sophisticated **timing attacks**.
  * **Burst Pattern Recognition:** Enhanced detection for potential DDoS attacks by monitoring bursts of extremely fast block production.

#### 3\. Advanced Threat Intelligence Engine (Enhanced)

  * **Multi-vector attack detection:** Improved pattern recognition for threats including SQL Injection, XSS, Command Injection, and Buffer Overflow.
  * **Similarity Analysis:** Improved **Jaccard similarity** to catch replay attacks and near-duplicate transactions.

#### 4\. Deep Security Analysis Framework (Enhanced)

  * Multi-layer block validation ensuring integrity across the entire chain structure.
  * Quarantine System with automatic risk-based threat isolation.

-----

### Core Features

| Feature Area | Key Capabilities |
| :--- | :--- |
| **PQC Resistance** | Hybrid Hashing (SHA256+SHA3), Optional BLAKE3, 32-Byte Nonces. |
| **Timing Analysis** | Z-Score Statistical Anomaly Detection, DDoS Burst Recognition, Temporal Validation. |
| **Threat Detection** | Recognizes and blocks 15+ common attack vectors (SQLi, XSS, Buffer Overflow). |
| **Replay Prevention** | Jaccard similarity analysis, Nonce uniqueness enforcement. |
| **Architecture** | **Thread-Safe**, Lock-based synchronization, Production-ready. |
| **Alerting** | Multi-level (LOW/MEDIUM/HIGH/CRITICAL), Detailed Risk Scoring, Mitigation Suggestions. |

-----

### Technical Requirements

**Dependencies:** None - Pure Python 3.7+ (uses only standard library modules).

**Optional Dependency (Recommended for Performance):** `blake3`

**Built-in modules used:**

```python
hashlib, time, secrets, json, threading, typing, dataclasses, enum, collections, re, statistics
```

### Quick Start

#### Installation

```bash
# Clone the repository
git clone [https://github.com/NemesisCyberForce/CryptGuardian.git](https://github.com/NemesisCyberForce/CryptGuardian.git)
cd CryptGuardian

# OPTIONAL: Install BLAKE3 for superior PQC performance
pip install blake3

# Run the demo
python cryptguardian_enhanced.py 
```

#### Basic Usage

```python
from cryptguardian_enhanced import SmartBlockchain, enhanced_alert_handler

# Initialize blockchain (automatically selects BLAKE3 or Hybrid hashing)
blockchain = SmartBlockchain()
blockchain.guardian.register_alert_handler(enhanced_alert_handler)

print(f"Current Hashing Scheme: {blockchain.BLOCK_CLASS.__name__}")

# Test scenarios including a malicious transaction
blockchain.add_block("Normal transaction #1")
blockchain.add_block("SELECT * FROM users; DROP TABLE users;--") # Blocked!

# Generate comprehensive security report
report = blockchain.get_security_report()
print(f"Security Status: {report}")
```

### Z-Score Anomaly Detection
```

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

    Args:
        historical_times: List of past process execution times (e.g., block signing).
        new_time_measurement: The current time measurement to evaluate.
        threshold: The Z-Score threshold for flagging an anomaly (e.g., 3.0 for 99.7% confidence).

    Returns:
        A tuple containing (Z-Score, Is_Anomaly_Flag).
    """
    if len(historical_times) < 2:
        # Not enough data to calculate variance reliably
        return 0.0, False

    # 1. Calculate Mean (mu)
    mu = np.mean(historical_times)

    # 2. Calculate Standard Deviation (sigma)
    sigma = np.std(historical_times)

    # Avoid division by zero if all times are identical (unlikely in real world)
    if sigma == 0:
        return 0.0, False

    # 3. Calculate the Z-Score (Z)
    # Z = (Value - Mean) / Standard Deviation
    z_score = (new_time_measurement - mu) / sigma

    # 4. Check for Anomaly
    is_anomaly = abs(z_score) > threshold

    return z_score, is_anomaly

# --- Demo Usage ---

# Simulate historical times (e.g., signature times in seconds)
# The time is normally around 0.05 seconds.
past_times = [0.051, 0.049, 0.050, 0.052, 0.048, 0.050, 0.051, 0.049]

# A) Normal, expected measurement
normal_time = 0.0505
z_norm, anomaly_norm = calculate_anomaly_zscore(past_times, normal_time)

# B) Deviant measurement (too slow - possible attack/resource shortage)
slow_time = 0.065 # Significantly slower
z_slow, anomaly_slow = calculate_anomaly_zscore(past_times, slow_time)

# C) Extremely fast measurement (very unlikely for real work, but detectable)
fast_time = 0.040 
z_fast, anomaly_fast = calculate_anomaly_zscore(past_times, fast_time)


# Output
print(f"Historical Mean Time: {np.mean(past_times):.4f}s, Standard Deviation: {np.std(past_times):.4f}s")
print("-" * 50)
print(f"Measurement A ({normal_time:.4f}s): Z-Score={z_norm:.2f}, Anomaly: {anomaly_norm}")
print(f"Measurement B ({slow_time:.4f}s): Z-Score={z_slow:.2f}, Anomaly: {anomaly_slow} <-- Slow Timing Anomaly!")
print(f"Measurement C ({fast_time:.4f}s): Z-Score={z_fast:.2f}, Anomaly: {anomaly_fast}")

```
### Demo & Attack Simulation

The module includes automated test scenarios that simulate real-world attacks, including: SQL Injection, XSS payloads, Command Injection, Buffer Overflow, and Replay/Timing Anomalies.

**Run comprehensive security testing:**

```bash
python cryptguardian_enhanced.py
```

**Expected Security Outcome:**

| Attack Vector | Detection Method | Status | Severity |
| :--- | :--- | :--- | :--- |
| SQL Injection | Regex Pattern Match | **BLOCKED** | CRITICAL |
| Replay Attack | Similarity Analysis | **INTERCEPTED** | HIGH |
| Timestamp Skew | **Z-Score** Analysis | **LOGGED** | HIGH |
| DDoS Burst | Sliding Window | **MONITORED** | HIGH |
| Buffer Overflow | A-Pattern Detection | **QUARANTINED** | MEDIUM |

-----

### Advanced Configuration

#### Cryptography Configuration (PQC)

The default block type is selected based on `blake3` availability. You can explicitly override it:

```python
from cryptguardian_enhanced import SmartBlockchain, LegacyBlock, HybridBlock, BLAKE3Block

# Force use of Hybrid Hashing (PQC without external dependencies)
hybrid_chain = SmartBlockchain(block_class=HybridBlock)

# Force use of Legacy SHA-256 (for comparison/testing)
legacy_chain = SmartBlockchain(block_class=LegacyBlock) 
```

#### Custom Threat Patterns & Alert Handling

*(The configuration examples remain valid from your previous README.)*



### Roadmap v0.3+

  * **PQC Signature Integration:** Move PQC Signature simulation (Lamport/Dilithium principles) into a production-ready module.
  * **Hybrid Key Exchange (Kyber KEM):** Integrate the **CRYSTALS-Kyber** Key Encapsulation Mechanism (KEM) to secure AES key exchange, making the final data encryption quantum-resistant.
  * **Machine Learning Integration:** Unsupervised anomaly detection for adaptive threat signature learning.
  * **Advanced Consensus:** Support for PoW, PoS, and PBFT validation standards.
  * **Performance Optimizations:** Async processing and distributed validation.





### License & Legal

Licensed under the Apache License, Version 2.0

#### ADDITIONAL TERMS:

  * This software is intended for legitimate security research and defensive purposes only. Users must comply with all applicable laws and regulations. **Malicious use is strictly prohibited.**

**Copyright:** [Volkan Sah//NCF](https://github.com/volkansah)

**Disclaimer:** This is **alpha-stage software** under active development. While designed with production-grade security principles, thorough testing is recommended before deployment in critical environments.
