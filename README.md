# CryptGuardian
#### Advanced Blockchain Security Module & Quantum-Hardened Ledger
an idea

**Version:** **v0.3-alpha (Quantum Leap)**

**Copyright:** 2025 NemesisCyberForce (Volkan Sah)

-----

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

-----

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

-----

### Roadmap v0.3+

  * **PQC Signature Integration:** Move PQC Signature simulation (Lamport/Dilithium principles) into a production-ready module.
  * **Machine Learning Integration:** Unsupervised anomaly detection for adaptive threat signature learning.
  * **Advanced Consensus:** Support for PoW, PoS, and PBFT validation standards.
  * **Performance Optimizations:** Async processing and distributed validation.

-----

### License & Legal

Licensed under the Apache License, Version 2.0

#### ADDITIONAL TERMS:

  * This software is intended for legitimate security research and defensive purposes only. Users must comply with all applicable laws and regulations. **Malicious use is strictly prohibited.**

**Copyright:** [Volkan Sah//NCF](https://github.com/volkansah)

**Disclaimer:** This is **alpha-stage software** under active development. While designed with production-grade security principles, thorough testing is recommended before deployment in critical environments.
