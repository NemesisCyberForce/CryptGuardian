import hashlib
import time
import secrets
import json
import threading
from typing import Callable, Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import re

# Alert Severity Levels
class AlertSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ThreatType(Enum):
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    PATTERN_ANOMALY = "PATTERN_ANOMALY"
    TIMING_ATTACK = "TIMING_ATTACK"
    DATA_MANIPULATION = "DATA_MANIPULATION"
    HASH_COLLISION = "HASH_COLLISION"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    DDOS_PATTERN = "DDOS_PATTERN"

@dataclass
class Alert:
    severity: AlertSeverity
    threat_type: ThreatType
    message: str
    block_index: int
    timestamp: float
    details: Dict
    risk_score: float
    mitigation_suggestions: List[str]

class SecurityException(Exception):
    def __init__(self, message: str, threat_type: ThreatType, risk_score: float = 1.0):
        super().__init__(message)
        self.threat_type = threat_type
        self.risk_score = risk_score

class ThreatIntelligence:
    def __init__(self):
        self.known_threats = {
            'sql_injection': [r'union\s+select', r'drop\s+table', r'exec\s*\(', r'script\s*>'],
            'xss_patterns': [r'<script.*?>', r'javascript:', r'onload\s*=', r'onerror\s*='],
            'command_injection': [r';\s*rm\s+-rf', r'&&\s*cat', r'\|\s*nc\s+', r'`.*`'],
            'buffer_overflow': [r'A{50,}', r'\\x90{10,}', r'shellcode'],
            'crypto_attacks': [r'rainbow\s+table', r'dictionary\s+attack', r'brute.*force']
        }
        
        self.reputation_db = defaultdict(int)  # IP/Hash reputation scoring
        
    def analyze_threat_patterns(self, data: str) -> Dict[str, float]:
        threats = {}
        data_lower = data.lower()
        
        for threat_category, patterns in self.known_threats.items():
            score = 0.0
            for pattern in patterns:
                matches = len(re.findall(pattern, data_lower, re.IGNORECASE))
                score += matches * 0.3
            threats[threat_category] = min(score, 1.0)
            
        return threats

class ChainGuardian:
    def __init__(self):
        self.alert_handlers: List[Callable] = []
        self.pattern_memory: Dict = {}
        self.suspicious_patterns: List[str] = []
        self.quarantine_blocks: List = []
        self.threat_intel = ThreatIntelligence()
        self.block_timing_window = deque(maxlen=100)
        self.consensus_validators = set()
        self._lock = threading.Lock()
        
        # Advanced detection parameters
        self.max_block_time_variance = 60.0  # seconds
        self.similarity_threshold = 0.85
        self.burst_detection_window = 10
        
    def register_alert_handler(self, handler: Callable):
        with self._lock:
            self.alert_handlers.append(handler)
        
    def register_validator(self, validator_id: str):
        self.consensus_validators.add(validator_id)
        
    def advanced_block_analysis(self, block: 'Block', blockchain: 'SmartBlockchain') -> Dict:
        analysis_results = {
            'integrity_check': True,
            'threat_patterns': {},
            'timing_analysis': {},
            'consensus_score': 0.0,
            'overall_risk': 0.0,
            'recommended_action': 'ACCEPT'
        }
        
        # 1. Integrity Deep Scan
        if not self._deep_integrity_check(block, blockchain):
            analysis_results['integrity_check'] = False
            analysis_results['overall_risk'] = 1.0
            self._raise_advanced_alert(
                AlertSeverity.CRITICAL,
                ThreatType.INTEGRITY_VIOLATION,
                "Deep integrity violation detected",
                block.index,
                {"hash_mismatch": True}
            )
            
        # 2. Threat Intelligence Analysis
        threat_patterns = self.threat_intel.analyze_threat_patterns(block.data)
        analysis_results['threat_patterns'] = threat_patterns
        max_threat_score = max(threat_patterns.values()) if threat_patterns else 0.0
        
        # 3. Advanced Timing Analysis
        timing_risk = self._analyze_block_timing(block)
        analysis_results['timing_analysis'] = timing_risk
        
        # 4. Data Similarity Analysis
        similarity_risk = self._analyze_data_similarity(block, blockchain)
        
        # 5. Calculate overall risk
        risk_factors = [max_threat_score, timing_risk.get('risk_score', 0), similarity_risk]
        analysis_results['overall_risk'] = max(risk_factors)
        
        # 6. Determine action
        if analysis_results['overall_risk'] > 0.8:
            analysis_results['recommended_action'] = 'QUARANTINE'
            self.quarantine_blocks.append(block)
        elif analysis_results['overall_risk'] > 0.5:
            analysis_results['recommended_action'] = 'MONITOR'
            
        return analysis_results
        
    def _deep_integrity_check(self, block: 'Block', blockchain: 'SmartBlockchain') -> bool:
        """Enhanced integrity checking with crypto validation"""
        if block.index == 0:
            return True
            
        prev_block = blockchain.chain[block.index - 1]
        
        # Standard hash chain validation
        if block.prev_hash != prev_block.hash:
            return False
            
        # Recalculate hash to detect tampering
        if block.hash != block.calculate_hash():
            return False
            
        # Timestamp validation
        if block.timestamp <= prev_block.timestamp:
            self._raise_advanced_alert(
                AlertSeverity.HIGH,
                ThreatType.TIMING_ATTACK,
                "Timestamp manipulation detected",
                block.index,
                {"timestamp_violation": True}
            )
            return False
            
        return True
        
    def _analyze_block_timing(self, block: 'Block') -> Dict:
        """Detect timing-based attacks and anomalies"""
        self.block_timing_window.append(block.timestamp)
        
        if len(self.block_timing_window) < 2:
            return {"risk_score": 0.0}
            
        # Calculate timing statistics
        intervals = []
        for i in range(1, len(self.block_timing_window)):
            intervals.append(self.block_timing_window[i] - self.block_timing_window[i-1])
            
        avg_interval = sum(intervals) / len(intervals)
        current_interval = intervals[-1] if intervals else 0
        
        timing_analysis = {
            "average_interval": avg_interval,
            "current_interval": current_interval,
            "variance": abs(current_interval - avg_interval),
            "risk_score": 0.0
        }
        
        # Detect timing anomalies
        if abs(current_interval - avg_interval) > self.max_block_time_variance:
            timing_analysis["risk_score"] = 0.7
            self._raise_advanced_alert(
                AlertSeverity.MEDIUM,
                ThreatType.TIMING_ATTACK,
                f"Block timing anomaly detected: {current_interval:.2f}s vs avg {avg_interval:.2f}s",
                block.index,
                timing_analysis
            )
            
        # Detect burst patterns (potential DDoS)
        recent_blocks = list(self.block_timing_window)[-self.burst_detection_window:]
        if len(recent_blocks) >= self.burst_detection_window:
            if all(recent_blocks[i+1] - recent_blocks[i] < 1.0 for i in range(len(recent_blocks)-1)):
                timing_analysis["risk_score"] = max(timing_analysis["risk_score"], 0.8)
                self._raise_advanced_alert(
                    AlertSeverity.HIGH,
                    ThreatType.DDOS_PATTERN,
                    "Potential DDoS pattern detected in block timing",
                    block.index,
                    {"burst_detected": True}
                )
        
        return timing_analysis
        
    def _analyze_data_similarity(self, block: 'Block', blockchain: 'SmartBlockchain') -> float:
        """Detect data manipulation and replay attacks"""
        if len(blockchain.chain) < 2:
            return 0.0
            
        # Check for exact duplicates (replay attacks)
        for existing_block in blockchain.chain[:-1]:  # Exclude current block
            if existing_block.data == block.data:
                self._raise_advanced_alert(
                    AlertSeverity.HIGH,
                    ThreatType.REPLAY_ATTACK,
                    "Potential replay attack: identical block data detected",
                    block.index,
                    {"duplicate_of_block": existing_block.index}
                )
                return 0.9
                
        # Fuzzy similarity check for near-duplicates
        recent_blocks = blockchain.chain[-10:]  # Check last 10 blocks
        max_similarity = 0.0
        
        for existing_block in recent_blocks:
            similarity = self._calculate_similarity(block.data, existing_block.data)
            max_similarity = max(max_similarity, similarity)
            
            if similarity > self.similarity_threshold:
                self._raise_advanced_alert(
                    AlertSeverity.MEDIUM,
                    ThreatType.DATA_MANIPULATION,
                    f"High data similarity detected: {similarity:.2%}",
                    block.index,
                    {"similar_to_block": existing_block.index, "similarity": similarity}
                )
                
        return max_similarity
        
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Simple Jaccard similarity for text comparison"""
        set1 = set(text1.lower().split())
        set2 = set(text2.lower().split())
        
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
            
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
        
    def _raise_advanced_alert(self, severity: AlertSeverity, threat_type: ThreatType, 
                            message: str, block_index: int, details: Dict):
        """Enhanced alert system with threat intelligence"""
        
        # Generate mitigation suggestions based on threat type
        mitigations = self._get_mitigation_suggestions(threat_type)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity, threat_type, details)
        
        alert = Alert(
            severity=severity,
            threat_type=threat_type,
            message=message,
            block_index=block_index,
            timestamp=time.time(),
            details=details,
            risk_score=risk_score,
            mitigation_suggestions=mitigations
        )
        
        # Notify all handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                print(f"Alert handler failed: {e}")
                
        # Raise exception for critical threats
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            raise SecurityException(message, threat_type, risk_score)
            
    def _get_mitigation_suggestions(self, threat_type: ThreatType) -> List[str]:
        """Provide threat-specific mitigation suggestions"""
        suggestions = {
            ThreatType.INTEGRITY_VIOLATION: [
                "Verify block hash calculations",
                "Check for network tampering",
                "Validate previous block references"
            ],
            ThreatType.TIMING_ATTACK: [
                "Implement rate limiting",
                "Monitor network synchronization",
                "Check for clock skew issues"
            ],
            ThreatType.REPLAY_ATTACK: [
                "Implement nonce verification",
                "Add timestamp validation windows",
                "Use unique transaction identifiers"
            ],
            ThreatType.DDOS_PATTERN: [
                "Enable DDoS protection",
                "Implement connection throttling",
                "Monitor resource usage"
            ]
        }
        return suggestions.get(threat_type, ["Contact security team", "Review logs"])
        
    def _calculate_risk_score(self, severity: AlertSeverity, threat_type: ThreatType, details: Dict) -> float:
        """Calculate numerical risk score for prioritization"""
        base_scores = {
            AlertSeverity.LOW: 0.2,
            AlertSeverity.MEDIUM: 0.5,
            AlertSeverity.HIGH: 0.8,
            AlertSeverity.CRITICAL: 1.0
        }
        
        threat_multipliers = {
            ThreatType.INTEGRITY_VIOLATION: 1.2,
            ThreatType.REPLAY_ATTACK: 1.1,
            ThreatType.DDOS_PATTERN: 1.0,
            ThreatType.TIMING_ATTACK: 0.9
        }
        
        base_score = base_scores.get(severity, 0.5)
        multiplier = threat_multipliers.get(threat_type, 1.0)
        
        return min(base_score * multiplier, 1.0)

class Block:
    def __init__(self, index: int, prev_hash: str, timestamp: float, data: str, nonce: str = None):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce or secrets.token_hex(16)
        self.hash = self.calculate_hash()
        self.validation_score = 0.0
        self.metadata = {}
        
    def calculate_hash(self) -> str:
        block_string = f"{self.index}{self.prev_hash}{self.timestamp}{self.data}{self.nonce}"
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()
        
    def to_dict(self) -> Dict:
        return {
            'index': self.index,
            'prev_hash': self.prev_hash,
            'timestamp': self.timestamp,
            'data': self.data,
            'nonce': self.nonce,
            'hash': self.hash,
            'validation_score': self.validation_score,
            'metadata': self.metadata
        }

class SmartBlockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.guardian = ChainGuardian()
        self.create_genesis_block()
        self._stats = {
            'blocks_created': 0,
            'threats_detected': 0,
            'blocks_quarantined': 0
        }
        
    def create_genesis_block(self):
        genesis_block = Block(0, "0", time.time(), "Genesis Block - CryptGuardian Initialized")
        self.chain.append(genesis_block)
        
    def add_block(self, data: str, force: bool = False) -> bool:
        """Add block with advanced security analysis"""
        try:
            # Basic chain validation
            if not self.is_chain_valid():
                self.guardian._raise_advanced_alert(
                    AlertSeverity.CRITICAL,
                    ThreatType.INTEGRITY_VIOLATION,
                    "Blockchain integrity violation detected before block addition!",
                    len(self.chain),
                    {"chain_valid": False}
                )
                
            prev_block = self.chain[-1]
            new_block = Block(
                index=len(self.chain),
                prev_hash=prev_block.hash,
                timestamp=time.time(),
                data=data
            )
            
            # Advanced security analysis
            if not force:
                analysis = self.guardian.advanced_block_analysis(new_block, self)
                
                if analysis['recommended_action'] == 'QUARANTINE':
                    self._stats['blocks_quarantined'] += 1
                    return False
                    
                new_block.validation_score = 1.0 - analysis['overall_risk']
                new_block.metadata['security_analysis'] = analysis
            
            self.chain.append(new_block)
            self._stats['blocks_created'] += 1
            return True
            
        except SecurityException as e:
            self._stats['threats_detected'] += 1
            if not force:
                print(f"🚨 Security Exception: {e}")
                return False
            else:
                print(f"⚠️ Forced addition despite security concerns: {e}")
                self.chain.append(new_block)
                return True
        
    def is_chain_valid(self) -> bool:
        """Comprehensive chain validation"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Hash chain validation
            if current.prev_hash != previous.hash:
                return False
            if current.hash != current.calculate_hash():
                return False
            # Temporal validation    
            if current.timestamp <= previous.timestamp:
                return False
                
        return True
        
    def get_security_report(self) -> Dict:
        """Generate comprehensive security report"""
        return {
            'chain_length': len(self.chain),
            'chain_valid': self.is_chain_valid(),
            'quarantined_blocks': len(self.guardian.quarantine_blocks),
            'statistics': self._stats,
            'threat_patterns': self.guardian.threat_intel.known_threats,
            'validators_registered': len(self.guardian.consensus_validators)
        }

# Advanced Alert Handler with logging
def enhanced_alert_handler(alert: Alert):
    severity_colors = {
        AlertSeverity.LOW: "🟢",
        AlertSeverity.MEDIUM: "🟡", 
        AlertSeverity.HIGH: "🟠",
        AlertSeverity.CRITICAL: "🔴"
    }
    
    color = severity_colors.get(alert.severity, "⚪")
    
    print(f"\n{color} SECURITY ALERT [{alert.severity.value}] - {alert.threat_type.value}")
    print(f"Block #{alert.block_index}: {alert.message}")
    print(f"Risk Score: {alert.risk_score:.2f}")
    
    if alert.details:
        print("Details:")
        for key, value in alert.details.items():
            print(f"  {key}: {value}")
    
    if alert.mitigation_suggestions:
        print("Suggested Actions:")
        for suggestion in alert.mitigation_suggestions:
            print(f"  • {suggestion}")
    print("-" * 60)

# Demo Usage
if __name__ == "__main__":
    print("🛡️ Initializing Enhanced CryptGuardian Blockchain...\n")
    
    # Initialize blockchain with advanced security
    blockchain = SmartBlockchain()
    blockchain.guardian.register_alert_handler(enhanced_alert_handler)
    blockchain.guardian.register_validator("validator_001")
    
    # Test scenarios
    test_cases = [
        "Normal transaction #1",
        "User payment to merchant",
        "SELECT * FROM users; DROP TABLE users;--",  # SQL injection
        "<script>alert('xss')</script>",  # XSS attempt
        "rm -rf / && cat /etc/passwd",  # Command injection
        "Normal transaction #2",
        "Normal transaction #2",  # Duplicate (replay attack)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # Buffer overflow pattern
    ]
    
    print("Testing various transaction patterns...\n")
    
    for i, data in enumerate(test_cases):
        try:
            success = blockchain.add_block(data)
            status = "✅ ACCEPTED" if success else "❌ REJECTED" 
            print(f"Transaction {i+1}: {status}")
            time.sleep(0.1)  # Small delay for realistic timing
            
        except Exception as e:
            print(f"Transaction {i+1}: ❌ BLOCKED - {e}")
    
    # Generate security report
    print(f"\n📊 SECURITY REPORT")
    print("=" * 60)
    report = blockchain.get_security_report()
    for key, value in report.items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    
    print(f"\n🔍 Chain Validation: {'✅ VALID' if blockchain.is_chain_valid() else '❌ INVALID'}")
