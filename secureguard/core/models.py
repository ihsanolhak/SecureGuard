from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Set
from datetime import datetime

class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AnalysisSource(Enum):
    """Tracks which analysis tool discovered a vulnerability."""
    STATIC_REGEX = "Static (Regex)"
    STATIC_AST = "Static (AST)"
    RUNTIME_SANDBOX = "Runtime (Sandbox)"
    VALGRIND = "Valgrind"
    ASAN = "AddressSanitizer"

class RiskRating(Enum):
    """Overall application security risk rating."""
    CRITICAL = "Critical Risk"
    HIGH = "High Risk"
    MEDIUM = "Medium Risk"
    LOW = "Low Risk"
    MINIMAL = "Minimal Risk"

@dataclass
class Vulnerability:
    id: str
    severity: Severity
    vuln_type: str
    file_path: str
    line_number: int
    description: str
    recommendation: str
    source: AnalysisSource = AnalysisSource.STATIC_REGEX
    cwe_id: Optional[str] = None
    stride_category: Optional[str] = None
    correlated_id: Optional[str] = None  # Links to CorrelatedFinding

@dataclass
class VulnerabilityProfile:
    name: str
    severity: Severity
    description: str
    technical_explanation: str
    attack_scenario: str
    remediation_guidance: str
    secure_alternative: str
    cwe_mapping: str
    stride_mapping: str
    secure_coding_example: str

@dataclass
class ScanResult:
    scan_id: str
    timestamp: datetime
    files_scanned: int
    vulnerabilities: List[Vulnerability]
    risk_score: float

@dataclass
class LogEntry:
    timestamp: datetime
    severity: str
    event: str
    previous_hash: str
    current_hash: str

@dataclass
class RiskScore:
    """Aggregated risk metrics for a finding or application."""
    overall_security_score: float  # 0-100 (higher = more secure)
    exploitability_score: float  # 0-100 (higher = more exploitable)
    confidence_score: float  # 0-100 (higher = more confident)
    criticality_score: float  # 0-100 (higher = more critical)
    risk_rating: RiskRating

@dataclass
class CorrelatedFinding:
    """Groups related vulnerabilities from multiple analysis sources."""
    id: str
    timestamp: datetime
    primary_file: str
    primary_line: int
    vuln_type: str
    severity: Severity
    finding_sources: Set[AnalysisSource] = field(default_factory=set)
    related_vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    is_exploitable: bool = False
    exploitation_chain: List[str] = field(default_factory=list)  # Steps to exploit
    confidence_description: str = ""
    cwe_ids: Set[str] = field(default_factory=set)
    stride_categories: Set[str] = field(default_factory=set)
    remediation_priority: str = "Medium"  # Low, Medium, High, Critical
    
@dataclass
class AnalysisSessionMetrics:
    """Aggregated metrics from an analysis session."""
    session_id: str
    timestamp: datetime
    total_findings: int
    correlated_findings: int
    unique_vulnerabilities: int
    risk_score: Optional[RiskScore] = None
    highest_severity: Optional[Severity] = None
    analysis_sources_used: Set[AnalysisSource] = field(default_factory=set)

