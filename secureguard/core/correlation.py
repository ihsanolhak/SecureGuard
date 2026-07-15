"""
Risk Correlation Engine - Combines findings from multiple analysis sources
and generates comprehensive risk assessment metrics.
"""

from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from difflib import SequenceMatcher
from enum import Enum
import uuid

from .models import (
    Vulnerability, CorrelatedFinding, RiskScore, RiskRating, 
    Severity, AnalysisSource, AnalysisSessionMetrics
)
from .frameworks import SecurityFrameworkMapper

class ExploitabilityCalculator:
    """Calculates exploitability scores based on vulnerability characteristics."""
    
    # High exploitability vulnerability patterns
    HIGH_EXPLOITABILITY_PATTERNS = {
        "buffer overflow": 0.95,
        "stack overflow": 0.90,
        "heap overflow": 0.88,
        "format string": 0.92,
        "use-after-free": 0.85,
        "double free": 0.80,
        "command injection": 0.90,
        "gets()": 0.95,
        "strcpy()": 0.90,
        "strcat()": 0.88,
        "sprintf()": 0.88,
        "system()": 0.85,
    }
    
    # Factors that increase exploitability
    NETWORK_ACCESSIBLE_FACTOR = 1.15  # Network-accessible = more exploitable
    PRIVESC_FACTOR = 1.20  # Can lead to privilege escalation
    RCE_FACTOR = 1.25  # Remote code execution
    
    @staticmethod
    def calculate_exploitability(vuln: Vulnerability, is_runtime_confirmed: bool) -> float:
        """
        Calculate exploitability score (0-100).
        
        Args:
            vuln: Vulnerability object
            is_runtime_confirmed: Whether runtime analysis confirmed the vulnerability
            
        Returns:
            Exploitability score 0-100
        """
        base_score = 50.0  # Default middle score
        
        # Check for high exploitability patterns
        vuln_lower = vuln.vuln_type.lower() + " " + vuln.description.lower()
        for pattern, score in ExploitabilityCalculator.HIGH_EXPLOITABILITY_PATTERNS.items():
            if pattern in vuln_lower:
                base_score = score * 100
                break
        
        # Boost score if runtime analysis confirmed it
        if is_runtime_confirmed:
            base_score = min(100, base_score * 1.2)
        
        # Apply modifiers based on severity
        if vuln.severity == Severity.CRITICAL:
            base_score = min(100, base_score * 1.15)
        elif vuln.severity == Severity.HIGH:
            base_score = min(100, base_score * 1.05)
        
        return min(100, base_score)

class ConfidenceCalculator:
    """Calculates confidence scores based on evidence from multiple sources."""
    
    # Confidence boost per source
    SOURCE_CONFIDENCE_BOOST = {
        AnalysisSource.STATIC_REGEX: 0.40,
        AnalysisSource.STATIC_AST: 0.50,  # AST is more accurate
        AnalysisSource.RUNTIME_SANDBOX: 0.90,  # Runtime is very high confidence
        AnalysisSource.VALGRIND: 0.95,  # Valgrind is extremely reliable
        AnalysisSource.ASAN: 0.98,  # ASan is the most reliable
    }
    
    @staticmethod
    def calculate_confidence(sources: Set[AnalysisSource]) -> float:
        """
        Calculate confidence score (0-100) based on number and type of sources.
        More sources = higher confidence.
        
        Args:
            sources: Set of AnalysisSource that found this vulnerability
            
        Returns:
            Confidence score 0-100
        """
        if not sources:
            return 0.0
        
        # Start with highest individual confidence
        max_confidence = max(
            ConfidenceCalculator.SOURCE_CONFIDENCE_BOOST.get(s, 0.3) 
            for s in sources
        )
        
        # Add bonus for additional sources (up to 100)
        bonus_per_source = 0.08
        additional_sources = len(sources) - 1
        confidence = max_confidence + (additional_sources * bonus_per_source)
        
        return min(100, confidence * 100)
    
    @staticmethod
    def get_confidence_description(score: float) -> str:
        """Get a human-readable confidence description."""
        if score >= 95:
            return "Extremely High (Confirmed by multiple analyses)"
        elif score >= 85:
            return "Very High (Multiple sources confirm)"
        elif score >= 70:
            return "High (Multiple sources detected)"
        elif score >= 50:
            return "Medium (2-3 analysis sources agree)"
        elif score >= 30:
            return "Low (Single analysis source or conflicting)"
        else:
            return "Very Low (Insufficient evidence)"


class CorrelationEngine:
    """
    Correlates findings from multiple analysis sources:
    - Static Analysis (Regex)
    - Static Analysis (AST)
    - Runtime Analysis (Sandbox)
    - Valgrind
    - AddressSanitizer
    
    Groups related findings, deduplicates, and identifies exploitation chains.
    """
    
    LOCATION_TOLERANCE = 5  # Lines within this range are considered same location
    SIMILARITY_THRESHOLD = 0.70  # String similarity threshold for correlation
    
    def __init__(self):
        self.mapper = SecurityFrameworkMapper()
        self.correlated_findings: Dict[str, CorrelatedFinding] = {}
    
    def correlate(self, vulnerabilities: List[Vulnerability]) -> List[CorrelatedFinding]:
        """
        Correlate vulnerabilities from multiple sources into groups.
        
        Args:
            vulnerabilities: List of findings from all analysis sources
            
        Returns:
            List of CorrelatedFinding objects
        """
        if not vulnerabilities:
            return []
        
        # Group vulnerabilities by location and type
        grouped = self._group_by_location_and_type(vulnerabilities)
        
        correlated_findings = []
        for group_id, group_vulns in grouped.items():
            correlated = self._create_correlated_finding(group_vulns)
            self.correlated_findings[correlated.id] = correlated
            correlated_findings.append(correlated)
        
        # Link exploitation chains
        self._identify_exploitation_chains(correlated_findings)
        
        return correlated_findings
    
    def _group_by_location_and_type(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by file, line, and type similarity."""
        groups: Dict[str, List[Vulnerability]] = {}
        
        for vuln in vulnerabilities:
            group_key = None
            
            # Try to match with existing group
            for existing_key, group_list in groups.items():
                if self._should_merge(vuln, group_list[0]):
                    group_key = existing_key
                    break
            
            # Create new group if no match found
            if group_key is None:
                group_key = str(len(groups))
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(vuln)
        
        return groups
    
    def _should_merge(self, vuln1: Vulnerability, vuln2: Vulnerability) -> bool:
        """Determine if two vulnerabilities should be merged."""
        # Same file and nearby lines
        if vuln1.file_path != vuln2.file_path:
            return False
        
        if abs(vuln1.line_number - vuln2.line_number) > self.LOCATION_TOLERANCE:
            return False
        
        # Similar vulnerability types
        similarity = SequenceMatcher(None, vuln1.vuln_type, vuln2.vuln_type).ratio()
        if similarity < self.SIMILARITY_THRESHOLD:
            # Allow merging if both are "unknown" type or similar patterns
            if vuln1.vuln_type.lower() == vuln2.vuln_type.lower():
                return True
            return False
        
        return True
    
    def _create_correlated_finding(self, vulnerabilities: List[Vulnerability]) -> CorrelatedFinding:
        """Create a CorrelatedFinding from a group of vulnerabilities."""
        # Primary finding is the most severe
        primary = max(vulnerabilities, key=lambda v: self._severity_value(v.severity))
        
        # Collect sources
        sources = {v.source for v in vulnerabilities}
        
        # Create finding
        correlated = CorrelatedFinding(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            primary_file=primary.file_path,
            primary_line=primary.line_number,
            vuln_type=primary.vuln_type,
            severity=primary.severity,
            finding_sources=sources,
            related_vulnerabilities=vulnerabilities,
        )
        
        # Update CWE and STRIDE from mapper
        cwe_ids, stride_cats = self.mapper.map_finding(primary.vuln_type)
        correlated.cwe_ids = set(cwe_ids)
        correlated.stride_categories = set(stride_cats)
        
        # Determine if runtime analysis confirms it
        has_runtime = any(s in sources for s in [
            AnalysisSource.RUNTIME_SANDBOX,
            AnalysisSource.VALGRIND,
            AnalysisSource.ASAN
        ])
        correlated.is_exploitable = has_runtime or primary.severity == Severity.CRITICAL
        
        return correlated
    
    def _identify_exploitation_chains(self, findings: List[CorrelatedFinding]):
        """Identify chains of vulnerabilities that could lead to exploit."""
        for finding in findings:
            chain = []
            
            # Buffer overflow + use-after-free = higher risk
            if any("buffer" in v.vuln_type.lower() or "overflow" in v.vuln_type.lower() for v in finding.related_vulnerabilities):
                chain.append("Buffer manipulation")
                
                if any("use-after-free" in v.vuln_type.lower() for v in finding.related_vulnerabilities):
                    chain.append("Memory reuse opportunity")
            
            # Command injection chains
            if any("command" in v.vuln_type.lower() or "system()" in v.vuln_type.lower() for v in finding.related_vulnerabilities):
                chain.append("Command execution")
            
            finding.exploitation_chain = chain
    
    @staticmethod
    def _severity_value(severity: Severity) -> int:
        """Convert severity to numeric value for sorting."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }.get(severity, 0)
    
    def deduplicate(self, findings: List[CorrelatedFinding]) -> List[CorrelatedFinding]:
        """Remove duplicate findings."""
        unique_findings = {}
        
        for finding in findings:
            key = (finding.primary_file, finding.primary_line, finding.vuln_type)
            if key not in unique_findings or \
               self._severity_value(finding.severity) > self._severity_value(unique_findings[key].severity):
                unique_findings[key] = finding
        
        return list(unique_findings.values())


class RiskAssessmentService:
    """
    Generates comprehensive risk assessment metrics for correlated findings
    and the overall application security posture.
    """
    
    def __init__(self):
        self.exploitability_calc = ExploitabilityCalculator()
        self.confidence_calc = ConfidenceCalculator()
    
    def assess_finding(self, finding: CorrelatedFinding) -> CorrelatedFinding:
        """Assess risk metrics for a single correlated finding."""
        # Calculate exploitability
        has_runtime = any(s in finding.finding_sources for s in [
            AnalysisSource.RUNTIME_SANDBOX,
            AnalysisSource.VALGRIND,
            AnalysisSource.ASAN
        ])
        exploitability = self.exploitability_calc.calculate_exploitability(
            finding.related_vulnerabilities[0],
            has_runtime
        )
        
        # Calculate confidence
        confidence = self.confidence_calc.calculate_confidence(finding.finding_sources)
        
        # Calculate criticality (based on severity + exploitability + confidence)
        criticality = self._calculate_criticality(
            finding.severity,
            exploitability,
            confidence
        )
        
        # Calculate overall security score (inverted: lower vulnerability = higher score)
        overall_security = 100 - (criticality * 0.6 + exploitability * 0.25 + (100 - confidence) * 0.15)
        
        # Determine risk rating
        risk_rating = self._determine_risk_rating(criticality, exploitability)
        
        # Determine remediation priority
        priority = self._determine_remediation_priority(criticality, exploitability, confidence)
        
        finding.risk_score = RiskScore(
            overall_security_score=max(0, overall_security),
            exploitability_score=exploitability,
            confidence_score=confidence,
            criticality_score=criticality,
            risk_rating=risk_rating,
        )
        
        finding.remediation_priority = priority
        finding.confidence_description = self.confidence_calc.get_confidence_description(confidence)
        
        return finding
    
    def assess_session(self, findings: List[CorrelatedFinding]) -> AnalysisSessionMetrics:
        """Assess overall risk metrics for an analysis session."""
        if not findings:
            return AnalysisSessionMetrics(
                session_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                total_findings=0,
                correlated_findings=0,
                unique_vulnerabilities=0,
            )
        
        # Count findings
        total_raw_findings = sum(len(f.related_vulnerabilities) for f in findings)
        unique_vulns = len(set(f.vuln_type for f in findings))
        
        # Collect all sources used
        all_sources = set()
        for finding in findings:
            all_sources.update(finding.finding_sources)
        
        # Get highest severity
        highest_severity = max(findings, key=lambda f: self._severity_value(f.severity)).severity
        
        # Calculate aggregate risk score
        avg_critical = sum(f.risk_score.criticality_score for f in findings if f.risk_score) / len(findings)
        avg_exploit = sum(f.risk_score.exploitability_score for f in findings if f.risk_score) / len(findings)
        avg_confidence = sum(f.risk_score.confidence_score for f in findings if f.risk_score) / len(findings)
        
        overall_security = 100 - (avg_critical * 0.6 + avg_exploit * 0.25 + (100 - avg_confidence) * 0.15)
        overall_rating = self._determine_risk_rating(avg_critical, avg_exploit)
        
        aggregate_score = RiskScore(
            overall_security_score=max(0, overall_security),
            exploitability_score=avg_exploit,
            confidence_score=avg_confidence,
            criticality_score=avg_critical,
            risk_rating=overall_rating,
        )
        
        return AnalysisSessionMetrics(
            session_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            total_findings=total_raw_findings,
            correlated_findings=len(findings),
            unique_vulnerabilities=unique_vulns,
            risk_score=aggregate_score,
            highest_severity=highest_severity,
            analysis_sources_used=all_sources,
        )
    
    def _calculate_criticality(self, severity: Severity, exploitability: float, confidence: float) -> float:
        """
        Calculate criticality score (0-100).
        Combines severity, exploitability, and confidence.
        """
        severity_base = {
            Severity.CRITICAL: 90,
            Severity.HIGH: 70,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
        }.get(severity, 25)
        
        # Criticality = severity + weighted exploitability/confidence
        criticality = (severity_base * 0.5) + (exploitability * 0.35) + (confidence * 0.15)
        return min(100, criticality)
    
    def _determine_risk_rating(self, criticality: float, exploitability: float) -> RiskRating:
        """Determine overall risk rating from criticality and exploitability."""
        combined_score = (criticality * 0.7) + (exploitability * 0.3)
        
        if combined_score >= 80:
            return RiskRating.CRITICAL
        elif combined_score >= 60:
            return RiskRating.HIGH
        elif combined_score >= 40:
            return RiskRating.MEDIUM
        elif combined_score >= 20:
            return RiskRating.LOW
        else:
            return RiskRating.MINIMAL
    
    def _determine_remediation_priority(self, criticality: float, exploitability: float, confidence: float) -> str:
        """Determine remediation priority."""
        combined = (criticality * 0.5) + (exploitability * 0.3) + (confidence * 0.2)
        
        if combined >= 75:
            return "Critical"
        elif combined >= 50:
            return "High"
        elif combined >= 25:
            return "Medium"
        else:
            return "Low"
    
    @staticmethod
    def _severity_value(severity: Severity) -> int:
        """Convert severity to numeric value."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }.get(severity, 0)
