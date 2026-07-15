import os
import re
import uuid
import json
from datetime import datetime
from typing import List, Dict

from secureguard.core.models import ScanResult, Vulnerability, Severity
from secureguard.core.interfaces import IStaticScanner
from secureguard.static_analysis.ast_scanner import ASTCorrelationEngine

class ScanRule:
    def __init__(self, pattern: str, severity: Severity, vuln_type: str, description: str, recommendation: str):
        self.pattern = re.compile(pattern)
        self.severity = severity
        self.vuln_type = vuln_type
        self.description = description
        self.recommendation = recommendation

class RegexStaticScanner(IStaticScanner):
    def __init__(self):
        self.rules = [
            # CRITICAL
            ScanRule(r'\bgets\s*\(', Severity.CRITICAL, "Buffer Overflow", "gets() does not check buffer length.", "Use fgets() instead."),
            ScanRule(r'\bstrcpy\s*\(', Severity.CRITICAL, "Buffer Overflow", "strcpy() does not check buffer length.", "Use strncpy() or strlcpy()."),
            ScanRule(r'\bsprintf\s*\(', Severity.CRITICAL, "Buffer Overflow", "sprintf() can cause buffer overflows.", "Use snprintf() instead."),
            
            # HIGH
            ScanRule(r'\bsystem\s*\(', Severity.HIGH, "Command Injection", "system() allows arbitrary command execution.", "Use exec() family of functions with proper sanitization."),
            ScanRule(r'\bstrcat\s*\(', Severity.HIGH, "Buffer Overflow", "strcat() does not check bounds.", "Use strncat() instead."),
            
            # MEDIUM
            ScanRule(r'\brand\s*\(', Severity.MEDIUM, "Weak Crypto", "rand() is not cryptographically secure.", "Use a CSPRNG (e.g. /dev/urandom)."),
            ScanRule(r'(password|passwd|pwd|secret)\s*=\s*["\'][^"\']+["\']', Severity.MEDIUM, "Hardcoded Credential", "Hardcoded credentials found.", "Use environment variables or secure vault."),
            
            # LOW
            ScanRule(r'//\s*TODO.*(?:security|fix|vuln|hack)', Severity.LOW, "TODO Comment", "Security-related TODO comment left in code.", "Resolve the security issue."),
            ScanRule(r'#ifdef\s+DEBUG', Severity.LOW, "Debug Code", "Debug code blocks may expose sensitive info.", "Ensure debug code is stripped in production.")
        ]
        
    def scan_directory(self, path: str) -> ScanResult:
        return self._scan(path, is_dir=True)
        
    def scan_file(self, path: str) -> ScanResult:
        return self._scan(path, is_dir=False)
        
    def _scan(self, path: str, is_dir: bool) -> ScanResult:
        vulnerabilities = []
        files_scanned = 0
        
        target_files = []
        if is_dir:
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith(('.c', '.cpp', '.h', '.hpp')):
                        target_files.append(os.path.join(root, f))
        else:
            if path.endswith(('.c', '.cpp', '.h', '.hpp')):
                target_files.append(path)
                
        for file_path in target_files:
            files_scanned += 1
            vulns = self._scan_single_file(file_path)
            vulnerabilities.extend(vulns)
            
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            files_scanned=files_scanned,
            vulnerabilities=vulnerabilities,
            risk_score=risk_score
        )

    def _scan_single_file(self, file_path: str) -> List[Vulnerability]:
        vulns = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_idx, line in enumerate(lines):
                line_content = line.strip()
                for rule in self.rules:
                    if rule.pattern.search(line_content):
                        vulns.append(Vulnerability(
                            id=str(uuid.uuid4())[:8],
                            severity=rule.severity,
                            vuln_type=rule.vuln_type,
                            file_path=file_path,
                            line_number=line_idx + 1,
                            description=rule.description,
                            recommendation=rule.recommendation
                        ))
        except Exception:
            pass
            
        # Use AST to validate and reduce false positives
        engine = ASTCorrelationEngine()
        vulns = engine.validate_findings(file_path, vulns)
            
        return vulns

    def _calculate_risk_score(self, vulns: List[Vulnerability]) -> float:
        if not vulns:
            return 0.0
            
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0
        }
        
        total_weight = 0.0
        for v in vulns:
            total_weight += weights.get(v.severity, 0.0)
            
        # Normalize somewhat and cap to 10.0 for risk score
        score = min(10.0, total_weight / 5.0)  
        return round(score, 1)

    def export_to_json(self, result: ScanResult, output_path: str) -> bool:
        try:
            data = {
                "scan_id": result.scan_id,
                "timestamp": result.timestamp.isoformat(),
                "files_scanned": result.files_scanned,
                "risk_score": result.risk_score,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "severity": v.severity.value,
                        "type": v.vuln_type,
                        "file": v.file_path,
                        "line": v.line_number,
                        "description": v.description,
                        "recommendation": v.recommendation
                    } for v in result.vulnerabilities
                ]
            }
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception:
            return False
