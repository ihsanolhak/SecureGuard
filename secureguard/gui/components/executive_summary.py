"""
Executive Summary Panel - High-level security posture overview.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QProgressBar
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from secureguard.core.models import AnalysisSessionMetrics, RiskRating, Severity


class ExecutiveSummaryPanel(QWidget):
    """Displays executive-level security summary."""
    
    def __init__(self):
        super().__init__()
        self.setObjectName("ExecutiveSummaryPanel")
        self.metrics = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the executive summary layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Executive Summary")
        title_font = QFont("Segoe UI", 14, QFont.Weight.Bold)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Security posture
        posture_label = QLabel("Security Posture")
        posture_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        layout.addWidget(posture_label)
        
        self.posture_text = QLabel("")
        self.posture_text.setWordWrap(True)
        layout.addWidget(self.posture_text)
        
        # Security score progress bar
        score_label = QLabel("Security Score")
        score_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(score_label)
        
        self.score_progress = QProgressBar()
        self.score_progress.setMaximum(100)
        self.score_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3e3e42;
                border-radius: 4px;
                background-color: #1e1e1e;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
            }
        """)
        layout.addWidget(self.score_progress)
        
        # Key findings
        findings_label = QLabel("Key Findings")
        findings_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        layout.addWidget(findings_label)
        
        self.findings_text = QTextEdit()
        self.findings_text.setReadOnly(True)
        self.findings_text.setMaximumHeight(200)
        self.findings_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.findings_text)
        
        # Recommendations
        recommendations_label = QLabel("Recommended Actions")
        recommendations_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        layout.addWidget(recommendations_label)
        
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.recommendations_text.setMaximumHeight(200)
        self.recommendations_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.recommendations_text)
        
        layout.addStretch()
    
    def update_with_metrics(self, metrics: AnalysisSessionMetrics):
        """Update summary with analysis metrics."""
        self.metrics = metrics
        
        if not metrics or not metrics.risk_score:
            self._clear_summary()
            return
        
        # Update security posture
        posture_text = self._generate_posture_text(metrics)
        self.posture_text.setText(posture_text)
        
        # Update score progress
        security_score = int(metrics.risk_score.overall_security_score)
        self.score_progress.setValue(security_score)
        
        # Update color based on score
        if security_score >= 80:
            chunk_color = "#4CAF50"  # Green
        elif security_score >= 60:
            chunk_color = "#8BC34A"  # Light Green
        elif security_score >= 40:
            chunk_color = "#FBC02D"  # Yellow
        elif security_score >= 20:
            chunk_color = "#F57C00"  # Orange
        else:
            chunk_color = "#D32F2F"  # Red
        
        self.score_progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid #3e3e42;
                border-radius: 4px;
                background-color: #1e1e1e;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {chunk_color};
            }}
        """)
        
        # Update key findings
        findings_text = self._generate_findings_text(metrics)
        self.findings_text.setText(findings_text)
        
        # Update recommendations
        recommendations_text = self._generate_recommendations(metrics)
        self.recommendations_text.setText(recommendations_text)
    
    def _generate_posture_text(self, metrics: AnalysisSessionMetrics) -> str:
        """Generate human-readable security posture text."""
        if not metrics.risk_score:
            return "No analysis data available."
        
        rating = metrics.risk_score.risk_rating
        
        posture_map = {
            RiskRating.CRITICAL: "🔴 CRITICAL RISK - Immediate action required. Severe vulnerabilities present that pose an imminent threat to system security.",
            RiskRating.HIGH: "🟠 HIGH RISK - Urgent attention needed. Multiple significant vulnerabilities discovered that require prompt remediation.",
            RiskRating.MEDIUM: "🟡 MEDIUM RISK - Moderate vulnerabilities detected. Review and address findings according to priority.",
            RiskRating.LOW: "🟢 LOW RISK - Minor vulnerabilities found. Consider remediation as part of regular security maintenance.",
            RiskRating.MINIMAL: "✅ MINIMAL RISK - Few to no vulnerabilities detected. Security posture is generally strong.",
        }
        
        posture = posture_map.get(rating, "Unknown")
        
        # Add details
        details = f"\n\nAnalysis Details:\n"
        details += f"  • Total Findings: {metrics.total_findings}\n"
        details += f"  • Correlated Groups: {metrics.correlated_findings}\n"
        details += f"  • Unique Vulnerabilities: {metrics.unique_vulnerabilities}\n"
        details += f"  • Security Score: {metrics.risk_score.overall_security_score:.1f}%\n"
        details += f"  • Highest Severity: {metrics.highest_severity.value if metrics.highest_severity else 'None'}\n"
        
        return posture + details
    
    def _generate_findings_text(self, metrics: AnalysisSessionMetrics) -> str:
        """Generate key findings summary."""
        if not metrics.risk_score:
            return "No findings."
        
        findings = ""
        
        # Exploitability
        if metrics.risk_score.exploitability_score >= 80:
            findings += "⚠️ HIGH EXPLOITABILITY - Multiple findings can likely be exploited to compromise the application.\n\n"
        elif metrics.risk_score.exploitability_score >= 50:
            findings += "⚠️ MODERATE EXPLOITABILITY - Some findings present practical exploitation paths.\n\n"
        
        # Confidence level
        if metrics.risk_score.confidence_score >= 95:
            findings += "✓ CONFIRMED FINDINGS - Runtime analysis confirmed static vulnerabilities with extremely high confidence.\n\n"
        elif metrics.risk_score.confidence_score >= 85:
            findings += "✓ HIGHLY CONFIDENT - Multiple analysis tools detected the same issues.\n\n"
        elif metrics.risk_score.confidence_score >= 70:
            findings += "ℹ️ VERIFIED FINDINGS - Multiple sources detected these issues.\n\n"
        else:
            findings += "⚠️ LOW CONFIDENCE - Limited evidence for some findings.\n\n"
        
        # Criticality
        if metrics.risk_score.criticality_score >= 80:
            findings += "🔴 CRITICAL ISSUES - Several critical-level vulnerabilities require immediate attention.\n"
        elif metrics.risk_score.criticality_score >= 60:
            findings += "🟠 HIGH-SEVERITY ISSUES - Important vulnerabilities that should be prioritized.\n"
        elif metrics.risk_score.criticality_score >= 40:
            findings += "🟡 MODERATE ISSUES - Significant vulnerabilities requiring attention.\n"
        else:
            findings += "🟢 LOW-SEVERITY ISSUES - Minor vulnerabilities present.\n"
        
        return findings
    
    def _generate_recommendations(self, metrics: AnalysisSessionMetrics) -> str:
        """Generate recommended actions."""
        recommendations = ""
        
        if not metrics.risk_score:
            return "No recommendations available."
        
        rating = metrics.risk_score.risk_rating
        
        if rating == RiskRating.CRITICAL:
            recommendations += "1. IMMEDIATE: Halt deployment and address critical vulnerabilities.\n"
            recommendations += "2. URGENT: Review all findings marked as exploitable.\n"
            recommendations += "3. ESCALATE: Involve security team for incident response planning.\n"
            recommendations += "4. REMEDIATE: Fix critical issues before any code changes proceed.\n"
        elif rating == RiskRating.HIGH:
            recommendations += "1. PRIORITY: Schedule remediation for all high-severity findings.\n"
            recommendations += "2. REVIEW: Analyze exploitation paths and attack surfaces.\n"
            recommendations += "3. PLAN: Create a timeline for fixes and validation.\n"
            recommendations += "4. MONITOR: Track remediation progress closely.\n"
        elif rating == RiskRating.MEDIUM:
            recommendations += "1. PLAN: Schedule remediation in the next development cycle.\n"
            recommendations += "2. PRIORITIZE: Address findings by criticality and exploitability.\n"
            recommendations += "3. REVIEW: Implement code review practices to prevent similar issues.\n"
            recommendations += "4. TEST: Re-scan after fixes to verify resolution.\n"
        elif rating == RiskRating.LOW:
            recommendations += "1. MAINTAIN: Continue monitoring for new issues.\n"
            recommendations += "2. IMPROVE: Use secure coding practices to prevent future vulnerabilities.\n"
            recommendations += "3. DOCUMENT: Record remediation actions for compliance.\n"
            recommendations += "4. REVIEW: Update security training based on findings.\n"
        else:  # MINIMAL
            recommendations += "1. SUSTAIN: Maintain current security practices.\n"
            recommendations += "2. MONITOR: Continue regular security scans.\n"
            recommendations += "3. EDUCATE: Reinforce secure coding standards.\n"
            recommendations += "4. IMPROVE: Implement defense-in-depth measures.\n"
        
        return recommendations
    
    def _clear_summary(self):
        """Clear all summary content."""
        self.posture_text.setText("No data available.")
        self.score_progress.setValue(0)
        self.findings_text.setText("")
        self.recommendations_text.setText("")
