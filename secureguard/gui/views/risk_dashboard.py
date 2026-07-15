"""
Risk Dashboard View - Displays aggregated risk metrics and correlation analysis.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QFont, QBrush
from ..theme import Theme
from ..components.cards import DashboardCard
from secureguard.core.models import CorrelatedFinding, RiskRating, Severity, RiskScore


class RiskDashboardView(QWidget):
    """Main risk dashboard displaying aggregated security metrics."""
    
    def __init__(self):
        super().__init__()
        self.setObjectName("RiskDashboardView")
        self.correlated_findings = []
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the risk dashboard layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Risk Assessment Dashboard")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        
        # Metrics row
        metrics_layout = QHBoxLayout()
        
        self.card_security_score = DashboardCard("Overall Security Score", "0%", color="#4CAF50")
        self.card_risk_rating = DashboardCard("Risk Rating", "Unknown", color="#FFC107")
        self.card_exploitability = DashboardCard("Exploitability", "0%", color="#FF5722")
        self.card_confidence = DashboardCard("Confidence Level", "0%", color="#2196F3")
        
        metrics_layout.addWidget(self.card_security_score)
        metrics_layout.addWidget(self.card_risk_rating)
        metrics_layout.addWidget(self.card_exploitability)
        metrics_layout.addWidget(self.card_confidence)
        
        layout.addLayout(metrics_layout)
        
        # Criticality cards
        criticality_layout = QHBoxLayout()
        self.card_criticality = DashboardCard("Criticality Score", "0%", color="#9C27B0")
        self.card_correlated = DashboardCard("Correlated Findings", "0", color="#00BCD4")
        self.card_unique = DashboardCard("Unique Vulnerabilities", "0", color="#673AB7")
        
        criticality_layout.addWidget(self.card_criticality)
        criticality_layout.addWidget(self.card_correlated)
        criticality_layout.addWidget(self.card_unique)
        
        layout.addLayout(criticality_layout)
        
        # Severity distribution
        severity_layout = QHBoxLayout()
        self.card_critical_count = DashboardCard("Critical", "0", color="#D32F2F")
        self.card_high_count = DashboardCard("High", "0", color="#F57C00")
        self.card_medium_count = DashboardCard("Medium", "0", color="#FBC02D")
        self.card_low_count = DashboardCard("Low", "0", color="#388E3C")
        
        severity_layout.addWidget(self.card_critical_count)
        severity_layout.addWidget(self.card_high_count)
        severity_layout.addWidget(self.card_medium_count)
        severity_layout.addWidget(self.card_low_count)
        
        layout.addLayout(severity_layout)
        
        # Findings table
        table_label = QLabel("Correlated Findings (Sorted by Criticality)")
        table_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        layout.addWidget(table_label)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(7)
        self.findings_table.setHorizontalHeaderLabels([
            "Vulnerability Type",
            "File",
            "Line",
            "Severity",
            "Risk Rating",
            "Criticality",
            "Exploitability"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.findings_table)
        
        layout.addStretch()
    
    def update_with_findings(self, findings: list):
        """Update dashboard with correlated findings."""
        self.correlated_findings = findings
        
        if not findings:
            self._clear_dashboard()
            return
        
        # Calculate aggregate metrics
        total_critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        total_high = sum(1 for f in findings if f.severity == Severity.HIGH)
        total_medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        total_low = sum(1 for f in findings if f.severity == Severity.LOW)
        
        # Average risk scores
        risk_scores = [f.risk_score for f in findings if f.risk_score]
        if risk_scores:
            avg_security = sum(r.overall_security_score for r in risk_scores) / len(risk_scores)
            avg_exploit = sum(r.exploitability_score for r in risk_scores) / len(risk_scores)
            avg_confidence = sum(r.confidence_score for r in risk_scores) / len(risk_scores)
            avg_criticality = sum(r.criticality_score for r in risk_scores) / len(risk_scores)
            
            # Determine overall risk rating
            overall_rating = self._determine_overall_rating(avg_criticality, avg_exploit)
        else:
            avg_security = 100
            avg_exploit = 0
            avg_confidence = 0
            avg_criticality = 0
            overall_rating = RiskRating.MINIMAL
        
        # Update metric cards
        self.card_security_score.update_value(f"{avg_security:.0f}%")
        self.card_security_score.update_color(self._get_color_for_security(avg_security))
        
        self.card_risk_rating.update_value(overall_rating.value)
        self.card_risk_rating.update_color(self._get_color_for_rating(overall_rating))
        
        self.card_exploitability.update_value(f"{avg_exploit:.0f}%")
        self.card_criticality.update_value(f"{avg_criticality:.0f}%")
        self.card_confidence.update_value(f"{avg_confidence:.0f}%")
        
        # Update counts
        total_raw = sum(len(f.related_vulnerabilities) for f in findings)
        self.card_correlated.update_value(str(len(findings)))
        self.card_unique.update_value(str(len(set(f.vuln_type for f in findings))))
        
        self.card_critical_count.update_value(str(total_critical))
        self.card_high_count.update_value(str(total_high))
        self.card_medium_count.update_value(str(total_medium))
        self.card_low_count.update_value(str(total_low))
        
        # Update findings table
        self._populate_findings_table(findings)
    
    def _populate_findings_table(self, findings: list):
        """Populate the findings table with correlated findings."""
        self.findings_table.setRowCount(len(findings))
        
        # Sort by criticality
        sorted_findings = sorted(
            findings,
            key=lambda f: f.risk_score.criticality_score if f.risk_score else 0,
            reverse=True
        )
        
        for row, finding in enumerate(sorted_findings):
            # Vulnerability Type
            type_item = QTableWidgetItem(finding.vuln_type)
            self.findings_table.setItem(row, 0, type_item)
            
            # File
            file_item = QTableWidgetItem(finding.primary_file.split('/')[-1])
            self.findings_table.setItem(row, 1, file_item)
            
            # Line
            line_item = QTableWidgetItem(str(finding.primary_line))
            self.findings_table.setItem(row, 2, line_item)
            
            # Severity
            severity_item = QTableWidgetItem(finding.severity.value)
            severity_item.setBackground(QBrush(self._get_color_for_severity(finding.severity)))
            self.findings_table.setItem(row, 3, severity_item)
            
            # Risk Rating
            risk_rating = finding.risk_score.risk_rating.value if finding.risk_score else "Unknown"
            rating_item = QTableWidgetItem(risk_rating)
            if finding.risk_score:
                rating_item.setBackground(QBrush(self._get_color_for_rating(finding.risk_score.risk_rating)))
            self.findings_table.setItem(row, 4, rating_item)
            
            # Criticality
            criticality = f"{finding.risk_score.criticality_score:.0f}%" if finding.risk_score else "0%"
            crit_item = QTableWidgetItem(criticality)
            self.findings_table.setItem(row, 5, crit_item)
            
            # Exploitability
            exploit = f"{finding.risk_score.exploitability_score:.0f}%" if finding.risk_score else "0%"
            exploit_item = QTableWidgetItem(exploit)
            self.findings_table.setItem(row, 6, exploit_item)
    
    def _clear_dashboard(self):
        """Clear all dashboard values."""
        self.card_security_score.update_value("0%")
        self.card_risk_rating.update_value("Unknown")
        self.card_exploitability.update_value("0%")
        self.card_confidence.update_value("0%")
        self.card_criticality.update_value("0%")
        self.card_correlated.update_value("0")
        self.card_unique.update_value("0")
        self.card_critical_count.update_value("0")
        self.card_high_count.update_value("0")
        self.card_medium_count.update_value("0")
        self.card_low_count.update_value("0")
        self.findings_table.setRowCount(0)
    
    def _get_color_for_severity(self, severity: Severity) -> QColor:
        """Get color for severity level."""
        if severity == Severity.CRITICAL:
            return QColor("#D32F2F")
        elif severity == Severity.HIGH:
            return QColor("#F57C00")
        elif severity == Severity.MEDIUM:
            return QColor("#FBC02D")
        else:
            return QColor("#388E3C")
    
    def _get_color_for_rating(self, rating: RiskRating) -> QColor:
        """Get color for risk rating."""
        if rating == RiskRating.CRITICAL:
            return QColor("#D32F2F")
        elif rating == RiskRating.HIGH:
            return QColor("#F57C00")
        elif rating == RiskRating.MEDIUM:
            return QColor("#FBC02D")
        elif rating == RiskRating.LOW:
            return QColor("#4CAF50")
        else:
            return QColor("#8BC34A")
    
    def _get_color_for_security(self, score: float) -> str:
        """Get color based on security score."""
        if score >= 80:
            return "#4CAF50"  # Green
        elif score >= 60:
            return "#8BC34A"  # Light Green
        elif score >= 40:
            return "#FBC02D"  # Yellow
        elif score >= 20:
            return "#F57C00"  # Orange
        else:
            return "#D32F2F"  # Red
    
    def _determine_overall_rating(self, criticality: float, exploitability: float) -> RiskRating:
        """Determine overall risk rating."""
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
