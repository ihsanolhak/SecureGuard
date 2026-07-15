"""
Finding Correlation View - Displays correlated findings from multiple analysis sources.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QHeaderView, QTextEdit, QSplitter, QComboBox
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QFont, QBrush
from ..theme import Theme
from secureguard.core.models import Severity, RiskRating


class FindingCorrelationView(QWidget):
    """Displays correlated findings and their relationships."""
    
    def __init__(self):
        super().__init__()
        self.setObjectName("FindingCorrelationView")
        self.correlated_findings = []
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the finding correlation layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Finding Correlation Analysis")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        
        # Filter/Sort options
        options_layout = QHBoxLayout()
        
        filter_label = QLabel("Filter by Severity:")
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        
        sort_label = QLabel("Sort by:")
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Criticality (Desc)", "Sources (Most)", "Exploitability (Desc)"])
        
        options_layout.addWidget(filter_label)
        options_layout.addWidget(self.severity_filter, 1)
        options_layout.addWidget(sort_label)
        options_layout.addWidget(self.sort_combo, 1)
        options_layout.addStretch()
        
        layout.addLayout(options_layout)
        
        # Main splitter with correlation table and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel: Findings table
        left_layout = QVBoxLayout()
        left_widget = QWidget()
        
        findings_label = QLabel("Correlated Finding Groups")
        findings_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        left_layout.addWidget(findings_label)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(6)
        self.findings_table.setHorizontalHeaderLabels([
            "Vulnerability",
            "Sources",
            "Count",
            "Confidence",
            "Exploitable",
            "Priority"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.itemSelectionChanged.connect(self._on_finding_selected)
        
        left_layout.addWidget(self.findings_table)
        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)
        
        # Right panel: Details
        right_layout = QVBoxLayout()
        right_widget = QWidget()
        
        details_label = QLabel("Finding Details")
        details_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        right_layout.addWidget(details_label)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
        """)
        
        right_layout.addWidget(self.details_text)
        right_widget.setLayout(right_layout)
        splitter.addWidget(right_widget)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter, 1)
        
        # Connect signals
        self.severity_filter.currentTextChanged.connect(self._apply_filters)
        self.sort_combo.currentTextChanged.connect(self._apply_sorting)
    
    def update_with_findings(self, findings: list):
        """Update view with correlated findings."""
        self.correlated_findings = findings
        self._populate_findings_table(findings)
    
    def _populate_findings_table(self, findings: list):
        """Populate the findings table."""
        self.findings_table.setRowCount(len(findings))
        
        for row, finding in enumerate(findings):
            # Vulnerability Type
            vuln_item = QTableWidgetItem(finding.vuln_type)
            self.findings_table.setItem(row, 0, vuln_item)
            
            # Sources (comma-separated)
            sources_str = ", ".join([s.value for s in finding.finding_sources])
            sources_item = QTableWidgetItem(sources_str)
            self.findings_table.setItem(row, 1, sources_item)
            
            # Count of related findings
            count_item = QTableWidgetItem(str(len(finding.related_vulnerabilities)))
            self.findings_table.setItem(row, 2, count_item)
            
            # Confidence
            if finding.risk_score:
                confidence = f"{finding.risk_score.confidence_score:.0f}%"
            else:
                confidence = "N/A"
            confidence_item = QTableWidgetItem(confidence)
            self.findings_table.setItem(row, 3, confidence_item)
            
            # Exploitable
            exploitable_str = "Yes" if finding.is_exploitable else "No"
            exploit_item = QTableWidgetItem(exploitable_str)
            exploit_color = QColor("#D32F2F") if finding.is_exploitable else QColor("#4CAF50")
            exploit_item.setBackground(QBrush(exploit_color))
            self.findings_table.setItem(row, 4, exploit_item)
            
            # Remediation Priority
            priority_item = QTableWidgetItem(finding.remediation_priority)
            priority_color = self._get_priority_color(finding.remediation_priority)
            priority_item.setBackground(QBrush(priority_color))
            self.findings_table.setItem(row, 5, priority_item)
    
    def _on_finding_selected(self):
        """Handle finding selection to show details."""
        selected_rows = self.findings_table.selectedIndexes()
        if not selected_rows:
            self.details_text.clear()
            return
        
        row = selected_rows[0].row()
        if row < len(self.correlated_findings):
            finding = self.correlated_findings[row]
            self._show_finding_details(finding)
    
    def _show_finding_details(self, finding):
        """Display detailed information about a finding."""
        details = f"""
CORRELATED FINDING ANALYSIS
{'=' * 60}

Vulnerability Type: {finding.vuln_type}
Location: {finding.primary_file}:{finding.primary_line}
Severity: {finding.severity.value}

ANALYSIS SOURCES
{'-' * 60}
"""
        
        for source in finding.finding_sources:
            details += f"  • {source.value}\n"
        
        details += f"""
RELATED VULNERABILITIES
{'-' * 60}
Count: {len(finding.related_vulnerabilities)}

"""
        for i, vuln in enumerate(finding.related_vulnerabilities, 1):
            details += f"{i}. {vuln.vuln_type}\n"
            details += f"   Source: {vuln.source.value}\n"
            details += f"   Description: {vuln.description}\n\n"
        
        if finding.risk_score:
            details += f"""
RISK METRICS
{'-' * 60}
Overall Security Score: {finding.risk_score.overall_security_score:.1f}%
Exploitability Score: {finding.risk_score.exploitability_score:.1f}%
Confidence Score: {finding.risk_score.confidence_score:.1f}%
Criticality Score: {finding.risk_score.criticality_score:.1f}%
Risk Rating: {finding.risk_score.risk_rating.value}

"""
        
        if finding.cwe_ids:
            details += f"""
CWE MAPPINGS
{'-' * 60}
"""
            for cwe_id in sorted(finding.cwe_ids):
                details += f"  • {cwe_id}\n"
            details += "\n"
        
        if finding.stride_categories:
            details += f"""
STRIDE MAPPINGS
{'-' * 60}
"""
            for stride in sorted(finding.stride_categories):
                details += f"  • {stride}\n"
            details += "\n"
        
        if finding.exploitation_chain:
            details += f"""
EXPLOITATION CHAIN
{'-' * 60}
"""
            for i, step in enumerate(finding.exploitation_chain, 1):
                details += f"{i}. {step}\n"
            details += "\n"
        
        details += f"""REMEDIATION
{'-' * 60}
Priority: {finding.remediation_priority}
Description: {finding.confidence_description}

Recommendations:
"""
        for vuln in finding.related_vulnerabilities:
            details += f"  • {vuln.recommendation}\n"
        
        self.details_text.setText(details)
    
    def _apply_filters(self):
        """Apply severity filter to the table."""
        severity_filter = self.severity_filter.currentText()
        
        for row in range(self.findings_table.rowCount()):
            should_show = True
            
            if severity_filter != "All":
                # Get severity from the finding object
                finding = self.correlated_findings[row]
                if finding.severity.value != severity_filter:
                    should_show = False
            
            self.findings_table.setRowHidden(row, not should_show)
    
    def _apply_sorting(self):
        """Apply sorting to the table."""
        sort_option = self.sort_combo.currentText()
        
        if sort_option == "Criticality (Desc)":
            self.correlated_findings.sort(
                key=lambda f: f.risk_score.criticality_score if f.risk_score else 0,
                reverse=True
            )
        elif sort_option == "Sources (Most)":
            self.correlated_findings.sort(
                key=lambda f: len(f.finding_sources),
                reverse=True
            )
        elif sort_option == "Exploitability (Desc)":
            self.correlated_findings.sort(
                key=lambda f: f.risk_score.exploitability_score if f.risk_score else 0,
                reverse=True
            )
        
        self._populate_findings_table(self.correlated_findings)
    
    def _get_priority_color(self, priority: str) -> QColor:
        """Get color for remediation priority."""
        if priority == "Critical":
            return QColor("#D32F2F")
        elif priority == "High":
            return QColor("#F57C00")
        elif priority == "Medium":
            return QColor("#FBC02D")
        else:
            return QColor("#4CAF50")
