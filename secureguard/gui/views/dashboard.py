from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QSplitter
from PyQt6.QtCore import Qt
from ..components.cards import DashboardCard
from ..components.executive_summary import ExecutiveSummaryPanel
from secureguard.core.models import Severity

class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        
        # Cards Layout
        cards_layout = QHBoxLayout()
        
        self.card_files = DashboardCard("Files Scanned", "1,240")
        self.card_vulns = DashboardCard("Vulnerabilities Found", "45")
        self.card_critical = DashboardCard("Critical Findings", "3")
        self.card_last_scan = DashboardCard("Last Scan", "2 mins ago")
        self.card_security_score = DashboardCard("Security Score", "0%", color="#4CAF50")
        
        cards_layout.addWidget(self.card_files)
        cards_layout.addWidget(self.card_vulns)
        cards_layout.addWidget(self.card_critical)
        cards_layout.addWidget(self.card_last_scan)
        cards_layout.addWidget(self.card_security_score)
        
        layout.addLayout(cards_layout)
        
        # Risk correlation cards
        risk_cards_layout = QHBoxLayout()
        
        self.card_risk_rating = DashboardCard("Risk Rating", "Unknown", color="#FFC107")
        self.card_correlated = DashboardCard("Correlated Findings", "0", color="#00BCD4")
        self.card_exploit = DashboardCard("Exploitable", "0", color="#FF5722")
        self.card_confidence = DashboardCard("Avg Confidence", "0%", color="#2196F3")
        
        risk_cards_layout.addWidget(self.card_risk_rating)
        risk_cards_layout.addWidget(self.card_correlated)
        risk_cards_layout.addWidget(self.card_exploit)
        risk_cards_layout.addWidget(self.card_confidence)
        
        layout.addLayout(risk_cards_layout)
        
        # Executive summary panel
        self.summary_panel = ExecutiveSummaryPanel()
        layout.addWidget(self.summary_panel, 1)
    
    def update_metrics(self, metrics):
        """Update dashboard with analysis metrics."""
        if metrics and metrics.risk_score:
            self.card_security_score.update_value(f"{metrics.risk_score.overall_security_score:.0f}%")
            self.card_risk_rating.update_value(metrics.risk_score.risk_rating.value)
            self.card_correlated.update_value(str(metrics.correlated_findings))
            
            exploitable_count = sum(1 for f in metrics.analysis_sources_used if f)
            self.card_exploit.update_value(str(exploitable_count))
            self.card_confidence.update_value(f"{metrics.risk_score.confidence_score:.0f}%")
            
            # Update summary
            self.summary_panel.update_with_metrics(metrics)

