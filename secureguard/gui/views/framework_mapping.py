from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QFrame)
from PyQt6.QtCore import Qt
from secureguard.core.frameworks import SecurityFrameworkMapper

class FrameworkMappingView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mapper = SecurityFrameworkMapper()
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title = QLabel("Security Framework Mapping")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        
        desc = QLabel("Map findings to CWE Framework and STRIDE Threat Model. Click 'Refresh Mapping' to pull latest findings from Static and Memory analysis.")
        desc.setStyleSheet("color: #9CA3AF; margin-bottom: 10px;")
        layout.addWidget(desc)
        
        # Controls
        controls = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh Mapping")
        self.btn_refresh.setStyleSheet("background-color: #3B82F6; font-weight: bold;")
        controls.addWidget(self.btn_refresh)
        controls.addStretch()
        layout.addLayout(controls)
        
        # Summary Panels
        stats_layout = QHBoxLayout()
        self.card_total = self._make_card("Mapped Findings", "0")
        self.card_cwe = self._make_card("Unique CWEs", "0")
        self.card_stride = self._make_card("Threat Categories", "0")
        stats_layout.addWidget(self.card_total)
        stats_layout.addWidget(self.card_cwe)
        stats_layout.addWidget(self.card_stride)
        layout.addLayout(stats_layout)
        
        # Main content splits into Table and Summary Text
        content_layout = QHBoxLayout()
        
        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Finding Type", "Severity", "CWE Mapping", "STRIDE Category"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        content_layout.addWidget(self.table, 2)
        
        # Threat Analysis Panel
        threat_panel = QFrame()
        threat_panel.setObjectName("DashboardCard")
        threat_layout = QVBoxLayout(threat_panel)
        
        threat_title = QLabel("Threat Analysis & Summary")
        threat_title.setStyleSheet("font-size: 12pt; font-weight: bold; color: #E5E7EB; margin-bottom: 10px;")
        threat_layout.addWidget(threat_title)
        
        self.lbl_summary = QLabel("No data loaded. Refresh mapping to see statistics.")
        self.lbl_summary.setWordWrap(True)
        self.lbl_summary.setAlignment(Qt.AlignmentFlag.AlignTop)
        threat_layout.addWidget(self.lbl_summary)
        threat_layout.addStretch()
        
        content_layout.addWidget(threat_panel, 1)
        layout.addLayout(content_layout)
        
        # Connect signals
        self.btn_refresh.clicked.connect(self.refresh_mapping)
        
    def _make_card(self, title: str, value: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName("DashboardCard")
        lo = QVBoxLayout(frame)
        t = QLabel(title)
        t.setObjectName("CardTitle")
        t.setWordWrap(True)
        v = QLabel(value)
        v.setObjectName("CardValue")
        v.setWordWrap(True)
        v.setStyleSheet("color: #F3F4F6;")
        lo.addWidget(t, 0, Qt.AlignmentFlag.AlignCenter)
        lo.addWidget(v, 0, Qt.AlignmentFlag.AlignCenter)
        return frame

    def _update_card(self, card: QFrame, value: str):
        lbl = card.findChild(QLabel, "CardValue")
        if lbl:
            lbl.setText(value)

    def get_main_window(self):
        parent = self.parent()
        while parent is not None:
            if hasattr(parent, 'view_static') and hasattr(parent, 'view_memory'):
                return parent
            parent = parent.parent()
        return None

    def refresh_mapping(self):
        main_win = self.get_main_window()
        all_vulns = []
        if main_win:
            if main_win.view_static.current_result:
                all_vulns.extend(main_win.view_static.current_result.vulnerabilities)
            if hasattr(main_win.view_memory, 'current_vulns') and main_win.view_memory.current_vulns:
                all_vulns.extend(main_win.view_memory.current_vulns)
                
        self.table.setRowCount(len(all_vulns))
        
        cwe_stats = {}
        stride_stats = {}
        
        for row, v in enumerate(all_vulns):
            cwes, strides = self.mapper.map_finding(v.vuln_type)
            
            cwe_text = ", ".join(cwes)
            stride_text = ", ".join(strides)
            
            self.table.setItem(row, 0, QTableWidgetItem(v.vuln_type))
            self.table.setItem(row, 1, QTableWidgetItem(v.severity.value))
            self.table.setItem(row, 2, QTableWidgetItem(cwe_text))
            self.table.setItem(row, 3, QTableWidgetItem(stride_text))
            
            for c in cwes:
                cwe_stats[c] = cwe_stats.get(c, 0) + 1
            for s in strides:
                stride_stats[s] = stride_stats.get(s, 0) + 1
                
        self._update_card(self.card_total, str(len(all_vulns)))
        self._update_card(self.card_cwe, str(len([c for c in cwe_stats if c != "Unknown"])))
        self._update_card(self.card_stride, str(len([s for s in stride_stats if s != "Unknown"])))
        
        if not all_vulns:
            self.lbl_summary.setText("No findings found. Please run a scan.")
            return
            
        summary_text = "<b>CWE Statistics:</b><br>"
        for c, count in sorted(cwe_stats.items(), key=lambda x: x[1], reverse=True):
            if c != "Unknown":
                name = self.mapper.cwe_db.get_cwe(c)["name"]
                summary_text += f"• {c} ({name}): {count}<br>"
                
        summary_text += "<br><b>STRIDE Statistics:</b><br>"
        for s, count in sorted(stride_stats.items(), key=lambda x: x[1], reverse=True):
            if s != "Unknown":
                summary_text += f"• {s}: {count}<br>"
                
        self.lbl_summary.setText(summary_text)
