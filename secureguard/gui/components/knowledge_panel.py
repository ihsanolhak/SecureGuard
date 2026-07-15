from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QScrollArea, QFrame, QHBoxLayout
from PyQt6.QtCore import Qt
from secureguard.core.knowledge import SecurityKnowledgeService
from secureguard.core.models import VulnerabilityProfile

class KnowledgePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.service = SecurityKnowledgeService()
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")
        
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        
        # Title
        self.lbl_title = QLabel("Security Knowledge Base")
        self.lbl_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #E5E7EB; margin-bottom: 10px;")
        self.content_layout.addWidget(self.lbl_title)
        
        # 1. Vulnerability Explanation Panel
        self.lbl_explanation_title = self._create_section_title("Vulnerability Explanation")
        self.txt_explanation = self._create_text_area()
        self.content_layout.addWidget(self.lbl_explanation_title)
        self.content_layout.addWidget(self.txt_explanation)
        
        # 2. Remediation Panel
        self.lbl_remediation_title = self._create_section_title("Remediation Guidance")
        self.txt_remediation = self._create_text_area()
        self.content_layout.addWidget(self.lbl_remediation_title)
        self.content_layout.addWidget(self.txt_remediation)
        
        # 3. Secure Coding Example Panel
        self.lbl_example_title = self._create_section_title("Secure Coding Example")
        self.txt_example = self._create_text_area()
        self.txt_example.setStyleSheet("font-family: 'Consolas', monospace; background-color: #0D1117; padding: 10px; color: #D4D4D4;")
        self.content_layout.addWidget(self.lbl_example_title)
        self.content_layout.addWidget(self.txt_example)
        
        # 4. CWE and 5. STRIDE Panel
        meta_layout = QHBoxLayout()
        
        self.cwe_panel = QFrame()
        cwe_layout = QVBoxLayout(self.cwe_panel)
        self.lbl_cwe_title = self._create_section_title("CWE Mapping")
        self.lbl_cwe = QLabel("N/A")
        self.lbl_cwe.setWordWrap(True)
        cwe_layout.addWidget(self.lbl_cwe_title)
        cwe_layout.addWidget(self.lbl_cwe)
        
        self.stride_panel = QFrame()
        stride_layout = QVBoxLayout(self.stride_panel)
        self.lbl_stride_title = self._create_section_title("STRIDE Mapping")
        self.lbl_stride = QLabel("N/A")
        self.lbl_stride.setWordWrap(True)
        stride_layout.addWidget(self.lbl_stride_title)
        stride_layout.addWidget(self.lbl_stride)
        
        meta_layout.addWidget(self.cwe_panel)
        meta_layout.addWidget(self.stride_panel)
        
        self.content_layout.addLayout(meta_layout)
        self.content_layout.addStretch()
        
        self.scroll_area.setWidget(self.content_widget)
        layout.addWidget(self.scroll_area)
        
        self.clear_panel()

    def _create_section_title(self, title: str) -> QLabel:
        lbl = QLabel(title)
        lbl.setStyleSheet("font-weight: bold; color: #9CA3AF; margin-top: 10px;")
        return lbl
        
    def _create_text_area(self) -> QTextEdit:
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setMaximumHeight(150)
        txt.setStyleSheet("background-color: #1F2937; padding: 8px; border-radius: 4px; color: #E5E7EB;")
        return txt
        
    def clear_panel(self):
        self.lbl_title.setText("Select a finding to view security guidance.")
        self.txt_explanation.setText("")
        self.txt_remediation.setText("")
        self.txt_example.setText("")
        self.lbl_cwe.setText("N/A")
        self.lbl_stride.setText("N/A")
        
    def update_knowledge(self, finding_identifier: str, fallback_description: str = "", fallback_recommendation: str = ""):
        profile = self.service.get_vulnerability_guidance(finding_identifier)
        if profile:
            self.lbl_title.setText(f"{profile.name} ({profile.severity.value})")
            self.txt_explanation.setPlainText(f"{profile.description}\n\nTechnical:\n{profile.technical_explanation}\n\nAttack Scenario:\n{profile.attack_scenario}")
            self.txt_remediation.setPlainText(f"{profile.remediation_guidance}\n\nSecure Alternative: {profile.secure_alternative}")
            self.txt_example.setPlainText(profile.secure_coding_example)
            self.lbl_cwe.setText(profile.cwe_mapping)
            self.lbl_stride.setText(profile.stride_mapping)
        else:
            self.lbl_title.setText("Guidance Available")
            self.txt_explanation.setPlainText(fallback_description)
            self.txt_remediation.setPlainText(fallback_recommendation)
            self.txt_example.setPlainText("No specific secure coding example available.")
            self.lbl_cwe.setText("Unknown")
            self.lbl_stride.setText("Unknown")
