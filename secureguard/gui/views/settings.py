from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QCheckBox, QPushButton

class SettingsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title = QLabel("Settings")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        
        self.chk_dark_mode = QCheckBox("Enable Dark Mode")
        self.chk_dark_mode.setChecked(True)
        
        self.chk_auto_scan = QCheckBox("Auto-scan on file change")
        
        layout.addWidget(self.chk_dark_mode)
        layout.addWidget(self.chk_auto_scan)
        
        btn_save = QPushButton("Save Settings")
        layout.addWidget(btn_save)
        
        layout.addStretch()
