from PyQt6.QtWidgets import QFrame, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

class DashboardCard(QFrame):
    def __init__(self, title: str, value: str, color: str = None, parent=None):
        super().__init__(parent)
        self.setObjectName("DashboardCard")
        self.color = color or "#2196F3"
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        self.title_label = QLabel(title)
        self.title_label.setObjectName("CardTitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setWordWrap(True)
        
        self.value_label = QLabel(value)
        self.value_label.setObjectName("CardValue")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_label.setWordWrap(True)
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        
        # Apply color styling
        self._apply_color_style()
    
    def _apply_color_style(self):
        """Apply color styling to the card."""
        self.setStyleSheet(f"""
            QFrame#DashboardCard {{
                border: 2px solid {self.color};
                border-radius: 8px;
                background-color: #252526;
                padding: 10px;
            }}
            QLabel#CardTitle {{
                font-size: 12px;
                color: #888888;
                font-weight: bold;
            }}
            QLabel#CardValue {{
                font-size: 24px;
                color: {self.color};
                font-weight: bold;
            }}
        """)
    
    def update_value(self, new_value: str):
        """Update the card value."""
        self.value_label.setText(new_value)
    
    def update_color(self, new_color: str):
        """Update the card color."""
        self.color = new_color
        self._apply_color_style()

