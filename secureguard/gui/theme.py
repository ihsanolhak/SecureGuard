class Theme:
    # Modern Cybersecurity Dark Theme Palette
    BG_APP = "#0B0F19"       # Deepest background (App background)
    BG_SIDEBAR = "#111827"   # Sidebar background
    BG_PANEL = "#111827"     # Main panel background
    BG_CARD = "#1F2937"      # Card/Widget background
    BG_INPUT = "#1F2937"     # Text input background
    
    TEXT_MAIN = "#F3F4F6"
    TEXT_MUTED = "#9CA3AF"
    
    ACCENT_PRIMARY = "#3B82F6"
    ACCENT_HOVER = "#2563EB"
    ACCENT_ACTIVE = "#1D4ED8"
    
    BORDER_COLOR = "#374151"
    
    SEVERITY_CRITICAL = "#EF4444"
    SEVERITY_HIGH = "#F59E0B"
    SEVERITY_MEDIUM = "#EAB308"
    SEVERITY_LOW = "#10B981"
    
    STYLESHEET = f"""
        /* Global Reset & Typography */
        * {{
            font-family: 'Segoe UI', 'Roboto', 'Inter', -apple-system, sans-serif;
            font-size: 10pt;
            color: {TEXT_MAIN};
        }}
        
        QMainWindow, QWidget {{
            background-color: {BG_APP};
        }}
        
        /* Prevent nested widgets from overwriting app background unless specified */
        QWidget#NavPanel, QWidget#NavPanel * {{
            background-color: transparent;
        }}
        
        /* Navigation Sidebar */
        QWidget#NavPanel {{
            background-color: {BG_SIDEBAR};
            border-right: 1px solid {BORDER_COLOR};
        }}
        
        QLabel#AppTitle {{
            font-size: 18pt;
            font-weight: 800;
            color: #FFFFFF;
            padding: 10px;
            letter-spacing: 1px;
        }}
        
        QLabel#PageTitle {{
            font-size: 22pt;
            font-weight: 800;
            color: #FFFFFF;
            padding-bottom: 15px;
            margin-bottom: 25px;
            border-bottom: 1px solid {BORDER_COLOR};
            letter-spacing: -0.5px;
        }}
        
        QPushButton#NavButton {{
            background-color: transparent;
            color: {TEXT_MUTED};
            text-align: left;
            padding: 14px 24px;
            border: none;
            font-size: 11pt;
            font-weight: 600;
            border-left: 4px solid transparent;
            border-radius: 0px;
        }}
        QPushButton#NavButton:hover {{
            background-color: {BG_CARD};
            color: {TEXT_MAIN};
        }}
        QPushButton#NavButton:checked {{
            background-color: #172033;
            color: {ACCENT_PRIMARY};
            border-left: 4px solid {ACCENT_PRIMARY};
        }}
        
        /* Dashboard Cards */
        QFrame#DashboardCard {{
            background-color: {BG_CARD};
            border-radius: 10px;
            border: 1px solid {BORDER_COLOR};
            padding: 20px;
        }}
        QFrame#DashboardCard:hover {{
            border: 1px solid {ACCENT_PRIMARY};
        }}
        
        QLabel#CardTitle {{
            color: {TEXT_MUTED};
            font-size: 11pt;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            background-color: transparent;
        }}
        
        QLabel#CardValue {{
            color: #FFFFFF;
            font-size: 28pt;
            font-weight: bold;
            margin-top: 10px;
            background-color: transparent;
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {ACCENT_PRIMARY};
            color: #FFFFFF;
            padding: 10px 20px;
            border-radius: 6px;
            border: none;
            font-size: 10pt;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background-color: {ACCENT_HOVER};
        }}
        QPushButton:pressed {{
            background-color: {ACCENT_ACTIVE};
        }}
        QPushButton:disabled {{
            background-color: {BG_CARD};
            color: {TEXT_MUTED};
        }}
        
        /* Table Styling */
        QTableWidget {{
            background-color: {BG_PANEL};
            alternate-background-color: #161F2E;
            color: {TEXT_MAIN};
            gridline-color: {BORDER_COLOR};
            border: 1px solid {BORDER_COLOR};
            border-radius: 8px;
            selection-background-color: {ACCENT_PRIMARY};
            selection-color: #FFFFFF;
            outline: none;
        }}
        QTableWidget::item {{
            padding: 8px;
            border-bottom: 1px solid #1E293B;
        }}
        QHeaderView::section {{
            background-color: {BG_CARD};
            color: {TEXT_MUTED};
            padding: 12px 8px;
            border: none;
            border-bottom: 2px solid {BORDER_COLOR};
            border-right: 1px solid {BORDER_COLOR};
            font-weight: bold;
            font-size: 10pt;
            text-transform: uppercase;
        }}
        
        /* Input & Text Areas */
        QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {{
            background-color: {BG_INPUT};
            color: {TEXT_MAIN};
            border: 1px solid {BORDER_COLOR};
            border-radius: 6px;
            padding: 8px 12px;
            selection-background-color: {ACCENT_PRIMARY};
        }}
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
            border: 1px solid {ACCENT_PRIMARY};
        }}
        
        /* Scrollbars (Modern invisible-ish) */
        QScrollBar:vertical {{
            border: none;
            background-color: transparent;
            width: 12px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background-color: {BORDER_COLOR};
            border-radius: 6px;
            min-height: 30px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical:hover {{
            background-color: {TEXT_MUTED};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
            background: none;
        }}
        
        QScrollBar:horizontal {{
            border: none;
            background-color: transparent;
            height: 12px;
            margin: 0px;
        }}
        QScrollBar::handle:horizontal {{
            background-color: {BORDER_COLOR};
            border-radius: 6px;
            min-width: 30px;
            margin: 2px;
        }}
        QScrollBar::handle:horizontal:hover {{
            background-color: {TEXT_MUTED};
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
            background: none;
        }}
        
        /* Progress Bar */
        QProgressBar {{
            background-color: {BG_CARD};
            border: 1px solid {BORDER_COLOR};
            border-radius: 6px;
            text-align: center;
            color: transparent;
            height: 8px;
            min-height: 8px;
            max-height: 8px;
        }}
        QProgressBar::chunk {{
            background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 {ACCENT_PRIMARY}, stop:1 #60A5FA);
            border-radius: 3px;
        }}
        
        /* Splitter */
        QSplitter::handle {{
            background-color: transparent;
            margin: 2px;
        }}
        QSplitter::handle:horizontal {{
            width: 6px;
        }}
        QSplitter::handle:hover {{
            background-color: {ACCENT_PRIMARY};
        }}
    """
