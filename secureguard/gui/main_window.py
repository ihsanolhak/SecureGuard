from PyQt6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QStackedWidget, QLabel
from PyQt6.QtCore import Qt
from .theme import Theme
from .views.dashboard import DashboardView
from .views.static_analysis import StaticAnalysisView
from .views.runtime_analysis import RuntimeAnalysisView
from .views.memory_analysis import MemoryAnalysisView
from .views.risk_dashboard import RiskDashboardView
from .views.finding_correlation import FindingCorrelationView
from .views.framework_mapping import FrameworkMappingView
from .views.logs import LogsView
from .views.settings import SettingsView

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureGuard - Advanced Security Analysis")
        self.setMinimumSize(800, 600)
        self.setStyleSheet(Theme.STYLESHEET)
        
        self.setup_ui()
        
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Left Navigation Panel
        self.nav_panel = QWidget()
        self.nav_panel.setObjectName("NavPanel")
        self.nav_panel.setFixedWidth(250)
        nav_layout = QVBoxLayout(self.nav_panel)
        nav_layout.setContentsMargins(0, 20, 0, 20)
        nav_layout.setSpacing(5)
        
        app_title = QLabel("SecureGuard")
        app_title.setObjectName("AppTitle")
        app_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav_layout.addWidget(app_title)
        
        # Navigation Buttons
        self.btn_dashboard = self.create_nav_button("Dashboard")
        self.btn_static = self.create_nav_button("Static Analysis")
        self.btn_runtime = self.create_nav_button("Runtime Analysis")
        self.btn_memory = self.create_nav_button("Memory Analysis")
        self.btn_risk = self.create_nav_button("Risk Assessment")
        self.btn_correlation = self.create_nav_button("Finding Correlation")
        self.btn_framework = self.create_nav_button("Framework Mapping")
        self.btn_logs = self.create_nav_button("Logs")
        self.btn_settings = self.create_nav_button("Settings")
        
        self.btn_demo = QPushButton("▶ Run Demo Mode")
        self.btn_demo.setObjectName("NavButton")
        self.btn_demo.setStyleSheet("color: #10B981; font-weight: bold;")
        
        nav_layout.addWidget(self.btn_dashboard)
        nav_layout.addWidget(self.btn_static)
        nav_layout.addWidget(self.btn_runtime)
        nav_layout.addWidget(self.btn_memory)
        nav_layout.addWidget(self.btn_risk)
        nav_layout.addWidget(self.btn_correlation)
        nav_layout.addWidget(self.btn_framework)
        nav_layout.addWidget(self.btn_logs)
        nav_layout.addWidget(self.btn_settings)
        nav_layout.addStretch()
        nav_layout.addWidget(self.btn_demo)
        
        # Main Content Area
        self.content_stack = QStackedWidget()
        self.content_stack.setContentsMargins(20, 20, 20, 20)
        
        self.view_dashboard = DashboardView()
        self.view_static = StaticAnalysisView()
        self.view_runtime = RuntimeAnalysisView()
        self.view_memory = MemoryAnalysisView()
        self.view_risk = RiskDashboardView()
        self.view_correlation = FindingCorrelationView()
        self.view_framework = FrameworkMappingView()
        self.view_logs = LogsView()
        self.view_settings = SettingsView()
        
        self.content_stack.addWidget(self.view_dashboard)
        self.content_stack.addWidget(self.view_static)
        self.content_stack.addWidget(self.view_runtime)
        self.content_stack.addWidget(self.view_memory)
        self.content_stack.addWidget(self.view_risk)
        self.content_stack.addWidget(self.view_correlation)
        self.content_stack.addWidget(self.view_framework)
        self.content_stack.addWidget(self.view_logs)
        self.content_stack.addWidget(self.view_settings)
        
        main_layout.addWidget(self.nav_panel)
        main_layout.addWidget(self.content_stack, 1)
        
        # Status Bar
        self.statusBar().showMessage("SecureGuard initialized. System ready.")
        
        # Connect signals
        self.btn_dashboard.clicked.connect(lambda: self.switch_view(0, self.btn_dashboard))
        self.btn_static.clicked.connect(lambda: self.switch_view(1, self.btn_static))
        self.btn_runtime.clicked.connect(lambda: self.switch_view(2, self.btn_runtime))
        self.btn_memory.clicked.connect(lambda: self.switch_view(3, self.btn_memory))
        self.btn_risk.clicked.connect(lambda: self.switch_view(4, self.btn_risk))
        self.btn_correlation.clicked.connect(lambda: self.switch_view(5, self.btn_correlation))
        self.btn_framework.clicked.connect(lambda: self.switch_view(6, self.btn_framework))
        self.btn_logs.clicked.connect(lambda: self.switch_view(7, self.btn_logs))
        self.btn_settings.clicked.connect(lambda: self.switch_view(8, self.btn_settings))
        self.btn_demo.clicked.connect(self.run_demo_mode)
        
        # Set default view
        self.switch_view(0, self.btn_dashboard)
        
    def create_nav_button(self, text: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName("NavButton")
        btn.setCheckable(True)
        return btn
        
    def switch_view(self, index: int, active_button: QPushButton):
        self.content_stack.setCurrentIndex(index)
        
        # Refresh global data before displaying dashboard, risk, or correlation views
        if index in [0, 4, 5]:
            self.refresh_correlation_data()
            
        # Reset all buttons
        for btn in [self.btn_dashboard, self.btn_static, self.btn_runtime, self.btn_memory,
                    self.btn_risk, self.btn_correlation, self.btn_framework, self.btn_logs, 
                    self.btn_settings, self.btn_demo]:
            btn.setChecked(False)
            
        active_button.setChecked(True)

    def refresh_correlation_data(self):
        from secureguard.core.correlation import CorrelationEngine, RiskAssessmentService
        all_vulns = []
        if hasattr(self.view_static, 'current_result') and self.view_static.current_result:
            all_vulns.extend(self.view_static.current_result.vulnerabilities)
        if hasattr(self.view_memory, 'current_vulns') and self.view_memory.current_vulns:
            all_vulns.extend(self.view_memory.current_vulns)
            
        engine = CorrelationEngine()
        correlated = engine.correlate(all_vulns)
        
        assessor = RiskAssessmentService()
        for f in correlated:
            assessor.assess_finding(f)
            
        metrics = assessor.assess_session(correlated)
        
        if hasattr(self.view_dashboard, 'update_metrics'):
            self.view_dashboard.update_metrics(metrics)
        if hasattr(self.view_risk, 'update_with_findings'):
            self.view_risk.update_with_findings(correlated)
        if hasattr(self.view_correlation, 'update_with_findings'):
            self.view_correlation.update_with_findings(correlated)

    def run_demo_mode(self):
        from PyQt6.QtWidgets import QMessageBox
        import os
        from PyQt6.QtCore import QTimer
        
        QMessageBox.information(self, "Demo Mode", "Starting Demo Mode.\\nWe will automatically analyze the vulnerable sample projects across Static, Runtime, and Memory analysis modules.")
        
        sample_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_vulnerable_programs")
        
        # 1. Static Analysis
        self.switch_view(1, self.btn_static)
        self.view_static.lbl_selected_path.setText(f"Selected Directory: {sample_dir}")
        self.view_static.run_scan(sample_dir, is_dir=True)
        
        def step_2_runtime():
            self.switch_view(2, self.btn_runtime)
            self.view_runtime.current_exe = os.path.join(sample_dir, "runtime_vuln")
            self.view_runtime.lbl_selected_path.setText(f"Selected: {os.path.basename(self.view_runtime.current_exe)}")
            self.view_runtime.chk_attack_mode.setChecked(True)
            self.view_runtime.run_executable()
            QTimer.singleShot(4000, step_3_memory)
            
        def step_3_memory():
            self.switch_view(3, self.btn_memory)
            self.view_memory.current_exe = os.path.join(sample_dir, "runtime_vuln_asan")
            self.view_memory.lbl_path.setText(f"Selected: {os.path.basename(self.view_memory.current_exe)}")
            self.view_memory.cmb_tool.setCurrentText("AddressSanitizer (ASan)")
            self.view_memory._run_analysis()
            QTimer.singleShot(6000, step_4_risk)
            
        def step_4_risk():
            self.switch_view(4, self.btn_risk)
            if hasattr(self.view_risk, "refresh_data"):
                self.view_risk.refresh_data()
            if hasattr(self.view_correlation, "refresh_data"):
                self.view_correlation.refresh_data()
            if hasattr(self.view_framework, "refresh_data"):
                self.view_framework.refresh_data()
            QTimer.singleShot(3000, step_5_reports)
            
        def step_5_reports():
            self.switch_view(7, self.btn_logs)
            QMessageBox.information(self, "Demo Mode Complete", "Demo sequence complete! You can now view the findings, frameworks, and generate reports.")
            
        QTimer.singleShot(4000, step_2_runtime)
