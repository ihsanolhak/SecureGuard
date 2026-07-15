from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, 
                             QHBoxLayout, QFileDialog, QTextEdit, QCheckBox, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QFrame, QSplitter)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QTextCursor
import os
from datetime import datetime
from secureguard.runtime_analysis.monitor import QRuntimeMonitor, RuntimeEvent, RuntimeEventType
from secureguard.logging_engine.secure_logger import SecureLogger, EventType, LogSeverity

class RuntimeAnalysisView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitor = QRuntimeMonitor()
        self.monitor.event_emitted.connect(self.on_runtime_event)
        self.monitor.finished.connect(self.on_execution_finished)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title = QLabel("Runtime Analysis")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        
        # Controls
        controls_layout = QHBoxLayout()
        self.btn_select_exe = QPushButton("Select Executable")
        self.chk_attack_mode = QCheckBox("Enable Attack Simulation (Buffer Overflow)")
        self.chk_valgrind = QCheckBox("Enable Valgrind (Future)")
        self.btn_run = QPushButton("Run Sandbox")
        self.btn_stop = QPushButton("Stop Execution")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background-color: #EF4444;") # Red button for stop
        
        controls_layout.addWidget(self.btn_select_exe)
        controls_layout.addWidget(self.chk_attack_mode)
        controls_layout.addWidget(self.chk_valgrind)
        controls_layout.addStretch()
        controls_layout.addWidget(self.btn_run)
        controls_layout.addWidget(self.btn_stop)
        
        layout.addLayout(controls_layout)
        
        self.lbl_selected_path = QLabel("Selected: None")
        self.lbl_selected_path.setStyleSheet("color: #888888; font-style: italic; margin-bottom: 10px;")
        layout.addWidget(self.lbl_selected_path)
        
        # Risk Dashboard (Mini cards)
        dashboard_layout = QHBoxLayout()
        self.lbl_runs = self.create_metric_card("Total Runs", "0")
        self.lbl_crashes = self.create_metric_card("Crashes Detected", "0", "#EF4444")
        self.lbl_warnings = self.create_metric_card("Warnings", "0", "#F59E0B")
        dashboard_layout.addWidget(self.lbl_runs)
        dashboard_layout.addWidget(self.lbl_crashes)
        dashboard_layout.addWidget(self.lbl_warnings)
        layout.addLayout(dashboard_layout)
        
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Real-time event log
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0,0,0,0)
        lbl_log = QLabel("Real-Time Event Log")
        lbl_log.setStyleSheet("font-weight: bold; margin-top: 10px; margin-bottom: 5px;")
        log_layout.addWidget(lbl_log)
        
        self.txt_output = QTextEdit()
        self.txt_output.setReadOnly(True)
        self.txt_output.setStyleSheet("font-family: 'Consolas', monospace; background-color: #0D1117; padding: 10px;")
        log_layout.addWidget(self.txt_output)
        
        # Execution History Table
        history_widget = QWidget()
        hist_layout = QVBoxLayout(history_widget)
        hist_layout.setContentsMargins(0,0,0,0)
        lbl_hist = QLabel("Execution History")
        lbl_hist.setStyleSheet("font-weight: bold; margin-top: 10px; margin-bottom: 5px;")
        hist_layout.addWidget(lbl_hist)
        
        self.table_history = QTableWidget(0, 4)
        self.table_history.setHorizontalHeaderLabels(["Timestamp", "Executable", "Mode", "Status"])
        header = self.table_history.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hist_layout.addWidget(self.table_history)
        
        self.splitter.addWidget(log_widget)
        self.splitter.addWidget(history_widget)
        self.splitter.setSizes([400, 200])
        
        layout.addWidget(self.splitter, 1)
        
        # Connect signals
        self.btn_select_exe.clicked.connect(self.select_exe)
        self.btn_run.clicked.connect(self.run_executable)
        self.btn_stop.clicked.connect(self.stop_execution)
        self.chk_valgrind.stateChanged.connect(self.toggle_valgrind)
        
        # State
        self.current_exe = ""
        self.runs_count = 0
        self.crash_count = 0
        self.warning_count = 0

    def create_metric_card(self, title, value, color="#F3F4F6"):
        frame = QFrame()
        frame.setObjectName("DashboardCard")
        l = QVBoxLayout(frame)
        t = QLabel(title)
        t.setObjectName("CardTitle")
        v = QLabel(value)
        v.setObjectName("CardValue")
        v.setStyleSheet(f"color: {color};")
        l.addWidget(t, 0, Qt.AlignmentFlag.AlignCenter)
        l.addWidget(v, 0, Qt.AlignmentFlag.AlignCenter)
        return frame

    def select_exe(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Executable", "", "Executables (*);;All Files (*)")
        if file_path:
            self.current_exe = file_path
            self.lbl_selected_path.setText(f"Selected: {file_path}")
            os.chmod(file_path, 0o755)

    def toggle_valgrind(self, state):
        self.monitor.use_valgrind = self.chk_valgrind.isChecked()

    def run_executable(self):
        if not self.current_exe:
            self.append_log("ERROR: No executable selected.", "#EF4444")
            return
            
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.txt_output.clear()
        
        self.runs_count += 1
        self.update_dashboards()
        
        SecureLogger().log(
            EventType.RUNTIME, LogSeverity.INFO,
            f"Runtime execution started: {self.current_exe} "
            f"(attack={'ON' if self.chk_attack_mode.isChecked() else 'OFF'})"
        )
        self.monitor.start_monitoring(self.current_exe, self.chk_attack_mode.isChecked())

    def stop_execution(self):
        self.monitor.stop_monitoring()

    def on_runtime_event(self, event: RuntimeEvent):
        color = "#F3F4F6"
        if event.event_type == RuntimeEventType.SAFE:
            color = "#10B981" # Emerald green
        elif event.event_type == RuntimeEventType.WARNING:
            color = "#F59E0B" # Amber/Orange
            self.warning_count += 1
            self.update_dashboards()
        elif event.event_type == RuntimeEventType.ALERT:
            color = "#F97316" # Deeper Orange
        elif event.event_type == RuntimeEventType.CRITICAL:
            color = "#EF4444" # Red
            
        # Insert without adding extra blank lines due to div
        msg = event.message.replace('<', '&lt;').replace('>', '&gt;')
        self.txt_output.moveCursor(QTextCursor.MoveOperation.End)
        self.txt_output.insertHtml(f'<span style="color: {color}; font-weight: bold;">[{event.event_type.value}]</span> <span style="color: #D4D4D4;">{msg}</span><br>')
        self.txt_output.moveCursor(QTextCursor.MoveOperation.End)

    def on_execution_finished(self, exit_code, crashed):
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        
        if crashed:
            self.crash_count += 1
            status = "CRASHED"
            color = Qt.GlobalColor.red
            SecureLogger().log(
                EventType.RUNTIME, LogSeverity.CRITICAL,
                f"Runtime CRASH detected: {os.path.basename(self.current_exe)} (exit {exit_code})"
            )
        else:
            status = "SUCCESS"
            color = Qt.GlobalColor.green
            SecureLogger().log(
                EventType.RUNTIME, LogSeverity.INFO,
                f"Runtime execution completed: {os.path.basename(self.current_exe)} (exit {exit_code})"
            )
            
        self.update_dashboards()
        self.add_history_entry(status, color)

    def append_log(self, text, color):
        self.txt_output.moveCursor(QTextCursor.MoveOperation.End)
        self.txt_output.insertHtml(f'<span style="color: {color};">{text}</span><br>')
        self.txt_output.moveCursor(QTextCursor.MoveOperation.End)

    def update_dashboards(self):
        self.lbl_runs.findChild(QLabel, "CardValue").setText(str(self.runs_count))
        self.lbl_crashes.findChild(QLabel, "CardValue").setText(str(self.crash_count))
        self.lbl_warnings.findChild(QLabel, "CardValue").setText(str(self.warning_count))

    def add_history_entry(self, status, color):
        row = self.table_history.rowCount()
        self.table_history.insertRow(row)
        
        self.table_history.setItem(row, 0, QTableWidgetItem(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        self.table_history.setItem(row, 1, QTableWidgetItem(os.path.basename(self.current_exe)))
        mode = "Attack Sim" if self.chk_attack_mode.isChecked() else "Normal"
        self.table_history.setItem(row, 2, QTableWidgetItem(mode))
        
        status_item = QTableWidgetItem(status)
        status_item.setForeground(color)
        self.table_history.setItem(row, 3, status_item)
