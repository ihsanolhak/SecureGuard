from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QHBoxLayout, QFileDialog, QProgressBar, QMessageBox, QSplitter, QTextEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QTextCharFormat, QColor, QSyntaxHighlighter, QFont
from secureguard.static_analysis.scanner import RegexStaticScanner
from secureguard.core.models import ScanResult
from secureguard.logging_engine.secure_logger import SecureLogger, EventType, LogSeverity
import os

class CSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.highlightingRules = []

        keywordFormat = QTextCharFormat()
        keywordFormat.setForeground(QColor("#569CD6"))
        keywordFormat.setFontWeight(QFont.Weight.Bold)
        keywords = [
            "char", "class", "const", "double", "enum", "explicit",
            "friend", "inline", "int", "long", "namespace", "operator",
            "private", "protected", "public", "short", "signals", "signed",
            "slots", "static", "struct", "template", "typedef", "typename",
            "union", "unsigned", "virtual", "void", "volatile", "if", "else", 
            "return", "for", "while"
        ]
        for word in keywords:
            pattern = rf"\b{word}\b"
            self.highlightingRules.append((pattern, keywordFormat))

        stringFormat = QTextCharFormat()
        stringFormat.setForeground(QColor("#CE9178"))
        self.highlightingRules.append((r'".*"', stringFormat))

        commentFormat = QTextCharFormat()
        commentFormat.setForeground(QColor("#6A9955"))
        self.highlightingRules.append((r'//[^\n]*', commentFormat))

        self.vulnLineFormat = QTextCharFormat()
        self.vulnLineFormat.setBackground(QColor("#4B1818")) # Dark red background for vuln line
        self.vuln_line = -1

    def set_vulnerable_line(self, line):
        self.vuln_line = line
        self.rehighlight()

    def highlightBlock(self, text):
        import re
        for pattern, format in self.highlightingRules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), format)
                
        # If this block is the vulnerable line, highlight the whole block
        block = self.currentBlock()
        line_number = block.blockNumber() + 1
        if line_number == self.vuln_line:
            self.setFormat(0, len(text), self.vulnLineFormat)

class ScannerThread(QThread):
    finished = pyqtSignal(ScanResult)
    progress = pyqtSignal(int)
    
    def __init__(self, path: str, is_dir: bool):
        super().__init__()
        self.path = path
        self.is_dir = is_dir
        self.scanner = RegexStaticScanner()
        
    def run(self):
        self.progress.emit(10)
        
        if self.is_dir:
            result = self.scanner.scan_directory(self.path)
        else:
            result = self.scanner.scan_file(self.path)
            
        self.progress.emit(100)
        self.finished.emit(result)

class StaticAnalysisView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = RegexStaticScanner()
        self.current_result = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title = QLabel("Static Code Analysis")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        
        # Controls
        controls_layout = QHBoxLayout()
        self.btn_select_file = QPushButton("Scan File")
        self.btn_select_dir = QPushButton("Scan Directory")
        self.btn_export = QPushButton("Export to JSON")
        self.btn_export.setEnabled(False)
        
        self.lbl_status = QLabel("Status: Ready")
        
        controls_layout.addWidget(self.btn_select_file)
        controls_layout.addWidget(self.btn_select_dir)
        controls_layout.addWidget(self.btn_export)
        controls_layout.addWidget(self.lbl_status)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        self.lbl_selected_path = QLabel("Selected: None")
        self.lbl_selected_path.setStyleSheet("color: #888888; font-style: italic;")
        layout.addWidget(self.lbl_selected_path)
        
        # Progress and Risk
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        
        self.lbl_risk_score = QLabel("Risk Score: N/A")
        self.lbl_risk_score.setStyleSheet("font-size: 12pt; font-weight: bold; color: #E0E0E0;")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.lbl_risk_score)
        layout.addLayout(progress_layout)
        
        # Splitter for Table and Preview
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Table
        self.table = QTableWidget(0, 7) # Added Hidden path column
        self.table.setHorizontalHeaderLabels([
            "Severity", "Type", "File", "Line", "Description", "Recommendation", "Path"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(False)
        self.table.setColumnHidden(6, True) # Hide the full path
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        self.splitter.addWidget(self.table)
        
        # Right Side Splitter
        right_splitter = QSplitter(Qt.Orientation.Vertical)

        # Code Preview
        preview_widget = QWidget()
        preview_layout = QVBoxLayout(preview_widget)
        preview_layout.setContentsMargins(0,0,0,0)
        self.lbl_preview_title = QLabel("Code Preview")
        self.lbl_preview_title.setObjectName("PageTitle")
        self.code_editor = QTextEdit()
        self.code_editor.setReadOnly(True)
        self.code_editor.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; background-color: #1E1E1E; color: #D4D4D4;")
        self.highlighter = CSyntaxHighlighter(self.code_editor.document())
        
        preview_layout.addWidget(self.lbl_preview_title)
        preview_layout.addWidget(self.code_editor)
        
        right_splitter.addWidget(preview_widget)
        
        # Knowledge Panel
        from gui.components.knowledge_panel import KnowledgePanel
        self.knowledge_panel = KnowledgePanel()
        right_splitter.addWidget(self.knowledge_panel)
        
        self.splitter.addWidget(right_splitter)
        self.splitter.setSizes([500, 500])
        
        layout.addWidget(self.splitter, 1) # Added stretch factor 1 so it fills the space
        
        # Connect signals
        self.btn_select_file.clicked.connect(self.select_file)
        self.btn_select_dir.clicked.connect(self.select_dir)
        self.btn_export.clicked.connect(self.export_json)
        self.table.itemSelectionChanged.connect(self.on_table_selection)
        
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select C/C++ File", "", "C/C++ Files (*.c *.cpp *.h *.hpp);;All Files (*)")
        if file_path:
            self.lbl_selected_path.setText(f"Selected File: {file_path}")
            self.run_scan(file_path, is_dir=False)
            
    def select_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if dir_path:
            self.lbl_selected_path.setText(f"Selected Directory: {dir_path}")
            self.run_scan(dir_path, is_dir=True)
            
    def run_scan(self, path: str, is_dir: bool):
        self.lbl_status.setText("Status: Scanning...")
        self.progress_bar.setValue(0)
        self.btn_export.setEnabled(False)
        self.table.setRowCount(0)
        self.code_editor.clear()
        self.lbl_risk_score.setText("Risk Score: N/A")
        self.lbl_risk_score.setStyleSheet("font-size: 12pt; font-weight: bold; color: #E0E0E0;")
        
        SecureLogger().log(EventType.SCAN, LogSeverity.INFO, f"Static scan started: {path}")
        
        self.thread = ScannerThread(path, is_dir)
        self.thread.progress.connect(self.progress_bar.setValue)
        self.thread.finished.connect(self.on_scan_finished)
        self.thread.start()
        
    def on_scan_finished(self, result: ScanResult):
        self.current_result = result
        self.lbl_status.setText(f"Status: Scan Complete. Found {len(result.vulnerabilities)} issues across {result.files_scanned} files.")
        self.lbl_risk_score.setText(f"Risk Score: {result.risk_score} / 10.0")
        
        sev = LogSeverity.WARNING if result.risk_score >= 4.0 else LogSeverity.INFO
        if result.risk_score >= 7.0:
            sev = LogSeverity.CRITICAL
        SecureLogger().log(
            EventType.SCAN, sev,
            f"Static scan complete: {result.files_scanned} files, "
            f"{len(result.vulnerabilities)} vulns, risk {result.risk_score}/10"
        )
        for v in result.vulnerabilities:
            SecureLogger().log(
                EventType.SECURITY, LogSeverity.WARNING,
                f"[Static] {v.severity.value} — {v.vuln_type} in {v.file_path}:{v.line_number}"
            )
        
        if result.risk_score >= 7.0:
            self.lbl_risk_score.setStyleSheet("font-size: 12pt; font-weight: bold; color: #FF3333;")
        elif result.risk_score >= 4.0:
            self.lbl_risk_score.setStyleSheet("font-size: 12pt; font-weight: bold; color: #FF8C00;")
        else:
            self.lbl_risk_score.setStyleSheet("font-size: 12pt; font-weight: bold; color: #33CC33;")
            
        self.table.setRowCount(len(result.vulnerabilities))
        for row, vuln in enumerate(result.vulnerabilities):
            sev_item = QTableWidgetItem(vuln.severity.value)
            
            from core.models import Severity
            if vuln.severity == Severity.CRITICAL:
                sev_item.setForeground(Qt.GlobalColor.red)
            elif vuln.severity == Severity.HIGH:
                sev_item.setForeground(Qt.GlobalColor.darkYellow)
            elif vuln.severity == Severity.MEDIUM:
                sev_item.setForeground(Qt.GlobalColor.yellow)
            else:
                sev_item.setForeground(Qt.GlobalColor.green)
                
            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, QTableWidgetItem(vuln.vuln_type))
            self.table.setItem(row, 2, QTableWidgetItem(os.path.basename(vuln.file_path)))
            self.table.setItem(row, 3, QTableWidgetItem(str(vuln.line_number)))
            self.table.setItem(row, 4, QTableWidgetItem(vuln.description))
            self.table.setItem(row, 5, QTableWidgetItem(vuln.recommendation))
            self.table.setItem(row, 6, QTableWidgetItem(vuln.file_path)) # Hidden full path
            
        if len(result.vulnerabilities) > 0:
            self.btn_export.setEnabled(True)

    def on_table_selection(self):
        selected_items = self.table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        file_path = self.table.item(row, 6).text()
        line_num = int(self.table.item(row, 3).text())
        vuln_type = self.table.item(row, 1).text()
        description = self.table.item(row, 4).text()
        recommendation = self.table.item(row, 5).text()
        
        self.knowledge_panel.update_knowledge(
            finding_identifier=vuln_type,
            fallback_description=description,
            fallback_recommendation=recommendation
        )
        
        self.lbl_preview_title.setText(f"Code Preview - {os.path.basename(file_path)}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            self.highlighter.set_vulnerable_line(line_num)
            self.code_editor.setPlainText(content)
            
            from PyQt6.QtWidgets import QApplication
            QApplication.processEvents() # Force layout update so scroll works
            
            # Scroll to line
            cursor = self.code_editor.textCursor()
            block = self.code_editor.document().findBlockByNumber(line_num - 1)
            cursor.setPosition(block.position())
            self.code_editor.setTextCursor(cursor)
            self.code_editor.ensureCursorVisible()
            
        except Exception as e:
            self.code_editor.setPlainText(f"Failed to load file: {str(e)}")

    def export_json(self):
        if not self.current_result:
            return
            
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Report to JSON", "scan_report.json", "JSON Files (*.json)")
        if file_path:
            success = self.scanner.export_to_json(self.current_result, file_path)
            if success:
                QMessageBox.information(self, "Export Success", f"Successfully exported to {file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to export report.")
