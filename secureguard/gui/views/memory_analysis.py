from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton,
                             QHBoxLayout, QFileDialog, QTextEdit, QCheckBox,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QFrame, QSplitter, QProgressBar, QMessageBox, QComboBox)
from PyQt6.QtCore import Qt, QProcess, QProcessEnvironment
from PyQt6.QtGui import QColor, QTextCursor
import os
import json
from typing import List
from datetime import datetime
from secureguard.runtime_analysis.valgrind_engine import ValgrindEngine
from secureguard.runtime_analysis.asan_engine import AsanEngine, AsanErrorType
from secureguard.core.models import Severity, Vulnerability
from secureguard.logging_engine.secure_logger import SecureLogger, EventType, LogSeverity


class MemoryAnalysisView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = ValgrindEngine()
        self.asan_engine = AsanEngine()
        
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self._handle_stdout)
        self.process.readyReadStandardError.connect(self._handle_stderr)
        self.process.finished.connect(self._on_finished)
        self.process.errorOccurred.connect(self._on_error)

        self.stderr_buffer = ""
        self.stdout_buffer = ""
        self.current_exe = ""
        self.current_vulns = []
        self.runs_count = 0
        self.issues_count = 0
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Memory & Sanitizer Analysis")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        # Controls
        controls = QHBoxLayout()
        self.btn_select = QPushButton("Select File (C/C++ or Binary)")
        
        lbl_tool = QLabel("Tool:")
        lbl_tool.setStyleSheet("color: #E5E7EB; font-weight: bold; margin-left: 10px;")
        
        self.cmb_tool = QComboBox()
        self.cmb_tool.addItems(["AddressSanitizer (ASan)", "Valgrind (memcheck)"])
        self.cmb_tool.setStyleSheet("background-color: #1F2937; color: white; padding: 4px; border-radius: 4px;")
        
        self.chk_attack = QCheckBox("Attack Simulation")
        
        self.btn_run = QPushButton("Run Analysis")
        self.btn_run.setStyleSheet("background-color: #8B5CF6;")
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background-color: #EF4444;")
        
        self.btn_export = QPushButton("Export Report")
        self.btn_export.setEnabled(False)

        controls.addWidget(self.btn_select)
        controls.addWidget(lbl_tool)
        controls.addWidget(self.cmb_tool)
        controls.addWidget(self.chk_attack)
        controls.addStretch()
        controls.addWidget(self.btn_run)
        controls.addWidget(self.btn_stop)
        controls.addWidget(self.btn_export)
        layout.addLayout(controls)

        self.lbl_path = QLabel("Selected: None")
        self.lbl_path.setStyleSheet("color: #9CA3AF; font-style: italic;")
        layout.addWidget(self.lbl_path)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        # Dashboard cards
        dash = QHBoxLayout()
        self.card_runs = self._make_card("Scans Run", "0")
        self.card_issues = self._make_card("Issues Found", "0", "#EF4444")
        self.card_leaks = self._make_card("Memory Leaks", "0", "#F59E0B")
        self.card_invalid = self._make_card("Invalid Access", "0", "#EF4444")
        dash.addWidget(self.card_runs)
        dash.addWidget(self.card_issues)
        dash.addWidget(self.card_leaks)
        dash.addWidget(self.card_invalid)
        layout.addLayout(dash)

        # Splitter: results table + detail view
        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # Findings table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Severity", "Type", "File", "Line", "Description", "Recommendation"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.splitter.addWidget(self.table)

        # Detail panel
        detail_splitter = QSplitter(Qt.Orientation.Vertical)
        
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)

        self.lbl_detail_title = QLabel("Finding Details")
        self.lbl_detail_title.setStyleSheet("font-weight: bold;")
        detail_layout.addWidget(self.lbl_detail_title)

        self.txt_detail = QTextEdit()
        self.txt_detail.setReadOnly(True)
        self.txt_detail.setStyleSheet(
            "font-family: 'Consolas', monospace; background-color: #0D1117; padding: 10px;"
        )
        detail_layout.addWidget(self.txt_detail)

        detail_splitter.addWidget(detail_widget)
        
        from gui.components.knowledge_panel import KnowledgePanel
        self.knowledge_panel = KnowledgePanel()
        detail_splitter.addWidget(self.knowledge_panel)

        self.splitter.addWidget(detail_splitter)
        self.splitter.setSizes([600, 400])
        layout.addWidget(self.splitter, 1)

        # Connect signals
        self.btn_select.clicked.connect(self._select_exe)
        self.btn_run.clicked.connect(self._run_analysis)
        self.btn_stop.clicked.connect(self._stop)
        self.btn_export.clicked.connect(self._export)
        self.table.itemSelectionChanged.connect(self._on_row_selected)

    # ── UI helpers ──────────────────────────────────────

    def _make_card(self, title: str, value: str, color: str = "#F3F4F6") -> QFrame:
        frame = QFrame()
        frame.setObjectName("DashboardCard")
        lo = QVBoxLayout(frame)
        t = QLabel(title)
        t.setObjectName("CardTitle")
        t.setWordWrap(True)
        v = QLabel(value)
        v.setObjectName("CardValue")
        v.setWordWrap(True)
        v.setStyleSheet(f"color: {color};")
        lo.addWidget(t, 0, Qt.AlignmentFlag.AlignCenter)
        lo.addWidget(v, 0, Qt.AlignmentFlag.AlignCenter)
        return frame

    def _update_card(self, card: QFrame, value: str):
        lbl = card.findChild(QLabel, "CardValue")
        if lbl:
            lbl.setText(value)

    def _color_for_severity(self, sev: Severity) -> QColor:
        return {
            Severity.CRITICAL: QColor("#EF4444"),
            Severity.HIGH: QColor("#F59E0B"),
            Severity.MEDIUM: QColor("#EAB308"),
            Severity.LOW: QColor("#10B981"),
        }.get(sev, QColor("#F3F4F6"))

    # ── Actions ─────────────────────────────────────────

    def _select_exe(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select C/C++ Source or Executable", "", "C/C++ Files (*.c *.cpp *.cc);;All Files (*)")
        if path:
            self.current_exe = path
            self.lbl_path.setText(f"Selected: {path}")
            if not path.endswith(('.c', '.cpp', '.cc', '.cxx')):
                os.chmod(path, 0o755)

    def compile_for_valgrind(self, source_path: str) -> str:
        import subprocess
        base, ext = os.path.splitext(source_path)
        output_path = base + "_valgrind"
        compiler = "g++" if ext in (".cpp", ".cc", ".cxx") else "gcc"
        cmd = [compiler, "-g", "-O0", "-o", output_path, source_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        os.chmod(output_path, 0o755)
        return output_path

    def _run_analysis(self):
        if not self.current_exe:
            QMessageBox.warning(self, "No File Selected", "Please select a source file or executable first.")
            return

        self.stderr_buffer = ""
        self.stdout_buffer = ""
        self.table.setRowCount(0)
        self.txt_detail.clear()
        self.current_vulns = []
        self.progress.setValue(10)
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_export.setEnabled(False)

        tool_label = "ASan" if self.cmb_tool.currentIndex() == 0 else "Valgrind"
        SecureLogger().log(
            EventType.MEMORY, LogSeverity.INFO,
            f"Memory analysis started ({tool_label}): {self.current_exe}"
        )

        is_source = self.current_exe.endswith(('.c', '.cpp', '.cc', '.cxx'))
        run_exe = self.current_exe

        # Compilation step for source files
        if is_source:
            self.progress.setValue(20)
            self.txt_detail.setPlainText("Compiling source file with selected tool configuration...")
            try:
                if self.cmb_tool.currentIndex() == 0:  # ASan
                    run_exe = self.asan_engine.compile_source(self.current_exe)
                else:  # Valgrind
                    run_exe = self.compile_for_valgrind(self.current_exe)
            except Exception as e:
                self.progress.setValue(0)
                QMessageBox.critical(self, "Compilation Error", f"Failed to compile source:\n\n{str(e)}")
                self.btn_run.setEnabled(True)
                self.btn_stop.setEnabled(False)
                self.txt_detail.setPlainText(f"Compilation failed:\n{str(e)}")
                return

        self.progress.setValue(45)

        tool_idx = self.cmb_tool.currentIndex()
        if tool_idx == 0:  # AddressSanitizer
            env = QProcessEnvironment.systemEnvironment()
            env.insert("ASAN_OPTIONS", "detect_leaks=1")
            self.process.setProcessEnvironment(env)
            
            program = run_exe
            args = []
            if self.chk_attack.isChecked():
                args.append("A" * 150)
            else:
                args.append("SafeInputData")
        else:  # Valgrind
            program, args = self.engine.build_command(
                run_exe, attack_mode=self.chk_attack.isChecked()
            )

        self.process.start(program, args)
        
        # Write to stdin and close channel to support programs reading stdin
        if self.chk_attack.isChecked():
            self.process.write(b"A" * 150 + b"\n")
        else:
            self.process.write(b"SafeInputData\n")
        self.process.closeWriteChannel()

    def _stop(self):
        if self.process.state() == QProcess.ProcessState.Running:
            self.process.kill()

    # ── Process signal handlers ─────────────────────────

    def _handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode(errors="ignore")
        self.stdout_buffer += data

    def _handle_stderr(self):
        data = self.process.readAllStandardError().data().decode(errors="ignore")
        self.stderr_buffer += data

    def _on_error(self, error):
        self.progress.setValue(0)
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        
        tool_name = "AddressSanitizer" if self.cmb_tool.currentIndex() == 0 else "Valgrind"
        QMessageBox.critical(
            self,
            f"{tool_name} Error",
            f"Could not execute analysis.\n\n{self.process.errorString()}",
        )

    def correlate_valgrind_findings(self, source_path: str, valgrind_vulns: List[Vulnerability]) -> List[Vulnerability]:
        if not source_path or not os.path.exists(source_path):
            return valgrind_vulns
            
        try:
            from static_analysis.scanner import RegexStaticScanner
            scanner = RegexStaticScanner()
            static_result = scanner.scan_file(source_path)
            static_vulns = static_result.vulnerabilities
        except Exception:
            return valgrind_vulns
            
        correlated_vulns = []
        for av in valgrind_vulns:
            matched = False
            for sv in static_vulns:
                if os.path.basename(av.file_path) == os.path.basename(sv.file_path) and av.line_number == sv.line_number:
                    av.vuln_type = f"[Correlated] {av.vuln_type[11:]}"  # Strip '[Valgrind] ' and prefix '[Correlated] '
                    av.description = (
                        f"⚠️ **EXPLOIT CONFIRMED (Static & Runtime Match)**\n\n"
                        f"**Static Rule Triggered**: {sv.description}\n"
                        f"**Valgrind Runtime Detection**: {av.description}"
                    )
                    av.recommendation = (
                        f"CRITICAL: Fix immediately.\n"
                        f"Runtime suggestion: {av.recommendation}\n"
                        f"Static suggestion: {sv.recommendation}"
                    )
                    matched = True
                    break
            correlated_vulns.append(av)
        return correlated_vulns

    def _on_finished(self, exit_code, exit_status):
        self.progress.setValue(80)
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)

        tool_idx = self.cmb_tool.currentIndex()

        if tool_idx == 0:  # AddressSanitizer
            findings = self.asan_engine.parse_output(self.stderr_buffer)
            vulns = self.asan_engine.to_vulnerabilities(findings)
            if self.current_exe.endswith(('.c', '.cpp', '.cc', '.cxx')):
                vulns = self.asan_engine.correlate_findings(self.current_exe, vulns)
            
            self.current_vulns = vulns
            self.runs_count += 1
            self.issues_count = len(vulns)

            leak_count = sum(1 for f in findings if f.error_type == AsanErrorType.MEMORY_LEAK)
            invalid_count = sum(1 for f in findings if f.error_type in (
                AsanErrorType.STACK_BUFFER_OVERFLOW, AsanErrorType.HEAP_BUFFER_OVERFLOW,
                AsanErrorType.GLOBAL_BUFFER_OVERFLOW, AsanErrorType.USE_AFTER_FREE,
                AsanErrorType.STACK_USE_AFTER_SCOPE, AsanErrorType.STACK_USE_AFTER_RETURN,
                AsanErrorType.DOUBLE_FREE, AsanErrorType.INVALID_FREE
            ))
        else:  # Valgrind
            findings = self.engine.parse_output(self.stderr_buffer)
            vulns = self.engine.to_vulnerabilities(findings)
            if self.current_exe.endswith(('.c', '.cpp', '.cc', '.cxx')):
                vulns = self.correlate_valgrind_findings(self.current_exe, vulns)
            
            self.current_vulns = vulns
            self.runs_count += 1
            self.issues_count = len(vulns)

            leak_count = sum(1 for f in findings if f.error_type.value == "Memory Leak")
            invalid_count = sum(
                1 for f in findings if f.error_type.value in ("Invalid Read", "Invalid Write")
            )

        self._update_card(self.card_runs, str(self.runs_count))
        self._update_card(self.card_issues, str(self.issues_count))
        self._update_card(self.card_leaks, str(leak_count))
        self._update_card(self.card_invalid, str(invalid_count))

        # Populate table
        self.table.setRowCount(len(vulns))
        for row, v in enumerate(vulns):
            sev_item = QTableWidgetItem(v.severity.value)
            sev_item.setForeground(self._color_for_severity(v.severity))

            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, QTableWidgetItem(v.vuln_type))
            self.table.setItem(row, 2, QTableWidgetItem(
                os.path.basename(v.file_path) if v.file_path else "—"
            ))
            self.table.setItem(row, 3, QTableWidgetItem(str(v.line_number)))
            # Truncate description for table cell
            short_desc = v.description.split("\n")[0][:120]
            self.table.setItem(row, 4, QTableWidgetItem(short_desc))
            self.table.setItem(row, 5, QTableWidgetItem(v.recommendation))

        self.progress.setValue(100)
        if vulns:
            self.btn_export.setEnabled(True)

        tool_name = "AddressSanitizer" if tool_idx == 0 else "Valgrind"
        summary = (
            f"{tool_name} analysis complete.\n"
            f"File: {os.path.basename(self.current_exe)}\n"
            f"Exit code: {exit_code}\n"
            f"Total issues: {len(vulns)}\n"
            f"Memory leaks: {leak_count}\n"
            f"Invalid accesses: {invalid_count}\n"
        )
        if not vulns:
            summary += "\n✅ No memory issues detected!"
        self.txt_detail.setPlainText(summary)

        sev = LogSeverity.CRITICAL if len(vulns) > 0 else LogSeverity.INFO
        SecureLogger().log(
            EventType.MEMORY, sev,
            f"{tool_name} analysis done on {os.path.basename(self.current_exe)}: "
            f"{len(vulns)} issues, {leak_count} leaks, {invalid_count} invalid accesses"
        )
        for v in vulns:
            SecureLogger().log(
                EventType.SECURITY, LogSeverity.WARNING,
                f"[{tool_name}] {v.severity.value} — {v.vuln_type} in {v.file_path}:{v.line_number}"
            )

    # ── Row selection ───────────────────────────────────

    def _on_row_selected(self):
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        if row >= len(self.current_vulns):
            return

        v = self.current_vulns[row]
        detail = (
            f"{'═' * 50}\n"
            f"  {v.vuln_type}\n"
            f"{'═' * 50}\n\n"
            f"Severity:       {v.severity.value}\n"
            f"File:           {v.file_path}\n"
            f"Line:           {v.line_number}\n\n"
            f"Description:\n{v.description}\n\n"
            f"{'─' * 50}\n"
            f"Recommendation:\n{v.recommendation}\n"
        )
        self.txt_detail.setPlainText(detail)
        
        self.knowledge_panel.update_knowledge(
            finding_identifier=v.vuln_type,
            fallback_description=v.description,
            fallback_recommendation=v.recommendation
        )

    # ── Export ──────────────────────────────────────────

    def _export(self):
        if not self.current_vulns:
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Memory Analysis Report", "memory_report.json", "JSON Files (*.json)"
        )
        if not path:
            return

        tool_name = "AddressSanitizer" if self.cmb_tool.currentIndex() == 0 else "Valgrind"
        report = {
            "report_type": f"{tool_name} Memory Analysis",
            "timestamp": datetime.now().isoformat(),
            "target": self.current_exe,
            "total_issues": len(self.current_vulns),
            "findings": [],
        }
        for v in self.current_vulns:
            report["findings"].append({
                "id": v.id,
                "severity": v.severity.value,
                "type": v.vuln_type,
                "file": v.file_path,
                "line": v.line_number,
                "description": v.description,
                "recommendation": v.recommendation,
            })

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            QMessageBox.information(self, "Export Success", f"Report exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))
