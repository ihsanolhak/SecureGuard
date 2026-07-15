from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QLineEdit, QComboBox, QFrame,
                             QMessageBox, QTextEdit, QSplitter, QFileDialog)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from secureguard.logging_engine.secure_logger import (
    SecureLogger, LogVerifier, EventType, LogSeverity
)


class LogsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = SecureLogger()
        self.all_entries = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Tamper-Proof Audit Logs")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        # ── Controls row ────────────────────────────────
        controls = QHBoxLayout()

        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setStyleSheet("background-color: #3B82F6;")

        self.btn_verify = QPushButton("Verify Integrity")
        self.btn_verify.setStyleSheet("background-color: #8B5CF6; font-weight: bold;")

        self.btn_export = QPushButton("Export Report")
        self.btn_export.setStyleSheet("background-color: #10B981;")

        controls.addWidget(self.btn_refresh)
        controls.addWidget(self.btn_verify)
        controls.addWidget(self.btn_export)
        controls.addStretch()
        layout.addLayout(controls)

        # ── Integrity status banner ─────────────────────
        self.integrity_banner = QFrame()
        self.integrity_banner.setFixedHeight(36)
        self.integrity_banner.setStyleSheet(
            "background-color: #1F2937; border-radius: 6px; padding: 4px 12px;"
        )
        banner_layout = QHBoxLayout(self.integrity_banner)
        banner_layout.setContentsMargins(12, 0, 12, 0)
        self.lbl_integrity = QLabel("Integrity: Not verified yet")
        self.lbl_integrity.setStyleSheet("color: #9CA3AF; font-weight: bold;")
        banner_layout.addWidget(self.lbl_integrity)
        layout.addWidget(self.integrity_banner)

        # ── Search & Filter row ─────────────────────────
        filter_row = QHBoxLayout()

        lbl_search = QLabel("Search:")
        lbl_search.setStyleSheet("color: #E5E7EB;")
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Filter log messages...")
        self.txt_search.setStyleSheet(
            "background-color: #1F2937; color: white; padding: 5px; border-radius: 4px;"
        )

        lbl_type = QLabel("Event:")
        lbl_type.setStyleSheet("color: #E5E7EB;")
        self.cmb_type = QComboBox()
        self.cmb_type.addItems(["All"] + [e.value for e in EventType])
        self.cmb_type.setStyleSheet(
            "background-color: #1F2937; color: white; padding: 4px; border-radius: 4px;"
        )

        lbl_sev = QLabel("Severity:")
        lbl_sev.setStyleSheet("color: #E5E7EB;")
        self.cmb_severity = QComboBox()
        self.cmb_severity.addItems(["All"] + [s.value for s in LogSeverity])
        self.cmb_severity.setStyleSheet(
            "background-color: #1F2937; color: white; padding: 4px; border-radius: 4px;"
        )

        self.btn_filter = QPushButton("Apply")
        self.btn_filter.setStyleSheet("background-color: #6366F1;")

        filter_row.addWidget(lbl_search)
        filter_row.addWidget(self.txt_search, 1)
        filter_row.addWidget(lbl_type)
        filter_row.addWidget(self.cmb_type)
        filter_row.addWidget(lbl_sev)
        filter_row.addWidget(self.cmb_severity)
        filter_row.addWidget(self.btn_filter)
        layout.addLayout(filter_row)

        # ── Dashboard cards ─────────────────────────────
        cards = QHBoxLayout()
        self.card_total = self._make_card("Total Entries", "0")
        self.card_security = self._make_card("Security Events", "0", "#EF4444")
        self.card_scans = self._make_card("Scan Events", "0", "#3B82F6")
        self.card_runtime = self._make_card("Runtime Events", "0", "#F59E0B")
        cards.addWidget(self.card_total)
        cards.addWidget(self.card_security)
        cards.addWidget(self.card_scans)
        cards.addWidget(self.card_runtime)
        layout.addLayout(cards)

        # ── Splitter: table + detail ────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Severity", "Message", "Prev Hash", "Current Hash"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        splitter.addWidget(self.table)

        # Detail / Verification panel
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)

        self.lbl_detail_title = QLabel("Entry Details / Verification Report")
        self.lbl_detail_title.setStyleSheet("font-weight: bold; color: #E5E7EB;")
        detail_layout.addWidget(self.lbl_detail_title)

        self.txt_detail = QTextEdit()
        self.txt_detail.setReadOnly(True)
        self.txt_detail.setStyleSheet(
            "font-family: 'Consolas', monospace; background-color: #0D1117; "
            "padding: 10px; color: #D4D4D4;"
        )
        detail_layout.addWidget(self.txt_detail)

        splitter.addWidget(detail_widget)
        splitter.setSizes([650, 350])
        layout.addWidget(splitter, 1)

        # ── Signal connections ──────────────────────────
        self.btn_refresh.clicked.connect(self.load_entries)
        self.btn_verify.clicked.connect(self.verify_integrity)
        self.btn_export.clicked.connect(self.export_verification_report)
        self.btn_filter.clicked.connect(self.apply_filters)
        self.txt_search.returnPressed.connect(self.apply_filters)
        self.table.itemSelectionChanged.connect(self._on_row_selected)

        # Initial load
        self.load_entries()

    # ── Card helpers ────────────────────────────────────

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

    # ── Data loading ────────────────────────────────────

    def load_entries(self):
        self.all_entries = self.logger.get_entries()
        self._populate_table(self.all_entries)
        self._update_stats(self.all_entries)
        self.txt_detail.clear()

    def _populate_table(self, entries):
        sev_colors = {
            "INFO": QColor("#9CA3AF"),
            "WARNING": QColor("#F59E0B"),
            "ERROR": QColor("#EF4444"),
            "CRITICAL": QColor("#DC2626"),
        }

        self.table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            self.table.setItem(row, 0, QTableWidgetItem(e.timestamp))
            self.table.setItem(row, 1, QTableWidgetItem(e.event_type))

            sev_item = QTableWidgetItem(e.severity)
            sev_item.setForeground(sev_colors.get(e.severity, QColor("#F3F4F6")))
            self.table.setItem(row, 2, sev_item)

            self.table.setItem(row, 3, QTableWidgetItem(e.message))
            self.table.setItem(row, 4, QTableWidgetItem(e.previous_hash[:16] + "…"))
            self.table.setItem(row, 5, QTableWidgetItem(e.current_hash[:16] + "…"))

    def _update_stats(self, entries):
        self._update_card(self.card_total, str(len(entries)))
        self._update_card(self.card_security,
                          str(sum(1 for e in entries if e.event_type == EventType.SECURITY.value)))
        self._update_card(self.card_scans,
                          str(sum(1 for e in entries if e.event_type == EventType.SCAN.value)))
        self._update_card(self.card_runtime,
                          str(sum(1 for e in entries
                                  if e.event_type in (EventType.RUNTIME.value, EventType.MEMORY.value))))

    # ── Filtering ───────────────────────────────────────

    def apply_filters(self):
        keyword = self.txt_search.text().lower()
        event_filter = self.cmb_type.currentText()
        sev_filter = self.cmb_severity.currentText()

        filtered = self.all_entries
        if keyword:
            filtered = [e for e in filtered if keyword in e.message.lower()]
        if event_filter != "All":
            filtered = [e for e in filtered if e.event_type == event_filter]
        if sev_filter != "All":
            filtered = [e for e in filtered if e.severity == sev_filter]

        self._populate_table(filtered)

    # ── Row selection ───────────────────────────────────

    def _on_row_selected(self):
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        # Show full entry detail
        ts = self.table.item(row, 0).text()
        etype = self.table.item(row, 1).text()
        sev = self.table.item(row, 2).text()
        msg = self.table.item(row, 3).text()

        # Find matching full entry by timestamp
        full_entry = None
        for e in self.all_entries:
            if e.timestamp == ts:
                full_entry = e
                break

        if full_entry:
            detail = (
                f"{'═' * 52}\n"
                f"  LOG ENTRY DETAIL\n"
                f"{'═' * 52}\n\n"
                f"Timestamp:     {full_entry.timestamp}\n"
                f"Event Type:    {full_entry.event_type}\n"
                f"Severity:      {full_entry.severity}\n\n"
                f"Message:\n{full_entry.message}\n\n"
                f"{'─' * 52}\n"
                f"Previous Hash:\n{full_entry.previous_hash}\n\n"
                f"Current Hash:\n{full_entry.current_hash}\n"
            )
        else:
            detail = f"Timestamp: {ts}\nType: {etype}\nSeverity: {sev}\nMessage: {msg}"

        self.lbl_detail_title.setText("Entry Details")
        self.txt_detail.setPlainText(detail)

    # ── Integrity verification ──────────────────────────

    def verify_integrity(self):
        verifier = LogVerifier(self.logger.log_file)
        is_intact, report = verifier.verify()

        if is_intact:
            self.integrity_banner.setStyleSheet(
                "background-color: #064E3B; border-radius: 6px; padding: 4px 12px;"
            )
            self.lbl_integrity.setText("✅ Integrity: VERIFIED — Hash chain is intact")
            self.lbl_integrity.setStyleSheet("color: #34D399; font-weight: bold;")
        else:
            self.integrity_banner.setStyleSheet(
                "background-color: #7F1D1D; border-radius: 6px; padding: 4px 12px;"
            )
            tampered_count = sum(1 for r in report if r["status"] == "TAMPERED")
            self.lbl_integrity.setText(
                f"🚨 Integrity: FAILED — {tampered_count} entries tampered!"
            )
            self.lbl_integrity.setStyleSheet("color: #FCA5A5; font-weight: bold;")

        # Build verification report text
        lines = [
            "═" * 52,
            "  INTEGRITY VERIFICATION REPORT",
            "═" * 52,
            "",
            f"Log File:   {self.logger.log_file}",
            f"Entries:    {len(report)}",
            f"Status:     {'INTACT' if is_intact else 'COMPROMISED'}",
            "",
            "─" * 52,
        ]
        for r in report:
            idx = r["index"]
            status = r["status"]
            if status == "TAMPERED":
                lines.append(
                    f"  [{idx:04d}]  ⛔ TAMPERED\n"
                    f"         Expected prev: {r['expected_prev'][:24]}…\n"
                    f"         Actual prev:   {r['actual_prev'][:24]}…\n"
                    f"         Expected hash: {r['expected_hash'][:24]}…\n"
                    f"         Actual hash:   {r['actual_hash'][:24]}…"
                )
            else:
                lines.append(f"  [{idx:04d}]  ✅ OK")
        lines.append("─" * 52)

        self.lbl_detail_title.setText("Verification Report")
        self.txt_detail.setPlainText("\n".join(lines))

        self._last_verification_report = "\n".join(lines)

    # ── Export ──────────────────────────────────────────

    def export_verification_report(self):
        if not hasattr(self, "_last_verification_report"):
            QMessageBox.warning(
                self, "No Report",
                "Please run 'Verify Integrity' first to generate a report."
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Verification Report",
            "integrity_report.txt", "Text Files (*.txt)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._last_verification_report)
            QMessageBox.information(
                self, "Export Success",
                f"Report exported to:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))
