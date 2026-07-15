"""
Tamper-Proof Logging Engine using SHA-256 hash chaining.

Each log entry is cryptographically linked to the previous one.
If any entry is modified, the chain breaks and integrity verification fails.
"""

import hashlib
import json
import os
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import List, Optional, Tuple


class EventType(Enum):
    SYSTEM = "System"
    SCAN = "Scan"
    RUNTIME = "Runtime"
    MEMORY = "Memory"
    SECURITY = "Security"
    FRAMEWORK = "Framework"
    REPORT = "Report"


class LogSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class SecureLogEntry:
    timestamp: str
    event_type: str
    severity: str
    message: str
    previous_hash: str
    current_hash: str

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "SecureLogEntry":
        return SecureLogEntry(**d)


class SecureLogger:
    """
    Forensic-grade logger that writes SHA-256 hash-chained entries to a JSONL file.
    Each entry's hash covers its own data plus the hash of the previous entry,
    forming an unbroken cryptographic chain. Any modification to any entry
    causes the chain to break from that point forward.
    """

    _instance: Optional["SecureLogger"] = None
    _lock = threading.Lock()

    GENESIS_HASH = "0" * 64  # The "previous hash" for the very first entry

    def __new__(cls, log_dir: Optional[str] = None):
        # Singleton so all modules share a single logger instance
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, log_dir: Optional[str] = None):
        if self._initialized:
            return
        self._initialized = True
        self._write_lock = threading.Lock()

        if log_dir is None:
            # Default to <project>/secureguard/logs/
            log_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "logs",
            )
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "secure_audit.jsonl")

        # Load previous hash from last entry in existing log
        self._previous_hash = self._load_last_hash()

        # Write genesis entry if the log is empty / new
        if self._previous_hash == self.GENESIS_HASH:
            self.log(EventType.SYSTEM, LogSeverity.INFO, "SecureGuard audit log initialized.")

    # ── Public API ──────────────────────────────────────

    def log(self, event_type: EventType, severity: LogSeverity, message: str) -> SecureLogEntry:
        with self._write_lock:
            ts = datetime.now().isoformat(timespec="milliseconds")
            payload = f"{ts}|{event_type.value}|{severity.value}|{message}|{self._previous_hash}"
            current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            entry = SecureLogEntry(
                timestamp=ts,
                event_type=event_type.value,
                severity=severity.value,
                message=message,
                previous_hash=self._previous_hash,
                current_hash=current_hash,
            )

            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")

            self._previous_hash = current_hash
            return entry

    def get_entries(self) -> List[SecureLogEntry]:
        entries: List[SecureLogEntry] = []
        if not os.path.exists(self.log_file):
            return entries
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(SecureLogEntry.from_dict(json.loads(line)))
        return entries

    # ── Internal helpers ────────────────────────────────

    def _load_last_hash(self) -> str:
        if not os.path.exists(self.log_file):
            return self.GENESIS_HASH
        last_hash = self.GENESIS_HASH
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        d = json.loads(line)
                        last_hash = d.get("current_hash", last_hash)
                    except json.JSONDecodeError:
                        pass
        return last_hash


class LogVerifier:
    """
    Verifies the integrity of the tamper-proof log by recomputing every hash
    in the chain. Returns a detailed report showing which entries (if any)
    have been tampered with.
    """

    GENESIS_HASH = SecureLogger.GENESIS_HASH

    def __init__(self, log_file: str):
        self.log_file = log_file

    def verify(self) -> Tuple[bool, List[dict]]:
        """
        Returns (is_intact, report_entries).
        Each report entry has keys: index, status ('OK' | 'TAMPERED'), expected_hash, actual_hash.
        """
        if not os.path.exists(self.log_file):
            return True, []

        entries: List[dict] = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))

        if not entries:
            return True, []

        report: List[dict] = []
        chain_intact = True
        expected_prev = self.GENESIS_HASH

        for idx, entry in enumerate(entries):
            stored_prev = entry.get("previous_hash", "")
            stored_hash = entry.get("current_hash", "")

            # Recompute hash
            payload = (
                f"{entry['timestamp']}|{entry['event_type']}|{entry['severity']}"
                f"|{entry['message']}|{expected_prev}"
            )
            computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            if stored_prev != expected_prev or stored_hash != computed_hash:
                report.append({
                    "index": idx,
                    "status": "TAMPERED",
                    "expected_prev": expected_prev,
                    "actual_prev": stored_prev,
                    "expected_hash": computed_hash,
                    "actual_hash": stored_hash,
                })
                chain_intact = False
            else:
                report.append({
                    "index": idx,
                    "status": "OK",
                    "expected_hash": computed_hash,
                    "actual_hash": stored_hash,
                })

            expected_prev = stored_hash  # Continue chain with stored hash

        return chain_intact, report
