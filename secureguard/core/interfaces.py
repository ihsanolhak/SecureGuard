from abc import ABC, abstractmethod
from typing import List, Optional
from .models import ScanResult, Vulnerability, LogEntry

class IStaticScanner(ABC):
    @abstractmethod
    def scan_directory(self, path: str) -> ScanResult:
        pass

class IRuntimeMonitor(ABC):
    @abstractmethod
    def start_monitoring(self, executable_path: str) -> None:
        pass

    @abstractmethod
    def stop_monitoring(self) -> None:
        pass

class IAIAssistant(ABC):
    @abstractmethod
    def explain_vulnerability(self, vuln: Vulnerability) -> str:
        pass

    @abstractmethod
    def suggest_fix(self, vuln: Vulnerability) -> str:
        pass

class ILogger(ABC):
    @abstractmethod
    def log_event(self, severity: str, event: str) -> LogEntry:
        pass
    
    @abstractmethod
    def get_logs(self) -> List[LogEntry]:
        pass

class IReportGenerator(ABC):
    @abstractmethod
    def generate_html_report(self, result: ScanResult, output_path: str) -> bool:
        pass

    @abstractmethod
    def generate_pdf_report(self, result: ScanResult, output_path: str) -> bool:
        pass
