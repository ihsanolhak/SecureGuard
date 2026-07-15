from PyQt6.QtCore import QObject, pyqtSignal, QProcess
from enum import Enum
import os

class RuntimeEventType(Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"

class RuntimeEvent:
    def __init__(self, event_type: RuntimeEventType, message: str):
        self.event_type = event_type
        self.message = message

class QRuntimeMonitor(QObject):
    event_emitted = pyqtSignal(RuntimeEvent)
    finished = pyqtSignal(int, bool) # exit_code, crashed
    
    def __init__(self):
        super().__init__()
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.handle_finished)
        self.process.errorOccurred.connect(self.handle_error)
        self.use_valgrind = False

    def start_monitoring(self, executable_path: str, simulate_attack: bool = False):
        if not os.path.exists(executable_path):
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.CRITICAL, "Executable not found!"))
            self.finished.emit(-1, True)
            return

        self.event_emitted.emit(RuntimeEvent(RuntimeEventType.SAFE, f"Initializing monitor for: {os.path.basename(executable_path)}"))
        
        args = []
        if self.use_valgrind:
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.WARNING, "Valgrind integration is pending future release. Running natively."))
            
        if simulate_attack:
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.ALERT, "ATTACK SIMULATION: Injecting massive payload to test buffer bounds..."))
            args.append("A" * 150)
        else:
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.SAFE, "Running with safe normal input."))
            args.append("SafeInputData")
            
        self.process.start(executable_path, args)
        
    def stop_monitoring(self):
        if self.process.state() == QProcess.ProcessState.Running:
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.WARNING, "Terminating process manually."))
            self.process.kill()

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode(errors='ignore').strip()
        for line in data.split('\n'):
            if line:
                self.event_emitted.emit(RuntimeEvent(RuntimeEventType.SAFE, f"[STDOUT] {line}"))

    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode(errors='ignore').strip()
        for line in data.split('\n'):
            if line:
                self.event_emitted.emit(RuntimeEvent(RuntimeEventType.WARNING, f"[STDERR] {line}"))

    def handle_finished(self, exit_code, exit_status):
        crashed = False
        if exit_status == QProcess.ExitStatus.CrashExit:
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.CRITICAL, "CRASH DETECTED: Process terminated unexpectedly (Segmentation Fault)."))
            crashed = True
        elif exit_code != 0:
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.ALERT, f"ABNORMAL EXIT: Process returned exit code {exit_code}."))
            crashed = True
        else:
            self.event_emitted.emit(RuntimeEvent(RuntimeEventType.SAFE, "Process executed successfully without crashes."))
            
        self.finished.emit(exit_code, crashed)
        
    def handle_error(self, error):
        self.event_emitted.emit(RuntimeEvent(RuntimeEventType.CRITICAL, f"EXECUTION ERROR: {self.process.errorString()}"))
        self.finished.emit(-1, True)
