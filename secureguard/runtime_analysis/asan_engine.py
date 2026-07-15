"""
AddressSanitizer (ASan) Integration Engine for SecureGuard.

Compiles source files with ASan, runs them, parses the ASan error/leak logs,
and converts findings into correlated SecureGuard Vulnerability objects.
"""

import os
import re
import uuid
import subprocess
from enum import Enum
from typing import List, Optional, Tuple
from secureguard.core.models import Vulnerability, Severity


class AsanErrorType(Enum):
    STACK_BUFFER_OVERFLOW = "Stack Buffer Overflow"
    HEAP_BUFFER_OVERFLOW = "Heap Buffer Overflow"
    GLOBAL_BUFFER_OVERFLOW = "Global Buffer Overflow"
    USE_AFTER_FREE = "Use After Free"
    STACK_USE_AFTER_SCOPE = "Stack Use After Scope"
    STACK_USE_AFTER_RETURN = "Stack Use After Return"
    MEMORY_LEAK = "Memory Leak"
    DOUBLE_FREE = "Double Free"
    INVALID_FREE = "Invalid Free"
    ALLOC_DEALLOC_MISMATCH = "Allocation/Deallocation Mismatch"
    UNKNOWN = "Unknown Memory Error"


# Maps ASan error strings to our enum
_ASAN_TYPE_MAP = {
    "stack-buffer-overflow": AsanErrorType.STACK_BUFFER_OVERFLOW,
    "heap-buffer-overflow": AsanErrorType.HEAP_BUFFER_OVERFLOW,
    "global-buffer-overflow": AsanErrorType.GLOBAL_BUFFER_OVERFLOW,
    "heap-use-after-free": AsanErrorType.USE_AFTER_FREE,
    "stack-use-after-scope": AsanErrorType.STACK_USE_AFTER_SCOPE,
    "stack-use-after-return": AsanErrorType.STACK_USE_AFTER_RETURN,
    "memory-leak": AsanErrorType.MEMORY_LEAK,
    "double-free": AsanErrorType.DOUBLE_FREE,
    "bad-free": AsanErrorType.INVALID_FREE,
    "alloc-dealloc-mismatch": AsanErrorType.ALLOC_DEALLOC_MISMATCH,
}

_SEVERITY_MAP = {
    AsanErrorType.STACK_BUFFER_OVERFLOW: Severity.CRITICAL,
    AsanErrorType.HEAP_BUFFER_OVERFLOW: Severity.CRITICAL,
    AsanErrorType.GLOBAL_BUFFER_OVERFLOW: Severity.CRITICAL,
    AsanErrorType.USE_AFTER_FREE: Severity.CRITICAL,
    AsanErrorType.STACK_USE_AFTER_SCOPE: Severity.HIGH,
    AsanErrorType.STACK_USE_AFTER_RETURN: Severity.HIGH,
    AsanErrorType.MEMORY_LEAK: Severity.HIGH,
    AsanErrorType.DOUBLE_FREE: Severity.CRITICAL,
    AsanErrorType.INVALID_FREE: Severity.CRITICAL,
    AsanErrorType.ALLOC_DEALLOC_MISMATCH: Severity.HIGH,
    AsanErrorType.UNKNOWN: Severity.MEDIUM,
}

_RECOMMENDATIONS = {
    AsanErrorType.STACK_BUFFER_OVERFLOW: "Avoid using unsafe string functions like gets, strcpy, sprintf. Check stack buffer boundaries and use bounds-checking alternatives (fgets, strncpy, snprintf).",
    AsanErrorType.HEAP_BUFFER_OVERFLOW: "Validate buffer sizes before copying data to heap-allocated arrays. Ensure allocations are large enough to hold all data.",
    AsanErrorType.GLOBAL_BUFFER_OVERFLOW: "Ensure global and static arrays are sized appropriately and index accesses are within bounds.",
    AsanErrorType.USE_AFTER_FREE: "Do not read or write to heap memory after freeing it. Set pointers to NULL after freeing to prevent accidental access.",
    AsanErrorType.STACK_USE_AFTER_SCOPE: "Avoid returning pointers to local block variables or accessing variables outside their defined scope.",
    AsanErrorType.STACK_USE_AFTER_RETURN: "Never return pointers or references to local stack-allocated variables from a function.",
    AsanErrorType.MEMORY_LEAK: "Ensure all heap-allocated objects (via malloc/calloc/new) are properly deallocated (via free/delete) before pointers go out of scope.",
    AsanErrorType.DOUBLE_FREE: "Ensure free() is called exactly once for each memory allocation. Avoid freeing a pointer multiple times.",
    AsanErrorType.INVALID_FREE: "Only pass pointers returned by malloc/calloc/realloc to free(). Never attempt to free stack-allocated variables.",
    AsanErrorType.ALLOC_DEALLOC_MISMATCH: "Always pair malloc/calloc with free, new with delete, and new[] with delete[].",
    AsanErrorType.UNKNOWN: "Review the code around the indicated location for potential memory safety issues.",
}


class AsanFinding:
    def __init__(
        self,
        error_type: AsanErrorType,
        description: str,
        stack_trace: List[str],
        file_path: Optional[str],
        line_number: int,
        variable_name: Optional[str] = None,
        operation: Optional[str] = None,
        size: int = 0,
    ):
        self.error_type = error_type
        self.description = description
        self.stack_trace = stack_trace
        self.file_path = file_path
        self.line_number = line_number
        self.variable_name = variable_name
        self.operation = operation
        self.size = size


class AsanEngine:
    """Handles compilation of test programs with ASan and parsing of runtime reports."""

    def compile_source(self, source_path: str) -> str:
        """
        Compiles a C/C++ source file with AddressSanitizer flags.
        Returns the path to the compiled executable.
        """
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source file not found: {source_path}")

        base, ext = os.path.splitext(source_path)
        output_path = base + "_asan"

        compiler = "g++" if ext in (".cpp", ".cc", ".cxx") else "gcc"

        cmd = [
            compiler,
            "-fsanitize=address",
            "-g",
            "-O1",
            "-Wno-implicit-function-declaration",
            "-o",
            output_path,
            source_path,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Compilation failed:\n{result.stderr}")

        os.chmod(output_path, 0o755)
        return output_path

    def parse_output(self, stderr_text: str) -> List[AsanFinding]:
        """Parses the ASan error/leak reports from standard error output."""
        findings: List[AsanFinding] = []

        # 1. Check for standard AddressSanitizer error block
        error_match = re.search(
            r"ERROR: AddressSanitizer:\s*([^\s]+)\s+on\s+address\s+(\S+)", stderr_text
        )

        if error_match:
            raw_type = error_match.group(1)
            addr = error_match.group(2)
            error_type = _ASAN_TYPE_MAP.get(raw_type, AsanErrorType.UNKNOWN)

            # Try to extract read/write operation and size
            op_match = re.search(r"(WRITE|READ) of size (\d+) at (\S+)", stderr_text)
            operation = op_match.group(1) if op_match else None
            size = int(op_match.group(2)) if op_match else 0

            # Extract stack frames
            stack_trace = []
            frames = re.findall(
                r"\s+#\d+\s+\S+\s+in\s+([^\s]+)\s+([^\s:]+):(\d+)", stderr_text
            )
            for fn, file, line in frames:
                stack_trace.append(f"  at {fn} ({file}:{line})")

            # Extract overflowed variable details if stack-buffer-overflow
            var_match = re.search(
                r"'([^']+)' \(line (\d+)\) <== Memory access at offset \d+ overflows this variable",
                stderr_text,
            )
            var_name = var_match.group(1) if var_match else None
            var_line = int(var_match.group(2)) if var_match else 0

            # Find primary file path and line number
            summary_match = re.search(
                r"SUMMARY: AddressSanitizer:\s*\S+\s+([^\s:]+):(\d+)\s+in\s+(\S+)",
                stderr_text,
            )

            file_path = None
            line_number = 0

            if summary_match:
                file_path = summary_match.group(1)
                line_number = int(summary_match.group(2))
            else:
                # Fallback: get first frame not in system libraries
                for fn, file, line in frames:
                    if not any(
                        x in file
                        for x in [
                            "libsanitizer",
                            "gcc",
                            "glibc",
                            "/usr/",
                            "asan_interceptors",
                        ]
                    ):
                        file_path = file
                        line_number = int(line)
                        break

            desc = f"AddressSanitizer detected {error_type.value} at address {addr}."
            if operation:
                desc += f" Invalid {operation} of size {size} bytes."
            if var_name:
                desc += f" Target variable: '{var_name}' (declared at line {var_line})."

            findings.append(
                AsanFinding(
                    error_type=error_type,
                    description=desc,
                    stack_trace=stack_trace,
                    file_path=file_path,
                    line_number=line_number,
                    variable_name=var_name,
                    operation=operation,
                    size=size,
                )
            )

        # 2. Check for LeakSanitizer leaks (if not already found standard ASan errors)
        elif "LeakSanitizer: detected memory leaks" in stderr_text:
            leak_blocks = re.findall(
                r"(?:Direct|Indirect) leak of (\d+) byte\(s\) in \d+ object\(s\) allocated from:(.*?)(?=\n\n|\n[A-Z]|\Z)",
                stderr_text,
                re.DOTALL,
            )
            for bytes_str, trace_text in leak_blocks:
                bytes_val = int(bytes_str)
                frames = re.findall(
                    r"\s+#\d+\s+\S+\s+in\s+([^\s]+)\s+([^\s:]+):(\d+)",
                    trace_text,
                )

                stack_trace = []
                file_path = None
                line_number = 0

                for fn, file, line in frames:
                    stack_trace.append(f"  at {fn} ({file}:{line})")
                    if not file_path and not any(
                        x in file for x in ["libsanitizer", "gcc", "glibc", "/usr/"]
                    ):
                        file_path = file
                        line_number = int(line)

                desc = f"AddressSanitizer LeakSanitizer detected a memory leak of {bytes_val} bytes."

                findings.append(
                    AsanFinding(
                        error_type=AsanErrorType.MEMORY_LEAK,
                        description=desc,
                        stack_trace=stack_trace,
                        file_path=file_path or "Unknown",
                        line_number=line_number,
                        size=bytes_val,
                    )
                )

        return findings

    def to_vulnerabilities(
        self, findings: List[AsanFinding]
    ) -> List[Vulnerability]:
        """Converts parsed findings into standard SecureGuard Vulnerability objects."""
        vulns: List[Vulnerability] = []
        for f in findings:
            severity = _SEVERITY_MAP.get(f.error_type, Severity.MEDIUM)
            recommendation = _RECOMMENDATIONS.get(
                f.error_type, "Review variable ranges and bounds checks."
            )

            desc = f.description
            if f.stack_trace:
                desc += "\nStack trace:\n" + "\n".join(f.stack_trace[:5])

            vulns.append(
                Vulnerability(
                    id=str(uuid.uuid4())[:8],
                    severity=severity,
                    vuln_type=f"[ASan] {f.error_type.value}",
                    file_path=f.file_path or "Unknown",
                    line_number=f.line_number,
                    description=desc,
                    recommendation=recommendation,
                )
            )
        return vulns

    def correlate_findings(
        self, source_path: str, asan_vulns: List[Vulnerability]
    ) -> List[Vulnerability]:
        """Correlates ASan runtime findings with static analysis scan findings to confirm exploits."""
        if not source_path or not os.path.exists(source_path):
            return asan_vulns

        # Perform a quick static scan on the C source file
        try:
            from static_analysis.scanner import RegexStaticScanner

            scanner = RegexStaticScanner()
            static_result = scanner.scan_file(source_path)
            static_vulns = static_result.vulnerabilities
        except Exception:
            # If static scan fails, return uncorrelated vulns
            return asan_vulns

        correlated_vulns = []
        for av in asan_vulns:
            matched = False
            for sv in static_vulns:
                # Match by filename (basename) and line number
                if (
                    os.path.basename(av.file_path)
                    == os.path.basename(sv.file_path)
                    and av.line_number == sv.line_number
                ):
                    # Flag this finding as correlated (exploited)
                    av.vuln_type = f"[Correlated] {av.vuln_type[7:]}"  # replace [ASan] with [Correlated]
                    av.description = (
                        f"⚠️ **EXPLOIT CONFIRMED (Static & Runtime Match)**\n\n"
                        f"**Static Rule Triggered**: {sv.description}\n"
                        f"**ASan Runtime Detection**: {av.description}"
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
