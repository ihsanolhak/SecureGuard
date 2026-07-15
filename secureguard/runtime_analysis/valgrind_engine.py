"""
Valgrind Integration Engine for SecureGuard.

Runs executables through Valgrind's memcheck tool, parses the XML output,
and converts findings into SecureGuard Vulnerability objects.
"""

import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
from secureguard.core.models import Vulnerability, Severity


class MemoryErrorType(Enum):
    INVALID_READ = "Invalid Read"
    INVALID_WRITE = "Invalid Write"
    MEMORY_LEAK = "Memory Leak"
    USE_AFTER_FREE = "Use After Free"
    UNINITIALISED_VALUE = "Uninitialized Memory Access"
    INVALID_FREE = "Invalid Free"
    MISMATCHED_FREE = "Mismatched Free/Delete"
    OVERLAP = "Overlapping Memory Copy"
    UNKNOWN = "Unknown Memory Error"


@dataclass
class ValgrindFinding:
    """Represents a single parsed Valgrind finding."""
    error_type: MemoryErrorType
    description: str
    stack_trace: List[str] = field(default_factory=list)
    file_path: Optional[str] = None
    line_number: int = 0
    bytes_affected: int = 0


# Mapping from Valgrind's internal error kind strings to our enum
_VALGRIND_KIND_MAP = {
    "InvalidRead": MemoryErrorType.INVALID_READ,
    "InvalidWrite": MemoryErrorType.INVALID_WRITE,
    "Leak_DefinitelyLost": MemoryErrorType.MEMORY_LEAK,
    "Leak_IndirectlyLost": MemoryErrorType.MEMORY_LEAK,
    "Leak_PossiblyLost": MemoryErrorType.MEMORY_LEAK,
    "Leak_StillReachable": MemoryErrorType.MEMORY_LEAK,
    "UninitCondition": MemoryErrorType.UNINITIALISED_VALUE,
    "UninitValue": MemoryErrorType.UNINITIALISED_VALUE,
    "InvalidFree": MemoryErrorType.INVALID_FREE,
    "MismatchedFree": MemoryErrorType.MISMATCHED_FREE,
    "Overlap": MemoryErrorType.OVERLAP,
    "UseAfterFree": MemoryErrorType.USE_AFTER_FREE,
}

# Mapping from MemoryErrorType to Severity
_SEVERITY_MAP = {
    MemoryErrorType.INVALID_READ: Severity.CRITICAL,
    MemoryErrorType.INVALID_WRITE: Severity.CRITICAL,
    MemoryErrorType.USE_AFTER_FREE: Severity.CRITICAL,
    MemoryErrorType.INVALID_FREE: Severity.HIGH,
    MemoryErrorType.MISMATCHED_FREE: Severity.HIGH,
    MemoryErrorType.MEMORY_LEAK: Severity.HIGH,
    MemoryErrorType.UNINITIALISED_VALUE: Severity.MEDIUM,
    MemoryErrorType.OVERLAP: Severity.MEDIUM,
    MemoryErrorType.UNKNOWN: Severity.LOW,
}

# Recommendations keyed by MemoryErrorType
_RECOMMENDATIONS = {
    MemoryErrorType.INVALID_READ: "Ensure all memory reads are within allocated bounds. Check array indices and pointer arithmetic.",
    MemoryErrorType.INVALID_WRITE: "Ensure all memory writes are within allocated bounds. Validate buffer sizes before writing.",
    MemoryErrorType.MEMORY_LEAK: "Ensure every malloc/calloc/realloc has a matching free(). Consider using RAII in C++.",
    MemoryErrorType.USE_AFTER_FREE: "Do not access memory after it has been freed. Set pointers to NULL after free().",
    MemoryErrorType.UNINITIALISED_VALUE: "Initialize all variables before use. Use memset() for buffers or set explicit default values.",
    MemoryErrorType.INVALID_FREE: "Only free() memory that was obtained from malloc/calloc/realloc. Never free stack memory or global data.",
    MemoryErrorType.MISMATCHED_FREE: "Match allocation and deallocation functions: malloc with free, new with delete, new[] with delete[].",
    MemoryErrorType.OVERLAP: "Use memmove() instead of memcpy() when source and destination buffers may overlap.",
    MemoryErrorType.UNKNOWN: "Review the code around the indicated location for potential memory safety issues.",
}


class ValgrindParser:
    """Parses Valgrind XML output into ValgrindFinding objects."""

    def parse_xml(self, xml_content: str) -> List[ValgrindFinding]:
        """Parse Valgrind --xml=yes output."""
        findings: List[ValgrindFinding] = []
        try:
            root = ET.fromstring(xml_content)
            for error_elem in root.findall('.//error'):
                finding = self._parse_error_element(error_elem)
                if finding:
                    findings.append(finding)
        except ET.ParseError:
            # Fall back to regex parsing if XML is malformed
            findings = self.parse_text(xml_content)
        return findings

    def _parse_error_element(self, error_elem) -> Optional[ValgrindFinding]:
        """Parse a single <error> element from Valgrind XML."""
        kind_elem = error_elem.find('kind')
        if kind_elem is None or kind_elem.text is None:
            return None

        kind_text = kind_elem.text.strip()
        error_type = _VALGRIND_KIND_MAP.get(kind_text, MemoryErrorType.UNKNOWN)

        # Extract description from <what> or <xwhat><text>
        desc = ""
        what_elem = error_elem.find('what')
        if what_elem is not None and what_elem.text:
            desc = what_elem.text.strip()
        else:
            xwhat_text = error_elem.find('xwhat/text')
            if xwhat_text is not None and xwhat_text.text:
                desc = xwhat_text.text.strip()

        # Extract stack trace and source location
        stack_trace: List[str] = []
        file_path = None
        line_number = 0

        for frame in error_elem.findall('.//frame'):
            fn_elem = frame.find('fn')
            obj_elem = frame.find('obj')
            file_elem = frame.find('file')
            line_elem = frame.find('line')
            dir_elem = frame.find('dir')

            fn_name = fn_elem.text if fn_elem is not None and fn_elem.text else "???"
            frame_desc = f"  at {fn_name}"

            if file_elem is not None and file_elem.text:
                f = file_elem.text
                if dir_elem is not None and dir_elem.text:
                    f = f"{dir_elem.text}/{f}"
                l = line_elem.text if line_elem is not None and line_elem.text else "?"
                frame_desc += f" ({f}:{l})"

                # Use the first user-code frame as the primary location
                if file_path is None:
                    file_path = f
                    try:
                        line_number = int(l)
                    except (ValueError, TypeError):
                        line_number = 0
            elif obj_elem is not None and obj_elem.text:
                frame_desc += f" (in {obj_elem.text})"

            stack_trace.append(frame_desc)

        # Extract bytes for leaks
        bytes_affected = 0
        xwhat_bytes = error_elem.find('xwhat/leakedbytes')
        if xwhat_bytes is not None and xwhat_bytes.text:
            try:
                bytes_affected = int(xwhat_bytes.text)
            except ValueError:
                pass

        return ValgrindFinding(
            error_type=error_type,
            description=desc if desc else f"{error_type.value} detected",
            stack_trace=stack_trace,
            file_path=file_path,
            line_number=line_number,
            bytes_affected=bytes_affected,
        )

    def parse_text(self, text: str) -> List[ValgrindFinding]:
        """Fallback: parse plain-text Valgrind output using regex."""
        findings: List[ValgrindFinding] = []
        patterns = [
            (r"Invalid read of size (\d+)", MemoryErrorType.INVALID_READ),
            (r"Invalid write of size (\d+)", MemoryErrorType.INVALID_WRITE),
            (r"(\d[\d,]*) bytes in \d+ blocks are definitely lost", MemoryErrorType.MEMORY_LEAK),
            (r"(\d[\d,]*) bytes in \d+ blocks are indirectly lost", MemoryErrorType.MEMORY_LEAK),
            (r"(\d[\d,]*) bytes in \d+ blocks are possibly lost", MemoryErrorType.MEMORY_LEAK),
            (r"Invalid free\(\)", MemoryErrorType.INVALID_FREE),
            (r"Mismatched free\(\)", MemoryErrorType.MISMATCHED_FREE),
            (r"Use of uninitialised value", MemoryErrorType.UNINITIALISED_VALUE),
            (r"Source and destination overlap", MemoryErrorType.OVERLAP),
        ]

        for pattern, error_type in patterns:
            for match in re.finditer(pattern, text):
                bytes_val = 0
                try:
                    bytes_val = int(match.group(1).replace(",", ""))
                except (IndexError, ValueError):
                    pass

                # Try to find file/line after the match
                context = text[match.start():match.start() + 500]
                file_match = re.search(r'\(([^)]+\.\w+):(\d+)\)', context)
                file_path = file_match.group(1) if file_match else None
                line_num = int(file_match.group(2)) if file_match else 0

                findings.append(ValgrindFinding(
                    error_type=error_type,
                    description=match.group(0),
                    file_path=file_path,
                    line_number=line_num,
                    bytes_affected=bytes_val,
                ))

        return findings


class ValgrindEngine:
    """Builds Valgrind command lines and converts findings to SecureGuard Vulnerabilities."""

    def __init__(self):
        self.parser = ValgrindParser()

    def build_command(self, executable_path: str, attack_mode: bool = False) -> tuple:
        """
        Returns (program, args) for QProcess.start().
        Uses XML output for structured parsing.
        """
        args = [
            "--tool=memcheck",
            "--leak-check=full",
            "--show-reachable=yes",
            "--track-origins=yes",
            "--xml=yes",
            "--xml-fd=2",       # XML goes to stderr
            executable_path,
        ]
        if attack_mode:
            args.append("A" * 150)
        else:
            args.append("SafeInputData")

        return ("valgrind", args)

    def parse_output(self, stderr_text: str) -> List[ValgrindFinding]:
        """Parse Valgrind output (try XML first, fall back to text)."""
        if "<valgrindoutput>" in stderr_text:
            # Extract the XML block
            start = stderr_text.index("<valgrindoutput>")
            end = stderr_text.index("</valgrindoutput>") + len("</valgrindoutput>")
            xml_block = stderr_text[start:end]
            return self.parser.parse_xml(xml_block)
        else:
            return self.parser.parse_text(stderr_text)

    def to_vulnerabilities(self, findings: List[ValgrindFinding]) -> List[Vulnerability]:
        """Convert ValgrindFindings into SecureGuard Vulnerability objects."""
        vulns: List[Vulnerability] = []
        for f in findings:
            severity = _SEVERITY_MAP.get(f.error_type, Severity.LOW)
            recommendation = _RECOMMENDATIONS.get(f.error_type, "Review the code for memory safety issues.")

            desc = f.description
            if f.bytes_affected > 0:
                desc += f" ({f.bytes_affected} bytes affected)"
            if f.stack_trace:
                desc += "\nStack trace:\n" + "\n".join(f.stack_trace[:5])

            vulns.append(Vulnerability(
                id=str(uuid.uuid4())[:8],
                severity=severity,
                vuln_type=f"[Valgrind] {f.error_type.value}",
                file_path=f.file_path or "Unknown",
                line_number=f.line_number,
                description=desc,
                recommendation=recommendation,
            ))
        return vulns
