from typing import Dict, List, Tuple

class CWEDatabase:
    def __init__(self):
        self.entries = {
            "CWE-120": {"name": "Buffer Copy without Checking Size of Input", "category": "Memory Safety"},
            "CWE-242": {"name": "Use of Inherently Dangerous Function", "category": "API Abuse"},
            "CWE-416": {"name": "Use After Free", "category": "Memory Safety"},
            "CWE-415": {"name": "Double Free", "category": "Memory Safety"},
            "CWE-78": {"name": "OS Command Injection", "category": "Injection"},
            "CWE-338": {"name": "Cryptographically Weak PRNG", "category": "Cryptography"},
            "CWE-798": {"name": "Use of Hard-coded Credentials", "category": "Authentication"},
            "CWE-401": {"name": "Memory Leak", "category": "Memory Safety"}
        }

    def get_cwe(self, cwe_id: str) -> dict:
        return self.entries.get(cwe_id, {"name": "Unknown CWE", "category": "Uncategorized"})


class STRIDEDatabase:
    def __init__(self):
        self.entries = {
            "Spoofing": {"description": "Impersonating something or someone else.", "property": "Authentication"},
            "Tampering": {"description": "Modifying data or code without authorization.", "property": "Integrity"},
            "Repudiation": {"description": "Claiming to have not performed an action.", "property": "Non-repudiation"},
            "Information Disclosure": {"description": "Exposing information to unauthorized individuals.", "property": "Confidentiality"},
            "Denial of Service": {"description": "Denying or degrading service to users.", "property": "Availability"},
            "Elevation of Privilege": {"description": "Gaining capabilities without proper authorization.", "property": "Authorization"}
        }

    def get_stride(self, threat: str) -> dict:
        return self.entries.get(threat, {"description": "Unknown threat", "property": "Unknown"})


class SecurityFrameworkMapper:
    def __init__(self):
        self.cwe_db = CWEDatabase()
        self.stride_db = STRIDEDatabase()

        # Mapping finding names or identifiers to lists of CWEs and STRIDE threats
        self.mapping = {
            "gets": (["CWE-242", "CWE-120"], ["Elevation of Privilege", "Tampering"]),
            "strcpy": (["CWE-120"], ["Elevation of Privilege", "Tampering"]),
            "sprintf": (["CWE-120"], ["Elevation of Privilege", "Tampering"]),
            "strcat": (["CWE-120"], ["Elevation of Privilege", "Tampering"]),
            "system": (["CWE-78"], ["Elevation of Privilege", "Information Disclosure", "Tampering", "Denial of Service"]),
            "rand": (["CWE-338"], ["Information Disclosure", "Spoofing"]),
            "hardcoded credentials": (["CWE-798"], ["Elevation of Privilege", "Information Disclosure", "Spoofing"]),
            "memory leak": (["CWE-401"], ["Denial of Service"]),
            "buffer overflow": (["CWE-120"], ["Elevation of Privilege", "Tampering", "Denial of Service"]),
            "use after free": (["CWE-416"], ["Elevation of Privilege", "Information Disclosure", "Tampering"]),
            "double free": (["CWE-415"], ["Elevation of Privilege", "Tampering", "Denial of Service"]),
            "invalid read": (["CWE-125"], ["Information Disclosure", "Denial of Service"]),
            "invalid write": (["CWE-787"], ["Elevation of Privilege", "Tampering", "Denial of Service"]),
            "privilege escalation risk": (["CWE-269"], ["Elevation of Privilege"])
        }

    def map_finding(self, vuln_type: str) -> Tuple[List[str], List[str]]:
        vuln_lower = vuln_type.lower()
        for key, (cwes, strides) in self.mapping.items():
            if key in vuln_lower:
                return cwes, strides
        return (["Unknown"], ["Unknown"])
