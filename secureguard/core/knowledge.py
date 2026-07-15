from typing import Optional, Dict
from .models import VulnerabilityProfile, Severity

class KnowledgeBase:
    """Offline knowledge base for security vulnerabilities."""
    
    def __init__(self):
        self.profiles: Dict[str, VulnerabilityProfile] = {
            "gets()": VulnerabilityProfile(
                name="gets() Function Usage",
                severity=Severity.CRITICAL,
                description="The gets() function reads a line from stdin into a buffer until either a terminating newline or EOF, which it replaces with a null byte. It does not check for buffer overrun.",
                technical_explanation="Because gets() does not know the size of the buffer it is writing to, an attacker can supply an arbitrarily long string that overflows the buffer, potentially overwriting adjacent memory spaces including the return address, leading to arbitrary code execution.",
                attack_scenario="An attacker inputs a payload larger than the allocated buffer during a prompt. The payload overwrites the return pointer on the stack, redirecting execution to attacker-controlled shellcode.",
                remediation_guidance="Never use gets(). It has been removed from C11.",
                secure_alternative="fgets(buffer, sizeof(buffer), stdin)",
                cwe_mapping="CWE-242: Use of Inherently Dangerous Function, CWE-120: Buffer Copy without Checking Size of Input",
                stride_mapping="Elevation of Privilege, Tampering",
                secure_coding_example="char buf[256];\nif (fgets(buf, sizeof(buf), stdin) != NULL) {\n    buf[strcspn(buf, \"\\n\")] = 0; // Remove newline\n}"
            ),
            "strcpy()": VulnerabilityProfile(
                name="strcpy() Function Usage",
                severity=Severity.HIGH,
                description="The strcpy() function copies a string without checking the size of the destination buffer.",
                technical_explanation="If the source string is larger than the destination buffer, strcpy() will write past the end of the buffer, causing a buffer overflow.",
                attack_scenario="Attacker provides a long string as input (e.g., via a command line argument or network packet). The application uses strcpy() to copy it into a fixed-size buffer on the stack, overwriting the saved instruction pointer.",
                remediation_guidance="Use length-bounded string copy functions. Ensure the destination buffer is correctly sized and null-terminated.",
                secure_alternative="strncpy() or strlcpy()",
                cwe_mapping="CWE-120: Buffer Copy without Checking Size of Input",
                stride_mapping="Elevation of Privilege, Tampering",
                secure_coding_example="char dest[256];\nstrncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = '\\0';"
            ),
            "sprintf()": VulnerabilityProfile(
                name="sprintf() Function Usage",
                severity=Severity.HIGH,
                description="The sprintf() function formats and stores a series of characters and values in the array buffer, without checking the buffer size.",
                technical_explanation="Similar to strcpy(), sprintf() writes data to a buffer. If the formatted output exceeds the buffer's capacity, it overflows the buffer, corrupting memory.",
                attack_scenario="An attacker controls the input to the format string or the arguments. The resulting formatted string exceeds the buffer size, corrupting stack variables.",
                remediation_guidance="Use snprintf() to specify the maximum number of bytes to write.",
                secure_alternative="snprintf(buffer, sizeof(buffer), ...)",
                cwe_mapping="CWE-120: Buffer Copy without Checking Size of Input",
                stride_mapping="Elevation of Privilege, Tampering",
                secure_coding_example="char dest[256];\nsnprintf(dest, sizeof(dest), \"Format: %s\", input);"
            ),
            "strcat()": VulnerabilityProfile(
                name="strcat() Function Usage",
                severity=Severity.HIGH,
                description="The strcat() function appends a copy of the source string to the end of the destination string, without bounds checking.",
                technical_explanation="It assumes the destination buffer is large enough to hold both strings. If it isn't, a buffer overflow occurs.",
                attack_scenario="An attacker provides input that, when concatenated with another string, exceeds the destination buffer length, resulting in memory corruption.",
                remediation_guidance="Use length-bounded concatenation functions.",
                secure_alternative="strncat() or strlcat()",
                cwe_mapping="CWE-120: Buffer Copy without Checking Size of Input",
                stride_mapping="Elevation of Privilege, Tampering",
                secure_coding_example="char dest[256] = \"Initial: \";\nstrncat(dest, src, sizeof(dest) - strlen(dest) - 1);"
            ),
            "system()": VulnerabilityProfile(
                name="system() Function Usage",
                severity=Severity.HIGH,
                description="The system() function executes a command specified in string by calling the host environment's command processor.",
                technical_explanation="If the command string incorporates unsanitized user input, an attacker can inject malicious shell commands (OS Command Injection).",
                attack_scenario="Application executes `system(\"ping \" + user_input)`. Attacker provides `127.0.0.1; rm -rf /`, causing the application to execute arbitrary commands.",
                remediation_guidance="Avoid using system() if possible. Use exec() family of functions which do not invoke a shell, or carefully sanitize input.",
                secure_alternative="execve() or fork()+exec()",
                cwe_mapping="CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                stride_mapping="Elevation of Privilege, Information Disclosure, Spoofing, Tampering, Repudiation, Denial of Service",
                secure_coding_example="pid_t pid = fork();\nif (pid == 0) {\n    execl(\"/bin/ls\", \"ls\", \"-l\", NULL);\n}"
            ),
            "rand()": VulnerabilityProfile(
                name="rand() Function Usage",
                severity=Severity.MEDIUM,
                description="The rand() function generates a sequence of pseudo-random numbers with a short period and predictable values.",
                technical_explanation="rand() is a linear congruential generator, which is cryptographically weak. An attacker can predict the sequence if they observe a few outputs.",
                attack_scenario="Application uses rand() to generate a session token or encryption key. An attacker predicts the values and hijacks user sessions or decrypts data.",
                remediation_guidance="Use a cryptographically secure pseudo-random number generator (CSPRNG) for any security-sensitive operations.",
                secure_alternative="getrandom() or /dev/urandom",
                cwe_mapping="CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
                stride_mapping="Information Disclosure, Spoofing",
                secure_coding_example="#include <sys/random.h>\nunsigned int secure_rand;\nif (getrandom(&secure_rand, sizeof(secure_rand), 0) == -1) {\n    // Handle error\n}"
            ),
            "Hardcoded Credentials": VulnerabilityProfile(
                name="Hardcoded Credentials",
                severity=Severity.CRITICAL,
                description="Authentication credentials (like passwords or cryptographic keys) are hardcoded in the source code.",
                technical_explanation="Hardcoded secrets can be extracted from the source code or binary. Once extracted, they provide unauthorized access to systems or data.",
                attack_scenario="An attacker extracts a hardcoded database password from an application binary and uses it to connect directly to the database and steal sensitive information.",
                remediation_guidance="Store secrets externally using environment variables, configuration files with strict permissions, or a dedicated secrets management system.",
                secure_alternative="Environment variables or Secrets Manager",
                cwe_mapping="CWE-798: Use of Hard-coded Credentials",
                stride_mapping="Elevation of Privilege, Information Disclosure, Spoofing",
                secure_coding_example="const char *db_pass = getenv(\"DB_PASSWORD\");\nif (!db_pass) {\n    // Handle missing configuration\n}"
            ),
            "Memory Leaks": VulnerabilityProfile(
                name="Memory Leaks",
                severity=Severity.MEDIUM,
                description="Memory is allocated dynamically but never freed after use.",
                technical_explanation="Continuous memory leaks consume system resources over time, eventually leading to application crashes due to out-of-memory (OOM) conditions.",
                attack_scenario="An attacker repeatedly triggers a specific application path that leaks memory, intentionally exhausting the server's memory and causing a Denial of Service (DoS).",
                remediation_guidance="Ensure every allocation (malloc, calloc, new) has a corresponding deallocation (free, delete) in all execution paths, including error handling.",
                secure_alternative="Proper resource management, RAII (in C++), or smart pointers.",
                cwe_mapping="CWE-401: Missing Release of Memory after Effective Lifetime",
                stride_mapping="Denial of Service",
                secure_coding_example="char *ptr = malloc(1024);\nif (!ptr) return -1;\n// Use ptr\nfree(ptr); // Ensure it's freed before returning"
            ),
            "Buffer Overflows": VulnerabilityProfile(
                name="Buffer Overflows",
                severity=Severity.CRITICAL,
                description="The software writes data past the boundary of the allocated memory buffer.",
                technical_explanation="Buffer overflows overwrite adjacent memory. On the stack, this can overwrite the return address. On the heap, it can overwrite allocator metadata or function pointers.",
                attack_scenario="An attacker sends a long string that exceeds the buffer size, overwriting the saved instruction pointer and hijacking control flow to execute malicious code.",
                remediation_guidance="Always validate input length before copying into fixed-size buffers. Use safe string handling functions.",
                secure_alternative="Bounds checking and safe APIs (snprintf, strncpy)",
                cwe_mapping="CWE-120: Buffer Copy without Checking Size of Input",
                stride_mapping="Elevation of Privilege, Tampering, Denial of Service",
                secure_coding_example="void safe_copy(char *src, size_t len) {\n    char dest[256];\n    if (len >= sizeof(dest)) return; // Reject or handle error\n    memcpy(dest, src, len);\n    dest[len] = '\\0';\n}"
            ),
            "Use After Free": VulnerabilityProfile(
                name="Use After Free (UAF)",
                severity=Severity.CRITICAL,
                description="The software attempts to access memory after it has been freed.",
                technical_explanation="When memory is freed, the allocator marks it as available. If the application continues to use the dangling pointer, it may corrupt data or be exploited if an attacker can reallocate the memory with controlled data.",
                attack_scenario="An attacker triggers a free() call, then allocates a new object in the same space, and finally uses the dangling pointer to execute arbitrary code or leak information.",
                remediation_guidance="Set pointers to NULL immediately after freeing them. Be mindful of object lifetimes and references.",
                secure_alternative="Nullify pointers after free()",
                cwe_mapping="CWE-416: Use After Free",
                stride_mapping="Elevation of Privilege, Information Disclosure, Tampering",
                secure_coding_example="free(ptr);\nptr = NULL;"
            ),
            "Double Free": VulnerabilityProfile(
                name="Double Free",
                severity=Severity.HIGH,
                description="The software calls free() twice on the same memory address.",
                technical_explanation="Calling free() on an already freed pointer corrupts the memory allocator's internal data structures, often leading to crashes or exploitable vulnerabilities.",
                attack_scenario="An attacker exploits complex error handling paths to trigger a double free, corrupting heap management structures to achieve arbitrary code execution.",
                remediation_guidance="Ensure a pointer is only freed once. Setting the pointer to NULL after the first free() prevents a double free because free(NULL) is a no-op.",
                secure_alternative="Nullify pointers after free()",
                cwe_mapping="CWE-415: Double Free",
                stride_mapping="Elevation of Privilege, Tampering, Denial of Service",
                secure_coding_example="if (ptr) {\n    free(ptr);\n    ptr = NULL;\n}"
            )
        }
        
    def get_profile(self, key: str) -> Optional[VulnerabilityProfile]:
        # Simple string matching to find the right profile
        # e.g., if the key is "gets()", return that profile.
        # If the key is a partial match or generic term, we can search.
        
        # Direct lookup
        if key in self.profiles:
            return self.profiles[key]
            
        # Case insensitive exact lookup
        for k, v in self.profiles.items():
            if k.lower() == key.lower():
                return v
                
        # Substring search (e.g. key="gets" matches "gets()")
        for k, v in self.profiles.items():
            if key.lower() in k.lower() or k.lower() in key.lower():
                return v
                
        return None


class SecurityKnowledgeService:
    """Service to provide vulnerability profiles and guidance."""
    
    def __init__(self):
        self.knowledge_base = KnowledgeBase()
        
    def get_vulnerability_guidance(self, finding_identifier: str) -> Optional[VulnerabilityProfile]:
        """
        Retrieve security guidance based on the finding identifier.
        The identifier could be a function name (e.g., 'gets'), a vulnerability type (e.g., 'Buffer Overflow').
        """
        return self.knowledge_base.get_profile(finding_identifier)
