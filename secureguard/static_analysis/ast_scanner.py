import re
import uuid
from pycparser import c_parser, c_ast
from secureguard.core.models import Vulnerability, Severity

class ASTValidator(c_ast.NodeVisitor):
    def __init__(self):
        self.func_calls = []
        self.pointers = []
        self.assignments = []

    def visit_FuncCall(self, node):
        if getattr(node.name, 'name', None):
            self.func_calls.append((node.name.name, node.coord.line if node.coord else None))
        self.generic_visit(node)
        
    def visit_PtrDecl(self, node):
        self.pointers.append(node.coord.line if node.coord else None)
        self.generic_visit(node)

class ASTCorrelationEngine:
    def __init__(self):
        self.parser = c_parser.CParser()
        
    def clean_c_code(self, code: str) -> str:
        """Removes preprocessor directives and comments so pycparser can parse without cpp"""
        lines = code.split('\n')
        cleaned = []
        for line in lines:
            if re.match(r'^\s*#', line):
                cleaned.append("") # preserve line numbers
            else:
                cleaned.append(line)
        text = '\n'.join(cleaned)
        
        # Remove // comments
        text = re.sub(r'//.*', '', text)
        
        # Remove /* */ comments but keep newlines to preserve line numbers
        def replacer(match):
            return '\n' * match.group(0).count('\n')
        text = re.sub(r'/\*.*?\*/', replacer, text, flags=re.DOTALL)
        
        return text

    def validate_findings(self, file_path: str, regex_vulns: list) -> list:
        if not file_path.endswith('.c'):
            # pycparser is for C only
            return regex_vulns
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
                
            cleaned_code = self.clean_c_code(code)
            # Create dummy typedefs for standard types to prevent parse errors
            dummy_typedefs = "typedef int size_t; typedef int FILE; typedef int uint8_t; typedef int uint16_t; typedef int uint32_t;\n"
            ast = self.parser.parse(dummy_typedefs + cleaned_code, filename=file_path)
            
            visitor = ASTValidator()
            visitor.visit(ast)
            
            ast_func_calls = {}
            for name, line in visitor.func_calls:
                if line:
                    actual_line = line - 1
                    ast_func_calls[actual_line] = name
                    
            validated = []
            # 1. Regex Validation (False Positive Reduction)
            for vuln in regex_vulns:
                line = vuln.line_number
                if vuln.vuln_type in ["Buffer Overflow", "Command Injection"]:
                    if line in ast_func_calls:
                        vuln.description += " [AST Validated: Confirmed function call]"
                        validated.append(vuln)
                    else:
                        pass # False positive removed
                else:
                    validated.append(vuln)
            
            # 2. Add New AST-based Detections
            malloc_lines = [line - 1 for name, line in visitor.func_calls if name == 'malloc' and line]
            free_lines = [line - 1 for name, line in visitor.func_calls if name == 'free' and line]
            
            # Memory Leaks
            if len(malloc_lines) > len(free_lines) and malloc_lines:
                vuln = Vulnerability(
                    id=str(uuid.uuid4())[:8],
                    severity=Severity.HIGH,
                    vuln_type="Memory Leak",
                    file_path=file_path,
                    line_number=malloc_lines[0],
                    description="[AST Detected] Potential memory leak. Unbalanced malloc() vs free() calls.",
                    recommendation="Ensure all allocated memory is properly freed."
                )
                validated.append(vuln)

            # Null Pointer Risks / Dangerous Pointers
            # Simple heuristic: If a pointer is declared and used in certain contexts without NULL check
            if visitor.pointers:
                ptr_line = visitor.pointers[0] - 1
                vuln = Vulnerability(
                    id=str(uuid.uuid4())[:8],
                    severity=Severity.MEDIUM,
                    vuln_type="Null Pointer Risk",
                    file_path=file_path,
                    line_number=ptr_line if ptr_line > 0 else 1,
                    description="[AST Detected] Dangerous pointer usage. Pointer may not be checked for NULL before dereference.",
                    recommendation="Always check pointers against NULL before accessing them."
                )
                validated.append(vuln)
                
            return validated
            
        except Exception as e:
            return regex_vulns
