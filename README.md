# SecureGuard


SecureGuard is an advanced, comprehensive security analysis platform that integrates static code analysis, runtime memory monitoring, and risk assessment into a single cohesive interface. Built for developers and security engineers, SecureGuard simplifies the process of identifying, mapping, and resolving vulnerabilities in C/C++ applications.

## 🌟 Key Features

- **Advanced Static Analysis**: Deeply inspect source code for insecure functions, buffer overflow risks, and poor practices without needing to execute the code.
- **Comprehensive Runtime Monitoring**: Leverage powerful integration with AddressSanitizer (ASan) and Valgrind to catch memory leaks, use-after-free, and segmentation faults during execution.
- **Risk Dashboard**: Get an immediate executive summary of your project's security posture, including severity breakdowns and historical trends.
- **Framework Mapping**: Automatically map detected vulnerabilities to standard security frameworks like CWE, MITRE ATT&CK, and OWASP, making compliance tracking effortless.
- **Knowledge Base**: Integrated contextual help providing mitigation strategies and code examples for fixing identified vulnerabilities.

| Runtime Analysis | Risk Dashboard |
|------------------|----------------|
| ![Runtime Analysis](screenshots/runtime-analysis.png) | ![Risk Dashboard](screenshots/risk-dashboard.png) |

## 🛠️ Technologies Used

- **Python 3**: Core application logic.
- **PyQt6**: Modern, responsive Graphical User Interface.
- **AddressSanitizer (ASan) / Valgrind**: Underlying engines for robust memory analysis.
- **pycparser**: Used for AST (Abstract Syntax Tree) generation in static analysis.
- **psutil**: System monitoring and resource management.

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/secureguard.git
   cd secureguard
   ```

2. **Set up a Virtual Environment (Recommended)**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install System Dependencies** (for Runtime Analysis)
   - Ensure Valgrind and GCC (with ASan support) are installed on your system.
   ```bash
   sudo apt-get install valgrind gcc
   ```

## 💻 Usage

Start the application by running:

```bash
python secureguard/main.py
```

Navigate through the interface to perform static scans on your code directories, or attach the runtime monitor to your compiled executables.

## 🏗️ Project Architecture

SecureGuard is built with a modular architecture to allow easy extension:
- `core/`: Data models, framework mappings, and the knowledge base.
- `gui/`: PyQt6 components divided into reusable widgets and main views.
- `static_analysis/`: AST and Regex based scanners.
- `runtime_analysis/`: Valgrind and ASan engine wrappers and process monitors.
- `logging_engine/`: Centralized secure audit logging.

## 🔮 Future Roadmap

- **Enhanced Multi-Language Support**: Expand static analysis capabilities to Java and Python.
- **CI/CD Integration**: Headless mode for running scans directly in GitHub Actions or Jenkins.
- **Machine Learning Heuristics**: Implement AI-driven false-positive reduction.
- **Exporting Reports**: Generate PDF and HTML compliance reports.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
