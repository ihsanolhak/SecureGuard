# SecureGuard Handoff Documentation

This document tracks the progress, implementation details, and objectives completed across each phase of the SecureGuard vulnerability scanner project.

---

## 📅 Completion Status & History

### Phases 1–3: Foundation & Static Analysis
* **Core Models**: Defined standard vulnerability data models (`Vulnerability`, `Severity`, `ScanResult`, `LogEntry`) and interface definitions.
* **Regex Static Analysis**: Built rules to scan C/C++ files for vulnerable APIs like `gets`, `strcpy`, `sprintf`, `system`, etc.
* **AST Correlation Engine**: Used `pycparser` to build an Abstract Syntax Tree (AST) validation stage that verifies if matches correspond to real function calls, effectively reducing static false positives. Added structural checks for unbalanced `malloc`/`free` calls.

### Phase 4: Sandboxed Runtime Analysis
* **Sandbox execution engine** (`monitor.py`): Runs the target binary within a monitored process, capturing `stdout`, `stderr`, and exit statuses.
* **Attack Simulation Mode**: Injects a long payload (150 bytes) into the C program's stdin to simulate a buffer overflow attack.
* **Crash Detection**: Detects segmentation faults or abnormal program exits through the OS signals and marks them as `CRITICAL` vulnerability findings.

### Phase 5: Valgrind Integration
* **Valgrind Execution & Parsing Engine** (`valgrind_engine.py`):
  * Monitored execution run through `valgrind --tool=memcheck --xml=yes`.
  * Parsed results in a structured XML format, falling back to a robust regex text parser when XML is missing/malformed.
  * Captures invalid reads, invalid writes, memory leaks, uninitialized accesses, mismatched frees, overlapping buffers, and use-after-free events.
  * Translates raw Valgrind trace events to SecureGuard `Vulnerability` objects, resolving precise file names and line numbers.
* **Memory Analysis Tab** (`memory_analysis.py`):
  * Dedicated PyQt6 interface with dashboard cards tracking Scans Run, Issues Found, Memory Leaks, and Invalid Accesses.
  * Split layout showing a list of errors on the left, and a full detail view (including trace stack frames) on the right.
  * JSON report exporter for sharing analysis data.

---

### Phase 6: AddressSanitizer (ASan) Support
* **ASan Compilation Utility**: Integrates on-the-fly compiling of C/C++ source files using GCC/G++ with flags `-fsanitize=address -g -O1` so that compiler-instrumented binaries can be executed and checked for memory safety bugs dynamically.
* **ASan Output Parser** (`asan_engine.py`):
  * Parses structured and unstructured ASan diagnostic outputs.
  * Detects heap, stack, and global buffer overflows, use-after-free, double frees, invalid frees, allocation-deallocation mismatches, and memory leaks (using LeakSanitizer).
  * Automatically extracts stack trace frames, variables involved, size of out-of-bounds operations, and primary faulting files and lines.
* **Static-to-Runtime Exploitation Correlation**:
  * Cross-references line-level dynamic ASan memory errors against rules triggered during static scanning of the source file.
  * When a match occurs, upgrades the vulnerability type to `[Correlated]` and flags it as a confirmed runtime exploit, linking the specific static vulnerability recommendation and ASan memory error details.
* **Dual Sanitizer GUI Integration**:
  * Upgraded **Memory Analysis** tab with a dropdown option to select between ASan and Valgrind tools.
  * Dynamic compilation triggers automatically if a `.c` or `.cpp` file is analyzed under either tool.
  * Dashboard indicators update counts for total runs, issues found, leaks, and invalid memory accesses.
* **Consolidated Reports Dashboard**:
  * Rebuilt the **Reports** view to consolidate findings from both Static Analysis and Memory/Sanitizer runs.
  * Generates premium styled HTML reports with risk score matrices, graphical statistics, and colored severity badges, alongside readable text-based security reports.

### Phase 7: Security Knowledge Engine
* **Offline Knowledge Base (`core/knowledge.py`)**:
  * Built an integrated dictionary tracking vulnerability profiles without relying on external APIs or AI.
  * Profiles contain Severity, Description, Technical Explanation, Attack Scenario, Remediation Guidance, Secure Alternative, CWE Mapping, STRIDE Mapping, and Secure Coding Examples.
  * Contains definitions for risky API usage (`gets`, `strcpy`, `sprintf`, `strcat`, `system`, `rand`), hardcoded credentials, memory leaks, buffer overflows, use-after-free, and double free instances.
* **SecurityKnowledgeService**: Maps specific finding identifiers (e.g., function names or vulnerability types) to their respective vulnerability profiles.
* **GUI Component (`KnowledgePanel`)**:
  * Encapsulated premium Knowledge Panel widget designed for a dark aesthetic and readability.
  * Integrated seamlessly into both **Static Analysis** and **Memory Analysis** views via splitters.
  * Provides dynamic and immediate feedback when a finding is selected, displaying all relevant security guidance directly beside the findings table and code preview.

### Phase 8: Security Framework Mapping & AI Removal
* **AI Feature Deletion**: Completely removed `AIAssistantView` and associated navigation/buttons from the project to accommodate offline, low-resource environments.
* **Security Framework Mapping (`core/frameworks.py`)**:
  * Created `CWEDatabase` containing CWE IDs, names, and categories.
  * Created `STRIDEDatabase` mapping STRIDE threats to security properties and descriptions.
  * Built `SecurityFrameworkMapper` to systematically map application findings (e.g., `strcpy`, use-after-free, buffer overflows) to their corresponding CWEs and STRIDE categories.
* **Framework Mapping GUI (`gui/views/framework_mapping.py`)**:
  * Added a dedicated **Framework Mapping View** to the main navigation.
  * Implemented a refresh mechanism that pulls active findings from Static Analysis and Memory Analysis sessions.
  * Generates real-time **CWE Statistics**, **STRIDE Statistics**, and **Security Category Distribution**.
  * Displays a clear tabular mapping of findings alongside a rich text Threat Analysis Panel detailing the distribution of framework mappings.

### Phase 9: Tamper-Proof Logging
* **SecureLogEntry / SecureLogger (`logging_engine/secure_logger.py`)**:
  * Every log entry contains: Timestamp, Event Type, Severity, Message, Previous Hash, and Current Hash.
  * SHA-256 hash chaining: each entry's hash covers its own payload **plus** the hash of the preceding entry. Modifying any single entry breaks every subsequent hash in the chain.
  * Singleton pattern ensures all modules share a single logger instance.
  * Supports event types: System, Scan, Runtime, Memory, Security, Framework, Report.
  * Supports severities: INFO, WARNING, ERROR, CRITICAL.
  * Persists entries as JSONL (one JSON object per line) in `secureguard/logs/secure_audit.jsonl`.
* **LogVerifier**:
  * Recomputes the entire SHA-256 chain from the genesis hash and compares against stored hashes.
  * If any entry was added, removed, or modified, verification fails and identifies the exact tampered entries.
* **Logging Integration**:
  * **Static Analysis View**: Logs scan start, scan completion (with risk score), and every individual finding.
  * **Runtime Analysis View**: Logs execution start (with attack mode status), crashes, and normal completions.
  * **Memory Analysis View**: Logs analysis start (with tool selection), completion summary, and every memory finding.
* **Rebuilt Logs GUI (`gui/views/logs.py`)**:
  * **Log Viewer**: Full table displaying Timestamp, Event Type, Severity, Message, Previous Hash, and Current Hash.
  * **Log Search**: Text search that filters log messages by keyword.
  * **Log Filters**: Dropdown filters for Event Type and Severity level.
  * **Integrity Status Indicator**: Banner that shows green (VERIFIED) or red (FAILED) after integrity check.
  * **Verification Report**: Detailed per-entry chain verification shown in the detail panel, with exportable text report.
  * Dashboard stat cards: Total Entries, Security Events, Scan Events, Runtime Events.

### Phase 10: Risk Correlation Engine & Advanced Assessment
* **Extended Data Models (`core/models.py`)**:
  * Added `AnalysisSource` enum to track which analysis tool discovered each vulnerability.
  * Added `RiskRating` enum for risk classification (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL).
  * Extended `Vulnerability` model with source tracking and CWE/STRIDE mappings.
  * Created `RiskScore` dataclass containing: Overall Security Score, Exploitability Score, Confidence Score, Criticality Score, and Risk Rating.
  * Created `CorrelatedFinding` dataclass to group related findings from multiple sources with exploitation chain tracking.
  * Created `AnalysisSessionMetrics` dataclass for aggregate session-level risk metrics.

* **Correlation Engine (`core/correlation.py`)**:
  * **CorrelationEngine**: Intelligently correlates findings from multiple sources (Static Regex, Static AST, Runtime Sandbox, Valgrind, AddressSanitizer).
    * Groups vulnerabilities by file location and type similarity (configurable tolerance).
    * Deduplicates findings across sources.
    * Identifies exploitation chains linking related vulnerabilities.
    * Maintains location and type similarity thresholds for accurate grouping.
  
  * **ExploitabilityCalculator**: Calculates exploitability scores (0-100) based on:
    * Vulnerability type patterns (high-risk patterns: buffer overflow, format string, RCE, etc.).
    * Runtime confirmation (vulnerabilities confirmed by runtime analysis get boosted scores).
    * Severity level weighting.
  
  * **ConfidenceCalculator**: Calculates confidence scores (0-100) based on:
    * Number and type of analysis sources detecting the vulnerability.
    * Source reliability hierarchy (ASan > Valgrind > Runtime > AST > Regex).
    * Multi-source agreement bonus for increased confidence.
    * Generates human-readable confidence descriptions.
  
  * **RiskAssessmentService**: Generates comprehensive risk metrics:
    * **Criticality Score**: Combines severity, exploitability, and confidence.
    * **Risk Rating**: Overall application security rating from CRITICAL to MINIMAL.
    * **Remediation Priority**: Assigns urgency level (Critical, High, Medium, Low).
    * Supports both individual finding assessment and session-level aggregate assessment.

* **Risk Dashboard View (`gui/views/risk_dashboard.py`)**:
  * Displays aggregate security metrics with color-coded cards for:
    * Overall Security Score (0-100%, automatically color-graduated).
    * Risk Rating (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL with threat colors).
    * Exploitability Score (0-100%).
    * Confidence Level (0-100%).
    * Criticality Score (0-100%).
  * Severity distribution breakdown (Critical, High, Medium, Low counts).
  * Correlated findings count and unique vulnerabilities summary.
  * Sortable table of all correlated findings with columns for: Vulnerability Type, File, Line, Severity, Risk Rating, Criticality, and Exploitability.
  * Color-coded severity and rating cells for quick visual scanning.

* **Finding Correlation View (`gui/views/finding_correlation.py`)**:
  * Split-panel interface showing:
    * Left: Correlated finding groups with metadata (sources, count, confidence, exploitability, priority).
    * Right: Detailed analysis of selected finding including:
      * Related vulnerabilities from all sources.
      * Risk metrics (all four scores + rating).
      * CWE and STRIDE mappings.
      * Exploitation chain steps.
      * Remediation recommendations from all related findings.
  * Interactive filtering by severity level (All, Critical, High, Medium, Low).
  * Sorting options (by Criticality, Source Count, or Exploitability).
  * Color-coded priority indicators for remediation action levels.

* **Executive Summary Panel (`gui/components/executive_summary.py`)**:
  * High-level security posture overview with:
    * Risk rating with human-readable threat description.
    * Visual security score progress bar (auto-colored by score level).
    * Key findings summary highlighting exploitability, confirmation status, and severity.
    * Recommended actions tailored to risk rating (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL).
    * Session metrics including findings count, source breakdown, and highest severity.
  * Integrated into the main Dashboard view.

* **Dashboard Enhancement**:
  * Added risk correlation metrics row with Risk Rating, Correlated Findings, Exploitable Count, and Average Confidence cards.
  * Integrated Executive Summary Panel for quick security posture assessment.
  * Connected to correlation engine for real-time metric updates.

* **Model & Architecture Integration**:
  * All analysis views (Static, Runtime, Memory) can feed findings into CorrelationEngine.
  * Correlation results automatically update Risk Dashboard and Finding Correlation View.
  * Metrics feed into Executive Summary for stakeholder communication.
  * Full traceability from raw findings to aggregated risk ratings.

---

### Phase 11: Professional Reporting System
* **Report Data Models (`reports/report_models.py`)**:
  * **ReportType enum**: Defines four professional report types:
    * EXECUTIVE: High-level overview for management and executives.
    * TECHNICAL: Detailed analysis for security professionals and developers.
    * DEVELOPER: Code-focused guidance with remediation examples.
    * COMPREHENSIVE: Complete assessment combining all sections.
  
  * **SecurityReport dataclass**: Main report structure containing:
    * ReportMetadata: Title, type, generation timestamp, project info, organization, analyst, version, confidentiality level.
    * ProjectSummary: Project name, version, description, files scanned, total LOC, programming languages, analysis duration.
    * SecurityMetrics: Overall security score (0-100%), risk rating, exploitability/confidence/criticality scores, findings breakdown by severity.
    * VulnerabilityDetail: Individual finding data including type, severity, location, line number, sources, CWE/STRIDE mappings, all risk scores, exploitation steps, secure code examples.
    * CWE and STRIDE statistics dictionaries for framework analysis.
    * Recommendations list tailored to risk level.
    * Summary texts for executive and technical audiences.
    * `to_dict()` method for JSON serialization.

* **HTML Report Generator (`reports/html_report_generator.py`)**:
  * Professional HTML report generation with responsive design and print optimization.
  * Full CSS styling (500+ lines) with:
    * Brand color scheme (blue #1976D2, red #D32F2F, orange #F57C00, yellow #FBC02D, green #388E3C).
    * Responsive grid layouts for multi-column sections.
    * Color-coded severity badges and status indicators.
    * Professional typography and spacing.
  
  * Report type-specific rendering:
    * EXECUTIVE: Title/metadata, executive summary, security metrics, recommendations.
    * TECHNICAL: All executive sections + detailed findings with CWE/STRIDE tables, exploitation chains.
    * DEVELOPER: All technical sections + secure code examples, remediation steps, exploit simulations.
    * COMPREHENSIVE: All sections combined.
  
  * Complete HTML structure with DOCTYPE, meta tags, responsive viewport.
  * All required sections: Header with metadata, Executive Summary with risk banner, Project Summary table, Security Metrics card grid, Severity distribution, Detailed Findings cards with CWE/STRIDE data, Exploitation Chain visualization, Recommendations, Footer with confidentiality notice.

* **PDF Report Generator (`reports/pdf_report_generator.py`)**:
  * PDF generation using reportlab library with graceful fallback to text format if reportlab unavailable.
  * In-memory PDF generation returning bytes for direct export.
  * Styled document with:
    * Header section with metadata table.
    * Executive summary with risk score banner and threat assessment.
    * Metrics section with scoring table.
    * Findings table (limited to 20 entries for readability).
    * Framework analysis with CWE and STRIDE tables.
    * Recommendations section.
    * Footer with timestamp and confidentiality notice.
  
  * Customized reportlab ParagraphStyles for title, headings, body text, and footer.
  * Color-coded severity badges and risk indicators.
  * Risk color mapping: Critical=#D32F2F, High=#F57C00, Medium=#FBC02D, Low=#4CAF50.

* **Report Service (`reports/report_service.py`)**:
  * **ReportService class**: Orchestrates report generation and export across all formats.
  * `generate_report()` method:
    * Accepts CorrelatedFinding list and AnalysisSessionMetrics.
    * Builds complete SecurityReport object from findings and metrics.
    * Converts CorrelatedFinding to VulnerabilityDetail with CWE/STRIDE extraction.
    * Generates CWE and STRIDE statistics dictionaries.
    * Produces recommendations tailored to risk level and finding characteristics.
    * Extracts executive and technical summary texts based on risk rating.
  
  * Export methods:
    * `export_html(report, output_path)`: Returns HTML string or writes to file.
    * `export_pdf(report, output_path)`: Returns PDF bytes or writes to file.
    * `export_json(report, output_path)`: Returns JSON string or writes to file.
    * `export_csv(report, output_path)`: Exports findings as CSV with all metadata.

* **Enhanced Reports GUI View (`gui/views/reports.py`)**:
  * **ReportGeneratorThread**: Background worker thread for non-blocking report generation.
    * Emits progress signals during generation and export.
    * Returns success/error status with messages.
  
  * **ReportsView improvements**:
    * Report type selector (dropdown): Executive, Technical, Developer, Comprehensive.
    * Export format selector (dropdown): HTML, PDF, JSON, CSV.
    * "Generate & Export Report" button: Main report generation with user selection.
    * "Quick Executive Report" button: One-click Executive HTML report.
    * "Quick Technical Report" button: One-click Technical HTML report.
    * Progress bar and status label for background generation feedback.
    * Informational section describing all four report types and their use cases.
    * File dialog for saving reports with appropriate file extensions.
    * Integration with Risk Assessment view to pull CorrelatedFinding and AnalysisSessionMetrics.
    * Fallback integration with legacy Static/Memory Analysis views.

* **Integration Points**:
  * ReportService connects to Risk Correlation Engine output (CorrelatedFinding objects).
  * Pulls session metrics from AnalysisSessionMetrics (combines all source data).
  * Extracts CWE/STRIDE mappings from correlated findings.
  * Identification of exploitable findings through is_exploitable flags.
  * Source attribution (finding_sources enum values).
  * HTML/PDF export output ready for stakeholder distribution.

* **Export Capabilities**:
  * HTML: Professional browser-viewable reports with CSS styling and responsive design.
  * PDF: Portable document format with embedded styling and multi-page layout.
  * JSON: Machine-readable format for integration with other tools or archival.
  * CSV: Spreadsheet-compatible findings export for quick analysis.
  * All exports include metadata, findings details, and recommendations.
  * All exports support all four report types with appropriate content filtering.

