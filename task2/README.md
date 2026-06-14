# AEGIS // Vulnerability Scanner & Security Auditor

AEGIS is a high-fidelity, dual-platform cybersecurity auditing and learning engine. It consists of a dynamic, interactive **Web Security Dashboard** and a robust **Command-Line Interface (CLI) Python Auditor**. Together, they provide both simulated sandbox training, real client-side browser context evaluations, and actual TCP/HTTP remote endpoint assessments.

---

## 🚀 Key Features

### 1. Web Security Dashboard (`index.html`, `app.js`, `style.css`)
A modern, dark-mode cyber security operations UI that serves as an interactive dashboard:
*   **Real Client-Side Origin Auditing:** Analyzes the hosting browser's context to inspect secure execution protocols (`window.isSecureContext`), HTTPS/TLS deployment, external target links missing sandboxing attributes (`rel="noopener noreferrer"`), unprotected nested frames (`iframe` sandboxing), and local session cookie safety practices.
*   **Target Simulation Sandboxes:** Probes interactive target profiles (a vulnerable system stack, a hardened security shield, or custom targets) through a visual radar animation and real-time terminal output logs (`audit_stream.log`).
*   **Remediation Code Playground:** Interactive code comparison tabs showcasing vulnerable vs. secure server setups (Node.js/Express security headers with `helmet`, SQL injection prevention with parameterized queries, and DOM XSS sanitization using `DOMPurify`).
*   **OWASP Security Matrix:** Training cards detail core vulnerability patterns (Broken Access Control, Cryptographic Failures, Injection, Security Misconfiguration) to support cyber awareness.
*   **Report Exporter:** Formats and exports fully responsive HTML and raw JSON reports containing scan metrics and vulnerabilities directly from the browser window.

### 2. Companion CLI Utility (`scanner.py`)
A standalone Python 3 utility to bypass browser sandboxing limits and execute real network evaluations:
*   **Multi-threaded TCP Port Scanner:** Scans specific custom ports or common standard ports to capture server banners.
*   **Software Version Auditor:** Cross-references banner versions (Apache, Nginx, PHP, OpenSSH) against a version-vulnerability threshold database to identify outdated services.
*   **HTTP Header Security Analyzer:** Probes live endpoints to audit response security headers (such as `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, and `X-Content-Type-Options`).
*   **Information Disclosure Prober:** Highlights exposure threats including verbose `Server` header signature broadcasting.
*   **Dual Reporting Outputs:** Writes a styled, standalone HTML report dashboard and a structured JSON dataset back to the project files.

---

## 📂 Project Architecture

```
task2/
├── index.html     # Web dashboard application layout (HTML5 / Lucide Icons)
├── style.css      # Custom dark-theme styling, animations, and typography
├── app.js         # Core front-end audit logic, simulations, and report exports
├── scanner.py     # Standalone Python CLI network & header scanner script
└── README.md      # Documentation (This file)
```

---

## ⚙️ Installation & Prerequisites

### Web Dashboard
*   No complex installations needed. The dashboard runs directly in any modern web browser.
*   To enable real cryptographic browser context checks (e.g. clipboard APIs and secure context triggers), it is recommended to run the app using a local HTTP server instead of opening the HTML file directly.

### CLI Scanner
*   Requires **Python 3.x**.
*   Built entirely using Python's standard library modules (`socket`, `ssl`, `json`, `argparse`, `urllib.parse`, `http.client`, `datetime`, `concurrent.futures`). No third-party package installations (`pip`) are required.

---

## 🛠️ Usage Instructions

### Running the Web Dashboard

1.  **Option A (Using python's built-in server):**
    Open a terminal inside the project directory and execute:
    ```bash
    python -m http.server 8000
    ```
    Then, navigate your web browser to `http://localhost:8000`.

2.  **Option B (Using Node's http-server):**
    ```bash
    npx -y http-server -p 8000
    ```
    Then, navigate to `http://localhost:8000`.

---

### Running the CLI Scanner

Navigate to the project root directory and invoke `scanner.py` using Python 3:

```bash
python scanner.py [target] [options]
```

#### CLI Parameters:
| Argument | Flags | Type | Description |
| :--- | :--- | :--- | :--- |
| **`target`** | *(Positional)* | String | Target hostname or IP address (e.g., `localhost` or `example.com`). |
| **`--ports`** | `-p` | String | Comma-separated list of TCP ports to audit (e.g., `22,80,443`). |
| **`--timeout`** | `-t` | Float | Maximum network socket connection timeout in seconds (Default: `1.0`). |
| **`--output`** | `-o` | String | Filename prefix for the generated HTML and JSON report files (Default: `aegis_report`). |

#### Example Executions:

*   **Quick Scan (Default Ports):**
    ```bash
    python scanner.py localhost
    ```
*   **Custom Target Ports and Output Path:**
    ```bash
    python scanner.py 127.0.0.1 -p 22,80,443,3306,8080 -o custom_audit_results -t 0.5
    ```

---

## 📊 Security Metrics & Severity Guide

AEGIS grades targeted environments out of a base **100 Security Score**. Vulnerabilities degrade the overall rating according to the severity weights below:

*   **Critical (Weight: 30):** Remote Code Execution (RCE), SQL Injection, etc.
*   **High (Weight: 20):** Plaintext authentication protocols (FTP, Telnet), missing TLS wrappers.
*   **Medium (Weight: 10):** Outdated daemon configurations, missing core security headers (`CSP`, `HSTS`).
*   **Low (Weight: 5):** Minor config omissions (`X-Frame-Options`, `X-Content-Type-Options`).
*   **Info (Weight: 0):** Server signature disclosures, environmental notices.

---

## ⚠️ Legal & Ethical Disclaimer

**Authorized Auditing Only.** 
AEGIS is developed strictly for educational, training, and legitimate penetration audit configurations. Attempting to scan or probe host systems without explicit, written permission from the network resource owner is illegal and constitutes a violation of computer fraud laws. Please practice responsible disclosure protocols.
