#!/usr/bin/env python3
"""
AEGIS Vulnerability Scanner & Security Auditor
A standalone CLI utility for security auditing, port scanning, and header checks.
"""

import socket
import ssl
import json
import argparse
import sys
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Default configuration settings
DEFAULT_TIMEOUT = 1.0
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
    "passed": 0
}

# Outdated software signature database (Simple matches)
OUTDATED_SOFTWARE = {
    "nginx": {"version": "1.24.0", "notes": "Upgrade to nginx/1.26.1+ (Stable)"},
    "apache": {"version": "2.4.54", "notes": "Upgrade to Apache 2.4.58+ (Stable)"},
    "php": {"version": "8.1.0", "notes": "Upgrade to PHP 8.3+ (Stable)"},
    "openssh": {"version": "8.9", "notes": "Upgrade to OpenSSH 9.3p1+ or apply patches"}
}

class AegisScanner:
    def __init__(self, target, ports=None, timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.ports = ports if ports else DEFAULT_PORTS
        self.timeout = timeout
        
        # Parse target name / host
        parsed = urllib.parse.urlparse(self.target)
        self.host = parsed.netloc if parsed.netloc else parsed.path
        if ":" in self.host:
            self.host = self.host.split(":")[0]
            
        self.target_ip = None
        self.findings = []
        self.open_ports = {}
        self.start_time = datetime.now()

    def resolve_target(self):
        """Resolves target hostname to IP address."""
        print(f"[*] Resolving target host: {self.host}...", end="", flush=True)
        try:
            self.target_ip = socket.gethostbyname(self.host)
            print(f" Success ({self.target_ip})")
            return True
        except socket.gaierror as e:
            print(f" Failed\n[!] Error: Unable to resolve host '{self.host}'. {e}")
            return False

    def scan_single_port(self, port):
        """Checks if a TCP port is open and attempts a basic banner grab."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            result = s.connect_ex((self.target_ip, port))
            if result == 0:
                banner = ""
                # Attempt to grab a banner for service ports
                try:
                    if port in [21, 22, 23, 25, 110, 143]:
                        # Read initial greeting banner from server
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    elif port in [80, 8080]:
                        # Send simple HTTP request to grab headers
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                return port, True, banner
        except Exception:
            pass
        finally:
            s.close()
        return port, False, ""

    def run_port_scan(self):
        """Executes multi-threaded port scan on chosen list."""
        print(f"[*] Executing port scan (timeout={self.timeout}s)...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self.scan_single_port, self.ports)
            
        for port, is_open, banner in results:
            if is_open:
                self.open_ports[port] = banner
                print(f"    [+] Port {port:5} : OPEN | {banner[:60] if banner else 'No banner detected'}")
                self.audit_port_vulnerabilities(port, banner)

    def audit_port_vulnerabilities(self, port, banner):
        """Checks if open ports represent security issues based on type or banner names."""
        # Port 21 - FTP
        if port == 21:
            self.findings.append({
                "id": "SEC-PORT-021",
                "severity": "high",
                "title": "Plaintext FTP Protocol Enabled",
                "category": "Insecure Protocol",
                "port": f"21/tcp",
                "description": f"FTP service was detected on port 21. Banner: '{banner or 'Unknown'}'. FTP transmits data in cleartext.",
                "impact": "Network sniffers can capture usernames, passwords, and file contents.",
                "remediation": "Migrate to SFTP (port 22) or FTPS (FTP over TLS) and disable plaintext FTP."
            })
            
        # Port 23 - Telnet
        elif port == 23:
            self.findings.append({
                "id": "SEC-PORT-023",
                "severity": "high",
                "title": "Cleartext Telnet Service Running",
                "category": "Insecure Protocol",
                "port": f"23/tcp",
                "description": "Telnet service is open on port 23. Telnet does not encrypt administrative login traffic.",
                "impact": "Attackers can intercept keystrokes and administrative login credentials.",
                "remediation": "Disable Telnet and replace it with SSH."
            })

        # Version Banner auditing
        if banner:
            banner_lower = banner.lower()
            for software, info in OUTDATED_SOFTWARE.items():
                if software in banner_lower:
                    # Parse version numbers safely
                    detected_ver = self.parse_version(banner_lower, software)
                    if detected_ver and detected_ver < info["version"]:
                        self.findings.append({
                            "id": f"SEC-VER-{software.upper()}",
                            "severity": "medium",
                            "title": f"Outdated {software.capitalize()} Version Signature Detected",
                            "category": "Outdated Software Check",
                            "port": f"{port}/tcp",
                            "description": f"The banner for {software} reports version {detected_ver}. The stable/secure threshold is {info['version']}.",
                            "impact": "Known security vulnerabilities (CVEs) exist for older versions of this software.",
                            "remediation": f"{info['notes']}."
                        })

    def parse_version(self, banner_str, software_name):
        """Simplistic parser to extract version numbers from server strings."""
        try:
            tokens = banner_str.replace("/", " ").replace("-", " ").split()
            for i, tok in enumerate(tokens):
                if software_name in tok:
                    # Try next token or parse current token
                    for check_tok in tokens[i:]:
                        # Check if matches version structure e.g. 1.2.3
                        nums = [c for c in check_tok if c.isdigit() or c == '.']
                        version_str = "".join(nums).strip('.')
                        if version_str and '.' in version_str:
                            return version_str
        except Exception:
            pass
        return None

    def audit_web_headers(self):
        """Performs HTTP security header assessment on web target (port 80 or 443)."""
        is_web = 80 in self.open_ports or 443 in self.open_ports or "http" in self.target
        if not is_web:
            return

        print("[*] Launching HTTP security header audit...")
        
        # Determine protocol
        use_https = 443 in self.open_ports or self.target.startswith("https")
        port_to_use = 443 if use_https else 80
        
        try:
            # Connect over HTTP or SSL/HTTPS
            if use_https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self.host, port=port_to_use, context=ctx, timeout=5.0)
            else:
                conn = http.client.HTTPConnection(self.host, port=port_to_use, timeout=5.0)
                
            conn.request("HEAD", "/")
            response = conn.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            conn.close()
            
            # Audit Headers
            self.check_header(headers, "content-security-policy", "Missing Content Security Policy (CSP) Header",
                              "medium", "Missing CSP allows loading of arbitrary unverified script files.",
                              "Inject 'Content-Security-Policy: default-src 'self'' into your web config files.")
                              
            self.check_header(headers, "strict-transport-security", "Missing HTTP Strict Transport Security (HSTS) Header",
                              "medium", "Allows connection downgrades and SSL stripping middlebox attacks.",
                              "Add header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")

            self.check_header(headers, "x-frame-options", "Missing Anti-Clickjacking Header (X-Frame-Options)",
                              "low", "Allows attackers to overlay your page inside arbitrary iframe environments.",
                              "Configure header: 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY'.")

            self.check_header(headers, "x-content-type-options", "Missing MIME-Sniffing Prevention Header",
                              "low", "Permits browser clients to execute style sheets and scripts from MIME-mismatched files.",
                              "Implement: 'X-Content-Type-Options: nosniff'.")

            # Check server broadcast signature
            server_header = headers.get("server", "")
            if server_header:
                self.findings.append({
                    "id": "SEC-HDR-SRV",
                    "severity": "info",
                    "title": f"Web Server Broadcasts Signature ({server_header})",
                    "category": "Information Disclosure",
                    "port": f"{port_to_use}/tcp",
                    "description": f"The response contains server signature: Server: '{server_header}'. Information exposure makes reconnaissance easier.",
                    "impact": "Facilitates quick targeting of version-specific security exploits.",
                    "remediation": "Configure server tokens off in server configurations (e.g. 'server_tokens off' in nginx)."
                })
            else:
                self.findings.append({
                    "id": "SEC-HDR-SRV-OK",
                    "severity": "passed",
                    "title": "Web Server Signature Hidden",
                    "category": "Information Disclosure",
                    "port": f"{port_to_use}/tcp",
                    "description": "Server headers do not broadcast detailed software version identifiers.",
                    "impact": "No risk.",
                    "remediation": "No action required."
                })

            # Check if TLS/HTTPS is active
            if not use_https:
                self.findings.append({
                    "id": "SEC-HDR-TLS",
                    "severity": "high",
                    "title": "Web Traffic Transmitted in Cleartext (No TLS/HTTPS)",
                    "category": "Transport Encryption",
                    "port": "80/tcp",
                    "description": "The site serves assets using HTTP rather than HTTPS. Communications are not encrypted.",
                    "impact": "Risk of session hijacking, credentials theft, and data sniffing on public routers.",
                    "remediation": "Obtain SSL/TLS certificate and configure redirects to enforce HTTPS traffic protocols."
                })
            else:
                self.findings.append({
                    "id": "SEC-HDR-TLS-OK",
                    "severity": "passed",
                    "title": "Transport Layer Security (HTTPS) Active",
                    "category": "Transport Encryption",
                    "port": "443/tcp",
                    "description": "Connection encrypted via TLS layers.",
                    "impact": "No risk.",
                    "remediation": "No action required."
                })

        except Exception as e:
            print(f"    [!] Web audit failed: {e}")

    def check_header(self, headers, header_name, title, severity, impact, remediation):
        """Helper to append configuration header failures."""
        if header_name not in headers:
            self.findings.append({
                "id": f"SEC-HDR-{header_name.upper().replace('-', '_')}",
                "severity": severity,
                "title": title,
                "category": "Security Headers Check",
                "port": "Web Service",
                "description": f"The HTTP header '{header_name}' was not detected in response payloads.",
                "impact": impact,
                "remediation": remediation
            })
        else:
            self.findings.append({
                "id": f"SEC-HDR-{header_name.upper().replace('-', '_')}-OK",
                "severity": "passed",
                "title": f"HTTP Security Header '{header_name}' Verified",
                "category": "Security Headers Check",
                "port": "Web Service",
                "description": f"Header '{header_name}' is correctly configured: '{headers[header_name]}'",
                "impact": "No risk.",
                "remediation": "No action required."
            })

    def compile_report(self):
        """Computes summary statistics and security ratings."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "passed": 0}
        score = 100
        
        for item in self.findings:
            sev = item["severity"]
            if sev in summary:
                summary[sev] += 1
            score -= SEVERITY_WEIGHTS.get(sev, 0)
            
        score = max(0, score)
        return {
            "target": self.target,
            "ip": self.target_ip,
            "timestamp": datetime.now().isoformat(),
            "duration": str(datetime.now() - self.start_time),
            "score": score,
            "summary": summary,
            "findings": self.findings
        }

    def generate_json_report(self, filepath, report_data):
        """Saves scan metadata as a JSON file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4)
            print(f"[*] JSON report exported successfully to: {filepath}")
        except Exception as e:
            print(f"[!] Failed to save JSON report: {e}")

    def generate_html_report(self, filepath, report_data):
        """Compiles an independent, styled HTML scan dashboard on disk."""
        vuln_rows = ""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "passed": 5}
        sorted_findings = sorted(report_data["findings"], key=lambda x: severity_order.get(x["severity"], 5))

        for f in sorted_findings:
            color = self.get_severity_color(f["severity"])
            badge = f"<span class='badge' style='background-color: {color};'>{f['severity'].upper()}</span>"
            
            vuln_rows += f"""
            <div class="card" style="border-left: 5px solid {color}; margin-bottom: 15px; padding: 15px; background: #fff; border-radius: 6px; border-top: 1px solid #eee; border-right: 1px solid #eee; border-bottom: 1px solid #eee;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
                    <h3 style="margin:0; font-size:1rem; color:#1e293b;">{f['title']}</h3>
                    {badge}
                </div>
                <div style="font-size:0.8rem; color:#64748b; margin-bottom: 10px;">
                    <strong>Port/Scope:</strong> {f.get('port', 'N/A')} | <strong>Category:</strong> {f.get('category', 'N/A')}
                </div>
                <p style="margin: 0 0 8px 0; font-size:0.9rem; color:#334155;"><strong>Description:</strong> {f['description']}</p>
                <p style="margin: 0 0 10px 0; font-size:0.9rem; color:#475569;"><strong>Threat Impact:</strong> {f['impact']}</p>
                {f"<div style='background: #f1f5f9; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem;'><strong>Remediation:</strong><br>{f['remediation']}</div>" if f['severity'] != 'passed' else ''}
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AEGIS Security Audit Report - {report_data['target']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f8fafc; color: #334155; margin: 0; padding: 40px; }}
        .header {{ background: #0f172a; color: #fff; padding: 30px; border-radius: 10px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-align: center; color: white; }}
        .grid {{ display: grid; grid-template-columns: 1fr 3fr; gap: 20px; margin-bottom: 30px; }}
        .score-box {{ text-align: center; font-size: 3rem; font-weight: bold; color: {self.get_score_color(report_data['score'])}; }}
        .metric-card {{ background: white; padding: 20px; border-radius: 10px; border: 1px solid #e2e8f0; }}
        .summary-list {{ list-style: none; padding: 0; margin: 0; }}
        .summary-list li {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px dashed #e2e8f0; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="header">
        <h1 style="margin:0; font-size:1.8rem; letter-spacing: 0.05em;">AEGIS SECURITY AUDIT REPORT</h1>
        <p style="margin: 8px 0 0 0; font-size:0.9rem; opacity: 0.8;">Target: {report_data['target']} ({report_data['ip']}) | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="grid">
        <div class="metric-card" style="display:flex; flex-direction:column; justify-content:center; align-items:center;">
            <h4 style="margin:0 0 10px 0; text-transform:uppercase; color:#64748b; font-size:0.75rem; letter-spacing:0.05em;">Security Score</h4>
            <div class="score-box">{report_data['score']}/100</div>
            <p style="margin:10px 0 0 0; font-weight:bold; font-size:0.95rem; color:#64748b;">Risk Index: {self.get_risk_index(report_data['score'])}</p>
        </div>
        
        <div class="metric-card">
            <h4 style="margin:0 0 10px 0; text-transform:uppercase; color:#64748b; font-size:0.75rem; letter-spacing:0.05em;">Findings Summary</h4>
            <ul class="summary-list">
                <li><span>Critical Threats:</span> <strong>{report_data['summary']['critical']}</strong></li>
                <li><span>High Threats:</span> <strong>{report_data['summary']['high']}</strong></li>
                <li><span>Medium Threats:</span> <strong>{report_data['summary']['medium']}</strong></li>
                <li><span>Informational Notices:</span> <strong>{report_data['summary']['info']}</strong></li>
                <li><span>Passed Checks:</span> <strong>{report_data['summary']['passed']}</strong></li>
            </ul>
        </div>
    </div>
    
    <h2 style="font-size:1.3rem; margin-bottom: 15px; color:#0f172a;">Detailed Findings & Remediation Roadmap</h2>
    {vuln_rows if vuln_rows else '<p>No vulnerabilities detected. Origin is secured.</p>'}
    
    <footer style="margin-top:50px; text-align:center; font-size:0.75rem; color:#94a3b8;">
        Report compiled by Aegis Security Suite CLI Scanner.
    </footer>
</body>
</html>"""

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[*] HTML report exported successfully to: {filepath}")
        except Exception as e:
            print(f"[!] Failed to save HTML report: {e}")

    @staticmethod
    def get_severity_color(severity):
        return {
            "critical": "#f43f5e",
            "high": "#f59e0b",
            "medium": "#6366f1",
            "info": "#06b6d4",
            "passed": "#10b981"
        }.get(severity, "#64748b")

    @staticmethod
    def get_score_color(score):
        if score >= 90: return "#10b981"
        if score >= 70: return "#06b6d4"
        if score >= 50: return "#f59e0b"
        return "#f43f5e"

    @staticmethod
    def get_risk_index(score):
        if score >= 90: return "Low Risk"
        if score >= 70: return "Medium Risk"
        if score >= 50: return "High Risk"
        return "Critical Risk"

# Import http.client here to prevent namespace bloat
import http.client

def main():
    parser = argparse.ArgumentParser(description="AEGIS Network & Web Vulnerability Scanner")
    parser.add_argument("target", help="Target host address or IP to audit")
    parser.add_argument("--ports", "-p", help="Comma-separated list of ports to scan", default=None)
    parser.add_argument("--timeout", "-t", type=float, help="Connection timeout (sec)", default=DEFAULT_TIMEOUT)
    parser.add_argument("--output", "-o", help="Filepath prefix to save reports", default="aegis_report")
    args = parser.parse_args()

    # Parse port inputs
    ports = None
    if args.ports:
        try:
            ports = [int(x.strip()) for x in args.ports.split(",")]
        except ValueError:
            print("[!] Error: Ports option must be comma-separated list of integers.")
            sys.exit(1)

    print("==================================================")
    print("      AEGIS Security Audit CLI Scanner v1.0.0     ")
    print("==================================================")
    
    scanner = AegisScanner(args.target, ports, args.timeout)
    if not scanner.resolve_target():
        sys.exit(1)
        
    try:
        scanner.run_port_scan()
        scanner.audit_web_headers()
        
        report = scanner.compile_report()
        
        print("\n================== SCAN SUMMARY ==================")
        print(f"Target:       {report['target']}")
        print(f"IP Address:   {report['ip']}")
        print(f"Security:     {report['score']}/100 ({scanner.get_risk_index(report['score'])})")
        print(f"Critical:     {report['summary']['critical']}")
        print(f"High:         {report['summary']['high']}")
        print(f"Medium:       {report['summary']['medium']}")
        print(f"Passed:       {report['summary']['passed']}")
        print("==================================================")
        
        # Export Reports
        scanner.generate_json_report(f"{args.output}.json", report)
        scanner.generate_html_report(f"{args.output}.html", report)
        
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user control sequence.")
        sys.exit(0)

if __name__ == "__main__":
    main()
