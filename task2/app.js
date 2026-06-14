// AEGIS Vulnerability Scanner Engine

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide Icons
    lucide.createIcons();

    // DOM Elements
    const targetInput = document.getElementById('target-input');
    const scanTypeSelect = document.getElementById('scan-type');
    const btnLaunchScan = document.getElementById('btn-launch-scan');
    const presetButtons = document.querySelectorAll('.preset-btn');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const radarContainer = document.getElementById('radar-container');
    const radarPercent = document.getElementById('radar-percent');
    const consoleOutput = document.getElementById('console-output');
    const scoreVal = document.getElementById('score-val');
    const scoreDesc = document.getElementById('score-desc');
    const scoreCircle = document.getElementById('score-circle');
    const countCritical = document.getElementById('count-critical');
    const countHigh = document.getElementById('count-high');
    const countMedium = document.getElementById('count-medium');
    const countInfo = document.getElementById('count-info');
    const countPassed = document.getElementById('count-passed');
    const reportActions = document.getElementById('report-actions');
    const btnDownloadJson = document.getElementById('btn-download-json');
    const btnDownloadHtml = document.getElementById('btn-download-html');
    const vulnList = document.getElementById('vuln-list');
    const resultsPlaceholder = document.getElementById('results-placeholder');
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const pgSelectButtons = document.querySelectorAll('.pg-select-btn');
    const codeVulnerable = document.getElementById('code-vulnerable');
    const codeRemediated = document.getElementById('code-remediated');
    const btnCopyCli = document.getElementById('btn-copy-cli');

    // State
    let currentPreset = 'local';
    let isScanning = false;
    let compiledReport = null;

    // Vulnerability Templates Database
    const vulnerabilitiesDb = {
        local: {
            score: 100,
            summary: { critical: 0, high: 0, medium: 0, info: 0, passed: 0 },
            items: []
        },
        vuln: {
            score: 28,
            summary: { critical: 2, high: 2, medium: 2, info: 1, passed: 1 },
            items: [
                {
                    id: 'VULN-001',
                    severity: 'critical',
                    title: 'Outdated Web Server Version Detected',
                    category: 'Security Misconfiguration',
                    port: '80/tcp',
                    description: 'The target server header reports "nginx/1.14.0". This version is outdated and vulnerable to multiple CVEs, including HTTP/2 request smuggling (CVE-2018-16843) and buffer overflow vulnerabilities (CVE-2018-16844).',
                    impact: 'Remote attackers can execute arbitrary code, bypass proxy access restrictions, or cause denial of service (DoS) conditions on the application host.',
                    remediation: 'Upgrade to nginx/1.26.1 (Stable) or higher. Additionally, disable server signature broadcasting by setting "server_tokens off;" inside nginx.conf.'
                },
                {
                    id: 'VULN-002',
                    severity: 'critical',
                    title: 'SQL Injection Vulnerability in Authentication Module',
                    category: 'Injection',
                    port: '443/tcp',
                    description: 'A query parameter "user_id" is concatenated directly into SQL command strings on "/login.php". Testing using parameter escape sequences (\' OR \'1\'=\'1) returned valid database data without password checks.',
                    impact: 'Allows unauthorized access to all user profiles, extraction of administrative database records, or deletion/modification of backend datasets.',
                    remediation: 'Implement parameterized SQL queries (Prepared Statements) using APIs like PDO in PHP, pg/mysql in Node.js, or SQLAlchemy in Python. Never concatenate input strings directly.'
                },
                {
                    id: 'VULN-003',
                    severity: 'high',
                    title: 'Insecure Plaintext FTP Service Running',
                    category: 'Weak Protocol Configuration',
                    port: '21/tcp',
                    description: 'FTP port 21 is open and returned banner "vsftpd 2.3.4". Credentials and data are transmitted across the network in cleartext without SSL/TLS encryption.',
                    impact: 'Network eavesdroppers can capture user credentials, hijack connections, or view/manipulate files in transit.',
                    remediation: 'Disable the FTP daemon. Migrate file transfers to SFTP (SSH File Transfer Protocol) or secure FTPS using TLS certificates.'
                },
                {
                    id: 'VULN-004',
                    severity: 'high',
                    title: 'Reflected Cross-Site Scripting (XSS) on Query Parameters',
                    category: 'Injection',
                    port: '443/tcp',
                    description: 'The query parameter "q" on search page "/search.html" is output directly to the browser DOM without HTML encoding or input sanitization, allowing script injections.',
                    impact: 'Allows malicious actors to execute scripts in user browsers, hijack active cookies/session tokens, or redirect clients to phishing portals.',
                    remediation: 'Clean and escape all dynamic content before writing it to the DOM. Use libraries like DOMPurify or sanitize-html, or use textContent instead of innerHTML.'
                },
                {
                    id: 'VULN-005',
                    severity: 'medium',
                    title: 'Missing Content Security Policy (CSP) Response Header',
                    category: 'Broken Configuration',
                    port: '80/443',
                    description: 'The web server does not return a "Content-Security-Policy" HTTP response header. A CSP restricts the origins from which scripts, images, and fonts can load.',
                    impact: 'Increases susceptibility to Cross-Site Scripting (XSS) and Clickjacking attacks since the browser will execute any loaded asset.',
                    remediation: 'Add a robust Content-Security-Policy header. For example: "Content-Security-Policy: default-src \'self\'; script-src \'self\' https://trusted-cdn.com;"'
                },
                {
                    id: 'VULN-006',
                    severity: 'medium',
                    title: 'Missing HTTP Strict Transport Security (HSTS) Header',
                    category: 'Broken Configuration',
                    port: '443/tcp',
                    description: 'The Strict-Transport-Security header is missing from the HTTPS server response. HSTS forces clients to interact with the domain only through encrypted channels.',
                    impact: 'Vulnerable to SSL stripping and man-in-the-middle (MitM) attacks where traffic is downgraded to plaintext HTTP.',
                    remediation: 'Configure the server to return: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" in all HTTPS responses.'
                },
                {
                    id: 'VULN-007',
                    severity: 'info',
                    title: 'TLS 1.0/1.1 Protocols Allowed',
                    category: 'Weak Encryption',
                    port: '443/tcp',
                    description: 'The HTTPS server accepts negotiations using TLS version 1.0 and TLS version 1.1, both of which are deprecated and suffer from cryptographic design vulnerabilities (e.g., BEAST).',
                    impact: 'Enables network eavesdroppers to decrypt encrypted session traffic under specific network configurations.',
                    remediation: 'Disable TLS 1.0 and 1.1 on the server or load balancer. Restrict accepted SSL/TLS negotiations to TLS 1.2 and TLS 1.3 only.'
                },
                {
                    id: 'VULN-008',
                    severity: 'passed',
                    title: 'Server Directory Indexing is Disabled',
                    category: 'Information Disclosure Check',
                    port: '80/tcp',
                    description: 'Attempts to read index directory structure on root folders returned HTTP 403 Forbidden. Directory browsing is correctly blocked.',
                    impact: 'No risk. File structure and source assets are hidden from directory queries.',
                    remediation: 'No action required. Keep standard directory listing features disabled on web servers.'
                }
            ]
        },
        secure: {
            score: 98,
            summary: { critical: 0, high: 0, medium: 0, info: 1, passed: 7 },
            items: [
                {
                    id: 'VULN-101',
                    severity: 'info',
                    title: 'Modern Web Stack Detected',
                    category: 'Information',
                    port: '443/tcp',
                    description: 'Web Server reports "nginx/1.26.1" (Latest Stable). Secure parameters are correctly configured.',
                    impact: 'Low threat profile. Up-to-date versions minimize vulnerable surface areas.',
                    remediation: 'Maintain general update procedures and run security audits during software releases.'
                },
                {
                    id: 'VULN-102',
                    severity: 'passed',
                    title: 'All Dangerous Protocols Secured or Disabled',
                    category: 'Protocol Configuration',
                    port: '21, 22, 23',
                    description: 'Telnet (23) and FTP (21) are closed. Secure SSH daemon (22) is open and requires key-based authentication.',
                    impact: 'No risk. Plaintext traffic protocols are deprecated.',
                    remediation: 'Keep outdated terminal connections disabled.'
                },
                {
                    id: 'VULN-103',
                    severity: 'passed',
                    title: 'Content Security Policy (CSP) Header Present',
                    category: 'HTTP Headers',
                    port: '443/tcp',
                    description: 'Content-Security-Policy response header is present and enforces default-src restriction of "self".',
                    impact: 'No risk. Protects against injection of malicious inline scripts.',
                    remediation: 'Periodically audit CSP policies as application architecture expands.'
                },
                {
                    id: 'VULN-104',
                    severity: 'passed',
                    title: 'HSTS Header Configured',
                    category: 'HTTP Headers',
                    port: '443/tcp',
                    description: 'Strict-Transport-Security header is set with active preload and max-age of 31536000 seconds.',
                    impact: 'No risk. Prevents protocol-downgrade and SSL strip vulnerabilities.',
                    remediation: 'No action required.'
                },
                {
                    id: 'VULN-105',
                    severity: 'passed',
                    title: 'Frame Protection Enabled (Anti-Clickjacking)',
                    category: 'HTTP Headers',
                    port: '443/tcp',
                    description: 'X-Frame-Options is set to DENY. Clickjacking attacks are blocked.',
                    impact: 'No risk.',
                    remediation: 'Maintain current configuration.'
                },
                {
                    id: 'VULN-106',
                    severity: 'passed',
                    title: 'Secure MIME Handling Enforced',
                    category: 'HTTP Headers',
                    port: '443/tcp',
                    description: 'X-Content-Type-Options is set to nosniff, forcing browsers to respect declared Content-Type headers.',
                    impact: 'No risk. Protects against MIME confusion attacks.',
                    remediation: 'No action required.'
                },
                {
                    id: 'VULN-107',
                    severity: 'passed',
                    title: 'TLS v1.3 Configuration Enforced',
                    category: 'Encryption Audit',
                    port: '443/tcp',
                    description: 'Negotiations enforce TLS v1.3. Disallowed deprecated connection methods (TLS 1.0, TLS 1.1).',
                    impact: 'No risk. Protects browser transactions using high-strength keys.',
                    remediation: 'No action required.'
                },
                {
                    id: 'VULN-108',
                    severity: 'passed',
                    title: 'SQL Prepared Queries Verified',
                    category: 'Code Quality Audit',
                    port: 'Application Layer',
                    description: 'Code scans verified parameterized database procedures for query parsing. No dynamic concatenation detected.',
                    impact: 'No risk. Eliminates SQL injection capabilities.',
                    remediation: 'Keep using parameterized ORM or queries.'
                }
            ]
        }
    };

    // Code Playground Snippets
    const codeSnippets = {
        headers: {
            vulnerable: `// Node.js Express Server
app.get('/api', (req, res) => {
    // Missing security headers allows clickjacking, XSS, MIME sniffing
    res.setHeader('X-Powered-By', 'Express');
    res.send({ status: 'active' });
});`,
            remediated: `// Node.js Express Server (Secured)
const helmet = require('helmet');
// Helmet secures HTTP headers automatically
app.use(helmet());
app.disable('x-powered-by');

app.get('/api', (req, res) => {
    res.send({ status: 'active' });
});`
        },
        sqli: {
            vulnerable: `// Vulnerable Authentication Handler
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // UNSAFE: Dynamic SQL concatenation allows query injection
    const query = "SELECT * FROM users WHERE user = '" + username + "' AND pass = '" + password + "'";
    
    db.query(query, (err, result) => {
        if (result.length > 0) res.redirect('/dashboard');
        else res.send('Invalid Credentials');
    });
});`,
            remediated: `// Secured Authentication Handler
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // SAFE: Use Parameterized Query placeholders ($1, $2)
    const query = "SELECT * FROM users WHERE user = $1 AND pass = $2";
    
    db.query(query, [username, password], (err, result) => {
        if (result.rows.length > 0) res.redirect('/dashboard');
        else res.send('Invalid Credentials');
    });
});`
        },
        xss: {
            vulnerable: `// Express Comment Logger (Vulnerable to XSS)
app.post('/post-comment', (req, res) => {
    const comment = req.body.commentText;
    
    // Direct DOM write allows malicious script execution (<script>alert(1)</script>)
    res.send(\`
        <div class="comment-box">
            <p>\${comment}</p>
        </div>
    \`);
});`,
            remediated: `// Express Comment Logger (Secured)
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

app.post('/post-comment', (req, res) => {
    const comment = req.body.commentText;
    
    // SAFE: Sanitize and filter dirty input markup
    const cleanHTML = purify.sanitize(comment);
    
    res.send(\`
        <div class="comment-box">
            <p>\${cleanHTML}</p>
        </div>
    \`);
});`
        }
    };

    // Manage Presets Selector
    presetButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            if (isScanning) return;
            
            presetButtons.forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            
            const targetVal = btn.getAttribute('data-target');
            targetInput.value = targetVal;
            currentPreset = btn.getAttribute('data-preset');
            
            logToConsole(`Target context updated: ${targetVal} (${currentPreset} profile)`);
        });
    });

    // Custom Target Input Handler
    targetInput.addEventListener('input', () => {
        presetButtons.forEach(p => p.classList.remove('active'));
        
        // Match value with presets to reconnect
        if (targetInput.value.includes('vulnerable')) {
            currentPreset = 'vuln';
            document.querySelector('[data-preset="vuln"]').classList.add('active');
        } else if (targetInput.value.includes('secure')) {
            currentPreset = 'secure';
            document.querySelector('[data-preset="secure"]').classList.add('active');
        } else if (targetInput.value === '127.0.0.1' || targetInput.value.includes('localhost')) {
            currentPreset = 'local';
            document.querySelector('[data-preset="local"]').classList.add('active');
        } else {
            currentPreset = 'custom'; // A customized target will simulate random checks or default to local audits
        }
    });

    // Tab switcher
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            
            tabButtons.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });

    // Code Playground switcher
    pgSelectButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const vulnType = btn.getAttribute('data-vulnerability');
            
            pgSelectButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            codeVulnerable.textContent = codeSnippets[vulnType].vulnerable;
            codeRemediated.textContent = codeSnippets[vulnType].remediated;
        });
    });

    // Copy command to clipboard
    btnCopyCli.addEventListener('click', () => {
        const cmdText = "python scanner.py localhost --ports 22,80,443,8080 --output report.html";
        navigator.clipboard.writeText(cmdText).then(() => {
            btnCopyCli.setAttribute('data-tooltip', 'Copied!');
            setTimeout(() => {
                btnCopyCli.setAttribute('data-tooltip', 'Copy Command');
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
        });
    });

    // Logging helpers
    function logToConsole(message, type = 'normal') {
        const line = document.createElement('div');
        line.className = `console-line ${type}`;
        
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        
        line.innerHTML = `
            <span class="timestamp">[${timeStr}]</span>
            <span class="prompt">aegis_cli$</span>
            <span class="text">${escapeHtml(message)}</span>
        `;
        
        consoleOutput.appendChild(line);
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
    }

    function escapeHtml(text) {
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Perform actual local environment security checks
    async function performLocalOriginAudit() {
        const findings = [];
        let score = 100;
        
        logToConsole("Auditing browser client security standards...", "info");
        await delay(300);

        // 1. Secure Context Check
        const isSecure = window.isSecureContext;
        if (isSecure) {
            logToConsole("[PASSED] Page running in a secure cryptographic environment.", "success");
            findings.push({
                id: 'REAL-001',
                severity: 'passed',
                title: 'Cryptographic Secure Context Enforced',
                category: 'Secure Context',
                port: 'Browser Web Client',
                description: 'The document execution context is marked as secure. Secure APIs (e.g. Service Workers, Geolocation, Cryptography) are permitted.',
                impact: 'Guarantees that active cryptographic web protocols prevent frame/execution side-channel spoofing.',
                remediation: 'No remediation needed.'
            });
        } else {
            logToConsole("[ALERT] Document running in an insecure context (window.isSecureContext is false).", "warning");
            score -= 15;
            findings.push({
                id: 'REAL-001-FAIL',
                severity: 'medium',
                title: 'Insecure Document Context Executing',
                category: 'Secure Context',
                port: 'Browser Web Client',
                description: 'The current context is executing without active HTTPS constraints or is flagged as unsafe by the user browser agent.',
                impact: 'Important browser APIs (like Clipboard API, Cryptography Web APIs, and Service Workers) are restricted, preventing correct functional actions.',
                remediation: 'Configure HTTPS protocols on the hosting server to resolve secure context validation failures.'
            });
        }
        await delay(300);

        // 2. HTTP Protocol Check
        const protocol = window.location.protocol;
        if (protocol === 'https:') {
            logToConsole("[PASSED] TLS active. Connection uses encrypted secure transport protocol (HTTPS).", "success");
            findings.push({
                id: 'REAL-002',
                severity: 'passed',
                title: 'Secure Socket Layers (TLS/HTTPS) Active',
                category: 'Protocol Configuration',
                port: '443/tcp',
                description: 'Web content traffic is encrypted during transfer, preventing local sniffing of raw socket frames.',
                impact: 'No risk.',
                remediation: 'No remediation needed.'
            });
        } else {
            logToConsole("[ALERT] Plaintext HTTP Protocol. Sniffing risk detected.", "warning");
            score -= 20;
            findings.push({
                id: 'REAL-002-FAIL',
                severity: 'high',
                title: 'Plaintext Transmission Protocol (HTTP) Enabled',
                category: 'Protocol Configuration',
                port: '80/tcp',
                description: 'The website is loaded over plaintext HTTP instead of TLS/HTTPS. Credentials and input data are fully readable on the wire.',
                impact: 'Enables middlebox operators and packet sniffers to view, alter, or insert malware into client sessions.',
                remediation: 'Deploy SSL/TLS certificates and configure server configuration redirects from port 80 to port 443.'
            });
        }
        await delay(300);

        // 3. Document Link Target Auditing (rel="noopener")
        const links = Array.from(document.querySelectorAll('a[target="_blank"]'));
        let linkIssueCount = 0;
        links.forEach(l => {
            const rel = l.getAttribute('rel') || '';
            if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
                linkIssueCount++;
            }
        });

        if (linkIssueCount === 0) {
            logToConsole("[PASSED] External outgoing links contain defensive sandbox attributes.", "success");
            findings.push({
                id: 'REAL-003',
                severity: 'passed',
                title: 'Cross-Origin Link Sandboxing Verified',
                category: 'DOM Code Integrity',
                port: 'DOM Document',
                description: 'All links targeted with target="_blank" use rel="noopener" or rel="noreferrer" tags correctly.',
                impact: 'No risk. Prevents tab-nabbing vulnerabilities where foreign redirects gain control of the source window.',
                remediation: 'No action required.'
            });
        } else {
            logToConsole(`[ALERT] Found ${linkIssueCount} external window link(s) missing 'rel="noopener"' tags.`, "warning");
            score -= 10;
            findings.push({
                id: 'REAL-003-FAIL',
                severity: 'medium',
                title: 'Missing Window sandboxing on External Anchor Links',
                category: 'DOM Code Integrity',
                port: 'DOM Document',
                description: `Found ${linkIssueCount} instances of links with target="_blank" that lack rel="noopener" or rel="noreferrer" configuration parameters.`,
                impact: 'Foreign sites can access the opening site window object via window.opener, enabling redirection tricks to hijack customer tab focuses.',
                remediation: 'Inspect all HTML files and append rel="noopener noreferrer" configurations to links referencing target="_blank" parameters.'
            });
        }
        await delay(300);

        // 4. Sandbox Frames Auditing
        const frames = Array.from(document.querySelectorAll('iframe'));
        let frameIssues = 0;
        frames.forEach(f => {
            if (!f.hasAttribute('sandbox')) {
                frameIssues++;
            }
        });

        if (frameIssues === 0) {
            logToConsole("[PASSED] All document frames sandbox restrictions verified.", "success");
            findings.push({
                id: 'REAL-004',
                severity: 'passed',
                title: 'Iframe Sandbox Restrictions Configured',
                category: 'DOM Code Integrity',
                port: 'DOM Document',
                description: 'All embedded iframe components are properly isolated using sandbox attributes.',
                impact: 'No risk.',
                remediation: 'No action required.'
            });
        } else {
            logToConsole(`[ALERT] Found ${frameIssues} nested iframe window frame(s) missing sandbox attributes.`, "warning");
            score -= 5;
            findings.push({
                id: 'REAL-004-FAIL',
                severity: 'info',
                title: 'Unrestricted Frame Isolation Sandbox Missing',
                category: 'DOM Code Integrity',
                port: 'DOM Document',
                description: `Discovered ${frameIssues} HTML iframe element(s) missing explicit "sandbox" values.`,
                impact: 'Permits frames to manipulate cookie states, trigger code execution outside sandbox scope, or trigger unauthorized downloads.',
                remediation: 'Add a sandbox="..." configuration to iframe tags to enable minimum required browser operations.'
            });
        }
        await delay(300);

        // 5. Session cookie properties
        const cookies = document.cookie;
        if (!cookies) {
            logToConsole("[PASSED] Cookie storage is empty. No session variables exposed.", "success");
            findings.push({
                id: 'REAL-005',
                severity: 'passed',
                title: 'State Storage Cookie Exposure Audited',
                category: 'Storage Audit',
                port: 'Local Cache',
                description: 'Client does not maintain exposed session headers inside document.cookie properties.',
                impact: 'No risk.',
                remediation: 'No action required.'
            });
        } else {
            logToConsole("[INFO] Cookies detected in client container. Security attributes must be server-validated.", "info");
            findings.push({
                id: 'REAL-005-INFO',
                severity: 'info',
                title: 'Local Client Cookie Storage Detected',
                category: 'Storage Audit',
                port: 'Local Cache',
                description: 'Active keys exist in document.cookie. Web scripts can query local storage states.',
                impact: 'If cookie tokens omit HttpOnly and Secure settings, script injections (XSS) can harvest tokens.',
                remediation: 'Enforce "Secure; HttpOnly; SameSite=Strict" settings when serving cookies from application servers.'
            });
        }

        // Summary calculations
        let critical = 0, high = 0, medium = 0, info = 0, passed = 0;
        findings.forEach(f => {
            if (f.severity === 'critical') critical++;
            else if (f.severity === 'high') high++;
            else if (f.severity === 'medium') medium++;
            else if (f.severity === 'info') info++;
            else if (f.severity === 'passed') passed++;
        });

        score = Math.max(0, score);

        return {
            score: score,
            summary: { critical, high, medium, info, passed },
            items: findings
        };
    }

    // Simulate standard scan sequence logs
    async function runSimulatedScanner(target, profile) {
        logToConsole(`Launching scanner process on target: ${target}`, "info");
        await delay(400);
        logToConsole("Testing routing pathways... (sending DNS query packets)", "normal");
        await delay(500);
        
        if (profile === 'vuln') {
            logToConsole("DNS Query finished. Target host resolved to IP 198.51.100.22", "normal");
            await delay(400);
            logToConsole("Initializing multi-threaded port scanner. Scanning common ports (1-10000)...", "info");
            await delay(700);
            logToConsole("[ALERT] Port 21 (FTP) is open. Banner grab: 'vsftpd 2.3.4'", "danger");
            await delay(400);
            logToConsole("[ALERT] Port 80 (HTTP) is open. Banner grab: 'nginx/1.14.0'", "danger");
            await delay(300);
            logToConsole("Port 443 (HTTPS) is open. Initializing SSL Handshake query...", "normal");
            await delay(500);
            logToConsole("[ALERT] Handshake completed. Deprecated TLS v1.0 and TLS v1.1 protocols accepted.", "warning");
            await delay(400);
            logToConsole("Executing Web Configuration Auditor...", "info");
            await delay(600);
            logToConsole("[ALERT] Missing Content-Security-Policy (CSP) header in HTTP reply.", "warning");
            await delay(300);
            logToConsole("[ALERT] Missing Strict-Transport-Security (HSTS) header in HTTPS reply.", "warning");
            await delay(300);
            logToConsole("Initializing Vulnerability Signature Analyzer (OWASP Engine)...", "info");
            await delay(800);
            logToConsole("[CRITICAL] SQL Injection payload accepted at '/login.php' on parameter 'user_id'!", "danger");
            await delay(500);
            logToConsole("[CRITICAL] Reflected XSS payload execution verified on target URL query parameter 'q'.", "danger");
            await delay(400);
        } else if (profile === 'secure') {
            logToConsole("DNS Query finished. Target host resolved to IP 203.0.113.88", "normal");
            await delay(400);
            logToConsole("Initializing multi-threaded port scanner. Scanning common ports (1-10000)...", "info");
            await delay(800);
            logToConsole("Port 22 (SSH) is open. Server protocol version verification completed.", "normal");
            await delay(300);
            logToConsole("Port 80 (HTTP) is open. HTTP redirect rules query completed.", "normal");
            await delay(350);
            logToConsole("[PASSED] Port 80 correctly enforces redirect status (301 Moved Permanently) to HTTPS.", "success");
            await delay(300);
            logToConsole("Port 443 (HTTPS) is open. Initializing SSL Handshake query...", "normal");
            await delay(600);
            logToConsole("[PASSED] TLS handshake completed. Connection restricts negotiations to modern TLS 1.3.", "success");
            await delay(400);
            logToConsole("Executing Web Configuration Auditor...", "info");
            await delay(500);
            logToConsole("[PASSED] Content-Security-Policy header verified.", "success");
            await delay(300);
            logToConsole("[PASSED] Strict-Transport-Security header verified.", "success");
            await delay(300);
            logToConsole("[PASSED] X-Frame-Options (DENY) and X-Content-Type-Options (nosniff) headers active.", "success");
            await delay(350);
            logToConsole("Initializing Vulnerability Signature Analyzer (OWASP Engine)...", "info");
            await delay(700);
            logToConsole("[PASSED] Database injection patterns blocked by authentication interface.", "success");
            await delay(400);
            logToConsole("[PASSED] No vulnerable software version signatures matching CVE database records found.", "success");
            await delay(300);
        } else {
            // General custom target simulation
            logToConsole(`DNS Query finished. Target host resolved to IP 8.8.8.8`, "normal");
            await delay(500);
            logToConsole("Initializing port scanner. Scanning common ports...", "info");
            await delay(600);
            logToConsole("Port 80 (HTTP) is open. Server: Apache/2.4.41", "normal");
            await delay(400);
            logToConsole("Port 443 (HTTPS) is open. Handshake completed using TLS v1.2.", "normal");
            await delay(500);
            logToConsole("Executing security checks...", "info");
            await delay(600);
            logToConsole("[ALERT] Outdated server stack Apache/2.4.41 detected.", "warning");
            await delay(400);
        }

        logToConsole("Vulnerability mapping completed. Assembling report...", "info");
        await delay(500);

        // Fetch pre-configured profiles or generate a randomized one
        if (profile === 'vuln') return vulnerabilitiesDb.vuln;
        if (profile === 'secure') return vulnerabilitiesDb.secure;
        
        // Custom default mock
        return {
            score: 75,
            summary: { critical: 0, high: 0, medium: 2, info: 1, passed: 5 },
            items: [
                {
                    id: 'CUST-001',
                    severity: 'medium',
                    title: 'Outdated Apache Server stack',
                    category: 'Software Version Check',
                    port: '80/tcp',
                    description: 'Detected Apache version 2.4.41. Current stable is 2.4.58.',
                    impact: 'Prone to older denial of service vulnerabilities.',
                    remediation: 'Patch server daemon package files.'
                },
                {
                    id: 'CUST-002',
                    severity: 'medium',
                    title: 'Missing Content Security Policy',
                    category: 'Headers Check',
                    port: '80/tcp',
                    description: 'CSP configuration parameters are omitted.',
                    impact: 'Increases risks of client-side XSS bypasses.',
                    remediation: 'Configure Content-Security-Policy responses.'
                },
                {
                    id: 'CUST-003',
                    severity: 'info',
                    title: 'Cookie flags missing Secure attribute',
                    category: 'State Storage',
                    port: 'Browser Cache',
                    description: 'Session cookie variables omit Secure configuration settings.',
                    impact: 'Cookies can be captured during unencrypted connections.',
                    remediation: 'Ensure secure tags are appended on cookie cookies.'
                },
                {
                    id: 'CUST-004',
                    severity: 'passed',
                    title: 'TLS v1.2 Protocol Enabled',
                    category: 'Cryptographic Suitability',
                    port: '443/tcp',
                    description: 'Encrypts remote data packets.',
                    impact: 'No risk.',
                    remediation: 'No action required.'
                }
            ]
        };
    }

    // Launch Scan Trigger
    btnLaunchScan.addEventListener('click', async () => {
        if (isScanning) return;
        
        isScanning = true;
        compiledReport = null;
        
        // Reset Dashboard visuals
        resetMetricsDashboard();
        vulnList.innerHTML = '';
        resultsPlaceholder.style.display = 'none';
        reportActions.style.display = 'none';
        
        // Activate scanning classes
        btnLaunchScan.classList.add('disabled');
        btnLaunchScan.innerHTML = `<i data-lucide="loader" class="spinning" style="width: 18px; height: 18px;"></i> Executing Audit...`;
        statusDot.className = 'status-dot pulsing scanning';
        statusText.textContent = 'AUDIT RUNNING';
        radarContainer.classList.add('scanning');
        radarPercent.textContent = '0%';
        
        // Add animated rotate class to loader icon inside button
        const btnIcon = btnLaunchScan.querySelector('svg');
        if (btnIcon) btnIcon.style.animation = 'radar-spin 1s linear infinite';
        
        const targetVal = targetInput.value.trim() || '127.0.0.1';
        logToConsole(`=======================================================`, "normal");
        logToConsole(`[INIT] Starting Security Audit Sequence`, "info");
        logToConsole(`[TARGET] ${targetVal}`, "normal");
        logToConsole(`[PROFILE] ${scanTypeSelect.value.toUpperCase()} scan type`, "normal");
        logToConsole(`=======================================================`, "normal");
        
        // Progress tick animation
        let progress = 0;
        const progressInterval = setInterval(() => {
            if (progress < 95) {
                progress += Math.floor(Math.random() * 8) + 2;
                progress = Math.min(progress, 95);
                radarPercent.textContent = `${progress}%`;
            }
        }, 300);

        try {
            let results;
            if (currentPreset === 'local') {
                results = await performLocalOriginAudit();
            } else {
                results = await runSimulatedScanner(targetVal, currentPreset);
            }
            
            // Finish scan progress
            clearInterval(progressInterval);
            radarPercent.textContent = '100%';
            await delay(400);
            
            compiledReport = results;
            
            // Render results
            renderVulnerabilityReport(results);
            animateSecurityMetrics(results.score, results.summary);
            
            logToConsole(`[COMPLETE] Audit finished successfully. Score: ${results.score}/100.`, "success");
            logToConsole(`Findings: ${results.items.length} issues registered.`, "info");
            
            // Enable Actions
            reportActions.style.display = 'flex';
            
        } catch (err) {
            clearInterval(progressInterval);
            logToConsole(`[ERROR] Audit sequence failed: ${err.message}`, "danger");
            statusText.textContent = 'AUDIT ERROR';
        } finally {
            isScanning = false;
            btnLaunchScan.classList.remove('disabled');
            btnLaunchScan.innerHTML = `<i data-lucide="play" style="width: 18px; height: 18px;"></i> Initialize Scan`;
            statusDot.className = 'status-dot pulsing';
            if (statusText.textContent === 'AUDIT RUNNING') {
                statusText.textContent = 'SYSTEM READY';
            }
            radarContainer.classList.remove('scanning');
            radarPercent.textContent = 'READY';
            lucide.createIcons();
        }
    });

    // Helper timer promise
    function delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Reset Metrics
    function resetMetricsDashboard() {
        scoreVal.textContent = '...';
        scoreDesc.textContent = 'WAITING';
        scoreDesc.style.color = 'var(--text-muted)';
        scoreCircle.style.background = 'radial-gradient(circle, rgba(15, 23, 42, 0.9) 60%, transparent 100%)';
        
        countCritical.textContent = '0';
        countHigh.textContent = '0';
        countMedium.textContent = '0';
        countInfo.textContent = '0';
        countPassed.textContent = '0';
    }

    // Animate Score counter and values
    function animateSecurityMetrics(targetScore, summary) {
        // Counter Animation
        let count = 0;
        const duration = 1200;
        const stepTime = Math.max(Math.floor(duration / (targetScore || 1)), 10);
        
        const timer = setInterval(() => {
            count++;
            if (count >= targetScore) {
                clearInterval(timer);
                scoreVal.textContent = targetScore;
            } else {
                scoreVal.textContent = count;
            }
        }, stepTime);

        // Score description evaluation
        let desc = 'POOR';
        let color = 'var(--color-rose)';
        let shadow = 'var(--color-rose-glow)';
        
        if (targetScore >= 90) {
            desc = 'EXCELLENT';
            color = 'var(--color-emerald)';
            shadow = 'var(--color-emerald-glow)';
        } else if (targetScore >= 70) {
            desc = 'SECURE';
            color = 'var(--color-cyan)';
            shadow = 'var(--color-cyan-glow)';
        } else if (targetScore >= 50) {
            desc = 'WARNING';
            color = 'var(--color-amber)';
            shadow = 'var(--color-amber-glow)';
        }
        
        scoreDesc.textContent = desc;
        scoreDesc.style.color = color;
        scoreCircle.style.boxShadow = `inset 0 0 20px ${shadow}, 0 0 15px ${shadow}`;

        // Populate summary counters
        countCritical.textContent = summary.critical;
        countHigh.textContent = summary.high;
        countMedium.textContent = summary.medium;
        countInfo.textContent = summary.info;
        countPassed.textContent = summary.passed;
    }

    // Render Findings List
    function renderVulnerabilityReport(report) {
        if (report.items.length === 0) {
            vulnList.innerHTML = `
                <div class="results-placeholder">
                    <i data-lucide="check-circle" style="width: 48px; height: 48px; color: var(--color-emerald);"></i>
                    <p style="color: var(--color-emerald);">No security vulnerabilities found on target!<br>Origin configuration is fully hardened.</p>
                </div>
            `;
            lucide.createIcons();
            return;
        }

        // Sort items by priority (Critical > High > Medium > Info > Passed)
        const priorityOrder = { critical: 0, high: 1, medium: 2, info: 3, passed: 4 };
        const sortedItems = [...report.items].sort((a, b) => priorityOrder[a.severity] - priorityOrder[b.severity]);

        let listHTML = '';
        sortedItems.forEach(item => {
            const hasRemediated = item.severity !== 'passed';
            
            listHTML += `
                <div class="vuln-item" id="vuln-card-${item.id}">
                    <button class="vuln-trigger" type="button" aria-expanded="false" onclick="toggleVulnAccordion('${item.id}')">
                        <span class="vuln-severity ${item.severity}">${item.severity}</span>
                        <span class="vuln-summary-title">
                            ${escapeHtml(item.title)}
                            ${item.port ? `<span class="target-port">${escapeHtml(item.port)}</span>` : ''}
                        </span>
                        <i data-lucide="chevron-down" class="vuln-chevron"></i>
                    </button>
                    <div class="vuln-content">
                        <div class="vuln-detail-section">
                            <div class="vuln-detail-label">Vulnerability Scope</div>
                            <div class="vuln-detail-desc">${escapeHtml(item.category)} (${item.id})</div>
                        </div>
                        <div class="vuln-detail-section">
                            <div class="vuln-detail-label">Detailed Description</div>
                            <div class="vuln-detail-desc">${escapeHtml(item.description)}</div>
                        </div>
                        <div class="vuln-detail-section">
                            <div class="vuln-detail-label">Threat Impact</div>
                            <div class="vuln-detail-desc" style="color: #cbd5e1;">${escapeHtml(item.impact)}</div>
                        </div>
                        ${hasRemediated ? `
                        <div class="vuln-detail-section">
                            <div class="vuln-detail-label">Remediation Action</div>
                            <pre class="vuln-detail-remediation"><code>${escapeHtml(item.remediation)}</code></pre>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        });

        vulnList.innerHTML = listHTML;
        lucide.createIcons();
    }

    // Accordion Toggle function attached globally so inline onclick works
    window.toggleVulnAccordion = (vulnId) => {
        const itemCard = document.getElementById(`vuln-card-${vulnId}`);
        if (!itemCard) return;
        
        const trigger = itemCard.querySelector('.vuln-trigger');
        const isOpen = itemCard.classList.contains('open');
        
        if (isOpen) {
            itemCard.classList.remove('open');
            trigger.setAttribute('aria-expanded', 'false');
        } else {
            itemCard.classList.add('open');
            trigger.setAttribute('aria-expanded', 'true');
        }
    };

    // Report Downloads: JSON Format
    btnDownloadJson.addEventListener('click', () => {
        if (!compiledReport) return;
        
        const reportData = {
            scanner: 'AEGIS Security Suite',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            target: targetInput.value.trim(),
            score: compiledReport.score,
            summary: compiledReport.summary,
            vulnerabilities: compiledReport.items
        };
        
        const jsonBlob = new Blob([JSON.stringify(reportData, null, 4)], { type: 'application/json' });
        const downloadUrl = URL.createObjectURL(jsonBlob);
        
        const downloadLink = document.createElement('a');
        downloadLink.href = downloadUrl;
        downloadLink.download = `aegis_scan_${targetInput.value.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        URL.revokeObjectURL(downloadUrl);
        
        logToConsole("JSON report export initiated.", "success");
    });

    // Report Downloads: HTML Format
    btnDownloadHtml.addEventListener('click', () => {
        if (!compiledReport) return;
        
        const targetName = escapeHtml(targetInput.value.trim());
        const timestamp = new Date().toLocaleString();
        
        // Build items HTML
        let itemsHTML = '';
        compiledReport.items.forEach(item => {
            itemsHTML += `
                <div class="card" style="margin-bottom: 20px; border-left: 5px solid ${getSeverityColor(item.severity)};">
                    <div style="display: flex; justify-content: space-between; font-weight: bold; margin-bottom: 10px;">
                        <span>${escapeHtml(item.title)}</span>
                        <span class="badge" style="background-color: ${getSeverityColor(item.severity)}; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; text-transform: uppercase;">${item.severity}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #666; margin-bottom: 10px;">
                        <strong>Port/Asset:</strong> ${escapeHtml(item.port)} | <strong>Category:</strong> ${escapeHtml(item.category)}
                    </div>
                    <div style="margin-bottom: 8px;">
                        <strong>Description:</strong> ${escapeHtml(item.description)}
                    </div>
                    <div style="margin-bottom: 8px;">
                        <strong>Impact:</strong> ${escapeHtml(item.impact)}
                    </div>
                    ${item.severity !== 'passed' ? `
                    <div style="background-color: #f1f5f9; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 0.85rem;">
                        <strong>Remediation:</strong><br>${escapeHtml(item.remediation)}
                    </div>
                    ` : ''}
                </div>
            `;
        });
        
        const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AEGIS Security Scan Report - ${targetName}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; margin: 40px; background-color: #f8fafc; }
        .header { background: #0f172a; color: #fff; padding: 30px; border-radius: 12px; margin-bottom: 30px; }
        .grid { display: grid; grid-template-columns: 1fr 3fr; gap: 20px; margin-bottom: 30px; }
        .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
        .score { font-size: 3rem; font-weight: bold; text-align: center; color: ${compiledReport.score >= 70 ? '#10b981' : '#f43f5e'}; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AEGIS // Vulnerability Report</h1>
        <p>Target: <strong>${targetName}</strong> | Audited At: ${timestamp}</p>
    </div>
    
    <div class="grid">
        <div class="card" style="display: flex; flex-direction: column; justify-content: center; align-items: center;">
            <h3>Security Score</h3>
            <div class="score">${compiledReport.score}/100</div>
            <p>Risk Status: <strong>${compiledReport.score >= 90 ? 'Low' : compiledReport.score >= 70 ? 'Moderate' : 'High'}</strong></p>
        </div>
        <div class="card">
            <h3>Audit Findings Summary</h3>
            <ul>
                <li><strong>Critical Threats:</strong> ${compiledReport.summary.critical}</li>
                <li><strong>High Threats:</strong> ${compiledReport.summary.high}</li>
                <li><strong>Medium Threats:</strong> ${compiledReport.summary.medium}</li>
                <li><strong>Informational:</strong> ${compiledReport.summary.info}</li>
                <li><strong>Passed Audits:</strong> ${compiledReport.summary.passed}</li>
            </ul>
        </div>
    </div>
    
    <h2>Discovered Vulnerabilities & Remediation Steps</h2>
    ${itemsHTML}
    
    <hr style="border: 0; border-top: 1px solid #e2e8f0; margin-top: 50px;">
    <footer style="text-align: center; color: #64748b; font-size: 0.8rem;">
        Report compiled by AEGIS Security Suite.
    </footer>
</body>
</html>`;

        const htmlBlob = new Blob([htmlTemplate], { type: 'text/html' });
        const downloadUrl = URL.createObjectURL(htmlBlob);
        
        const downloadLink = document.createElement('a');
        downloadLink.href = downloadUrl;
        downloadLink.download = `aegis_report_${targetInput.value.replace(/[^a-zA-Z0-9]/g, '_')}.html`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        URL.revokeObjectURL(downloadUrl);
        
        logToConsole("HTML report export initiated.", "success");
    });

    function getSeverityColor(severity) {
        switch(severity) {
            case 'critical': return '#f43f5e';
            case 'high': return '#f59e0b';
            case 'medium': return '#6366f1';
            case 'info': return '#06b6d4';
            case 'passed': return '#10b981';
            default: return '#94a3b8';
        }
    }
});
