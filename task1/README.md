# 🛡️ Fortress | Password Security Suite

**Fortress** is a modern, premium, client-side cybersecurity suite designed to evaluate password strength, generate cryptographically secure credentials, and educate users on safe password storage practices (preventing reuse through simulated hash database matching).

Built using vanilla web technologies and the **Web Crypto API**, Fortress runs entirely in the browser. None of your credentials or inputs are sent to a server—guaranteeing complete privacy.

---

## ✨ Features

### 1. 🔍 Real-Time Password Strength Analyzer
*   **Shannon Entropy Calculation:** Computes the mathematical complexity of your password in bits ($E = L \times \log_2(R)$).
*   **Structural Checklist:** Evaluates passwords against standard complexity rules (length, casing, digits, special characters).
*   **Pattern & Keyboard Path Detection:** Rejects easily guessable sequential patterns (e.g., `1234`, `abcd`), repeating characters (`aaa`), and keyboard paths (e.g., `qwer`, `asdf`).
*   **Common Leaks Check:** Rejects passwords included in the top 100 most common/compromised password lists.
*   **Hardware Crack Time Estimator:** Predicts brute-force attack times across different hardware tiers (Consumer Desktop PC, Custom GPU Rig, and Supercomputer/Botnet).
*   **SHA-256 Hashing Visualizer:** Demonstrates the cryptographic avalanche effect by showing the SHA-256 signature update in real time.

### 2. ⚡ Smart Password Generator
*   **Cryptographically Secure Randomness:** Leverages the browser's `window.crypto.getRandomValues` (CSRNG) rather than predictable pseudo-random utilities.
*   **Granular Customization:** Configure length (8 to 64 characters) and switch toggles for uppercase, lowercase, numbers, and symbols.
*   **Ambiguous Character Filtering:** Option to avoid confusing characters (e.g., `O`, `0`, `l`, `1`, `I`) to ensure maximum readability.
*   **One-Click Analyzer Redirect:** Easily send generated passwords directly to the Analyzer for a structural checkup.

### 3. 🔒 Security Vault & Reuse Simulator
*   **Simulated Hash Database:** Visualizes how modern systems store credentials securely by saving one-way SHA-256 hashes instead of plaintext passwords.
*   **Reuse Prevention Engine:** Triggers a high-priority warning if you attempt to register a password hash that already exists in the database under another account.
*   **Educative Sandbox:** Teaches the risk of credential stuffing attacks and how password reuse exposes all accounts once a single service is breached.

---

## 🛠️ Technology Stack

Fortress is engineered to load instantly and run efficiently with zero build tools or dependencies:

*   **HTML5:** Structured using semantic HTML for accessibility, SEO, and layout.
*   **Vanilla CSS3:** Styled using custom properties, modern glassmorphism (backdrop filters), smooth layout transitions, responsive design systems, and dedicated **Dark & Light Mode** themes.
*   **Vanilla JavaScript:** Logic, tab controller, state, and cryptographic processes using standard ES6+ APIs.
*   **Web Crypto API:** Executes performant client-side SHA-256 hashing and cryptographically secure random number generation.
*   **Typography:** Google Fonts (**Outfit** for interface elements, **JetBrains Mono** for cryptographic hashes and entropy counters).

---

## 🚀 Getting Started

Since Fortress is serverless and dependency-free, you can run it instantly:

1. Clone or download the repository to your local system.
2. Double-click the [index.html](file:///d:/Cybersecurity%20intern%20project/task1/index.html) file to open it in any modern web browser (Chrome, Firefox, Safari, Edge).
3. Alternatively, serve it locally with simple utilities:
    *   **Python:** `python -m http.server 8000` (then navigate to `http://localhost:8000`)
    *   **Node.js (Live Server):** `npx live-server`

---

## 🧠 Security Details Explained

### Shannon Entropy ($E$)
Password complexity is measured using Shannon Entropy, which represents the number of bits required to guess the password space:
$$E = L \times \log_2(R)$$
Where:
*   $L$ is the length of the password.
*   $R$ is the size of the character pool (alphabet size) based on character types present:
    *   Lowercase only: $R = 26$
    *   Uppercase + Lowercase: $R = 52$
    *   Alphanumeric: $R = 62$
    *   Alphanumeric + Special Symbols: $R = 94$

#### Strength Verdict Thresholds
| Entropy (Bits) | Strength Verdict | Security Level |
| :--- | :--- | :--- |
| **< 28 bits** | Very Weak | Vulnerable to instant dictionary/brute-force attacks. |
| **28 – 39 bits** | Weak | Vulnerable to simple custom brute-force engines. |
| **40 – 59 bits** | Medium | Fair resistance; could be broken by a dedicated GPU rig. |
| **60 – 79 bits** | Strong | Highly secure; suitable for standard personal vaults. |
| **≥ 80 bits** | Excellent | Fortress level complexity; mathematically unfeasible to brute-force. |

### Cryptographic Hashing (SHA-256)
When you submit credentials in the Security Vault simulator, the suite runs the password through a SHA-256 one-way hashing function:
$$\text{Plaintext Password} \xrightarrow{\text{SHA-256}} \text{64-character Hexadecimal Hash}$$
Because SHA-256 is a **one-way function**, the database only stores the output hash. A hacker who breaches the database cannot reverse the hash back to the original password, showing the importance of cryptographic hash storage in industry.

---

## 🔒 Privacy & Safety Disclaimer
> [!IMPORTANT]
> **100% Client-Side:** Fortress runs entirely in your web browser. No analytics trackers, no backend storage, and no internet API calls are executed. All inputs, vaults, and generated passwords remain resident in your browser's local memory (`localStorage` is utilized only for persisting the simulator vault locally on your device).
