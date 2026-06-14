# Secure Auth: Advanced Multi-Factor Login System

A secure, responsive Single Page Application (SPA) login system featuring robust session management, database persistence, and Two-Factor Authentication (2FA) with a companion CLI automation helper. Built on **Node.js (Express)**, **SQLite**, and **Speakeasy/QRCode**, this project is designed following industry-standard cybersecurity best practices.

---

## 🌟 Visuals & Interface
The user interface is designed with a premium, high-fidelity aesthetic:
* **Glassmorphism Design**: High-contrast, transparent cards overlaying dark fluid backgrounds.
* **Ambient Glow System**: Dynamic background lights that shift smoothly to focus user attention.
* **Micro-Animations**: Smooth entry transitions, active loading states with spinners, and slide-in toast notifications.
* **Typography & Layout**: Modern, clean text scaling using the **Outfit** Google Font.

---

## 🔒 Security Architectures & Vulnerability Mitigation

This application was engineered with a security-first mindset to eliminate common web vulnerabilities:

### 1. SQL Injection (SQLi) Mitigation
* **Method**: All SQL statements within [database.js](file:///d:/Cybersecurity%20intern%20project/task4/database.js) and [server.js](file:///d:/Cybersecurity%20intern%20project/task4/server.js) use **parameterized queries** (placeholders `?` with execution arguments passed separately). 
* **Impact**: Completely isolates user input from statement parsing, rendering SQL Injection impossible.

### 2. User Enumeration / Email Harvesting Prevention
* **Method**: The authentication endpoint `/api/login` uses generic validation logic. In the event of a validation failure, it responds with a unified `"Invalid email or password."` message regardless of whether the email exists in the database.
* **Impact**: Malicious actors cannot brute-force register check to harvest valid user emails.

### 3. Password Security & Hashing
* **Method**: Uses `bcryptjs` to hash all passwords.
* **Cost Factor / Salt Rounds**: `12` rounds, balancing server security with response latency.
* **Complexity Validation**: Enforces standard password requirements:
  * Minimum 8 characters.
  * At least 1 uppercase letter (`A-Z`).
  * At least 1 lowercase letter (`a-z`).
  * At least 1 numerical digit (`0-9`).
  * At least 1 special character (e.g. `!@#$%^&*()`).
* **Visual Aid**: Includes a client-side password strength bar mapping weak, medium, and strong criteria live.

### 4. Cross-Site Scripting (XSS) & Clickjacking Protections
* **Method**: Custom security headers middleware:
  * `X-Frame-Options: DENY`: Blocks framing to prevent Clickjacking attacks.
  * `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing vulnerabilities.
  * `Referrer-Policy: strict-origin-when-cross-origin`: Controls referrer data transmission.
  * `httpOnly` Cookies: Session identifier cookies are configured with `httpOnly: true`, preventing client-side JavaScript access (`document.cookie`) and eliminating Cookie theft via XSS.

### 5. Session Management & CSRF Protection
* **Method**: Driven by `express-session`.
* **State Controls**:
  * `sameSite: 'lax'`: Restricts session identifiers to local navigation context, reducing CSRF attack surfaces.
  * `secure: false`: (Configured for local development. Set to `true` when SSL certificates are active in staging/production).
  * `maxAge`: Session lifetime is capped strictly at `1 hour`.
  * Temporary 2FA Authentication state: Users matching passwords but holding 2FA requirements are kept in a temporary verification stage (`req.session.tempUserId`) to prevent unauthenticated dashboard access.

---

## 🛠️ Project Structure
```
task4/
├── database.js          # SQLite connector with helper Promise wrappers
├── database.sqlite      # Persistent database storage
├── package.json         # Project manifests and scripts
├── server.js            # Express API server, routes, and middlewares
├── watch-2fa.js         # Automated 2FA local testing helper
└── public/              # SPA Frontend static files
    ├── app.js           # Client SPA state, AJAX logic, and validators
    ├── index.html       # HTML skeleton structure
    └── style.css        # Premium CSS design tokens & animations
```

---

## 🛢️ Database Schema
The SQLite schema consists of a `users` table:
```sql
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  two_factor_secret TEXT,
  two_factor_enabled INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## ⚡ Setup & Run Instructions

### 1. Prerequisites
Ensure you have **Node.js** (v14 or higher) installed.

### 2. Installation
Install the required dependencies inside the `task4` directory:
```bash
npm install
```

### 3. Running the Server
Start the development server:
```bash
npm run dev
```
The application will boot and run on: **[http://localhost:3000](http://localhost:3000)**.

---

## 🤖 Automated 2FA Testing Helper (`watch-2fa.js`)

To facilitate rapid verification and testing of 2FA functionality without needing a physical phone or manual OTP entry, a background directory watcher script is included.

### How it works
1. When configuring 2FA or displaying a secret key, write/copy the base32 secret code text (e.g. `KVKVEK2FKVKVEK2F`) to a file named `temp-secret.txt` in the root of the project.
2. The watcher detects this new file, decodes it, and calculates the active 6-digit TOTP code.
3. The watcher writes this generated 6-digit code to `temp-totp.txt`.
4. You can read the code from `temp-totp.txt` or copy it from the CLI output logs directly!

### Running the Watcher
To run the helper in a separate terminal:
```bash
node watch-2fa.js
```

### Sample Automated Testing Workflow
1. Start the server and the watcher in separate terminal windows.
2. Open the browser and go to `http://localhost:3000`. Register and log in.
3. Click **Enable 2FA**.
4. Copy the displayed base32 secret string (e.g. from the instruction box).
5. Paste this secret text into a new file named `temp-secret.txt` in the root workspace directory.
6. The watcher console will log:
   `[Watcher] Secret detected: KVKVE... -> Generated TOTP: 123456`
   and write `123456` into `temp-totp.txt`.
7. Retrieve the code and paste it into the confirmation input form to complete setup!
