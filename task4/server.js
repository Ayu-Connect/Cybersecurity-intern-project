const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { initDb, dbRun, dbGet } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Configure Express Session
app.use(session({
  secret: 'secure-login-system-secret-key-987654321', // Fallback secure secret key
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Protect from XSS access to session ID
    secure: false, // Set to true if deploying over HTTPS (we're running locally)
    sameSite: 'lax', // CSRF protection
    maxAge: 60 * 60 * 1000 // 1 hour session lifetime
  }
}));

// Basic Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Middleware to enforce authentication
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
}

// Input validation helpers
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validateUsername(username) {
  // Username: alphanumeric plus underscores, length 3-20
  const re = /^[a-zA-Z0-9_]{3,20}$/;
  return re.test(username);
}

function validatePassword(password) {
  // Password criteria: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
  if (password.length < 8) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false;
  return true;
}

// --- API ROUTES ---

// 1. User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    // Sanity Checks
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }

    if (!validateUsername(username)) {
      return res.status(400).json({ error: 'Username must be 3-20 characters long and contain only alphanumeric characters or underscores.' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long, and include an uppercase letter, a lowercase letter, a number, and a special character.' });
    }

    // Check if username or email already exists (using parameterized query)
    const existingUser = await dbGet(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username.trim(), email.trim().toLowerCase()]
    );

    if (existingUser) {
      return res.status(400).json({ error: 'Username or Email is already registered.' });
    }

    // Hash the password with bcrypt (salt rounds = 12)
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert user into DB (parameterized query)
    await dbRun(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username.trim(), email.trim().toLowerCase(), passwordHash]
    );

    res.status(201).json({ message: 'Registration successful! You can now log in.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
  }
});

// 2. User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Retrieve user by email (parameterized query)
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    if (!user) {
      // Use generic error message to prevent email harvesting
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Verify hashed password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Check if Two-Factor Authentication is enabled
    if (user.two_factor_enabled === 1) {
      // Create a temporary state in session; don't fully authenticate yet
      req.session.tempUserId = user.id;
      return res.json({ twoFactorRequired: true });
    }

    // Fully log in the user
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.email = user.email;

    res.json({
      success: true,
      user: {
        username: user.username,
        email: user.email,
        twoFactorEnabled: false
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
  }
});

// 3. Verify 2FA Login Code
app.post('/api/verify-2fa-login', async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: '2FA verification code is required.' });
    }

    if (!req.session.tempUserId) {
      return res.status(400).json({ error: 'Session expired or invalid. Please log in again.' });
    }

    // Retrieve user details
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [req.session.tempUserId]);
    if (!user || user.two_factor_enabled !== 1) {
      return res.status(400).json({ error: 'Invalid operation.' });
    }

    // Verify code
    const verified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token: code.trim()
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid 2FA verification code.' });
    }

    // Complete login procedure
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.email = user.email;
    delete req.session.tempUserId;

    res.json({
      success: true,
      user: {
        username: user.username,
        email: user.email,
        twoFactorEnabled: true
      }
    });
  } catch (error) {
    console.error('2FA Verification error:', error);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
  }
});

// 4. Session Check (Check auth status)
app.get('/api/session', async (req, res) => {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ loggedIn: false });
    }

    // Fetch latest info from DB (e.g. if 2FA status changed)
    const user = await dbGet('SELECT username, email, two_factor_enabled FROM users WHERE id = ?', [req.session.userId]);
    if (!user) {
      // Invalidate session if user doesn't exist anymore
      req.session.destroy();
      return res.status(401).json({ loggedIn: false });
    }

    res.json({
      loggedIn: true,
      user: {
        username: user.username,
        email: user.email,
        twoFactorEnabled: user.two_factor_enabled === 1
      }
    });
  } catch (error) {
    console.error('Session check error:', error);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
  }
});

// 5. Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Failed to destroy session.' });
    }
    res.clearCookie('connect.sid'); // Clear session cookie
    res.json({ success: true, message: 'Logged out successfully.' });
  });
});

// 6. Setup 2FA - Generate QR Code & secret (authenticated)
app.post('/api/2fa/setup', requireAuth, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({
      name: `SecureLoginApp (${req.session.email})`
    });

    // Save temporary secret in session (not in DB yet, until confirmed)
    req.session.temp2FASecret = secret.base32;

    // Generate QR code data URI
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      qrCodeUrl,
      secretText: secret.base32
    });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Could not set up 2FA.' });
  }
});

// 7. Verify 2FA Setup - Confirm & activate (authenticated)
app.post('/api/2fa/verify', requireAuth, async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Verification code is required.' });
    }

    if (!req.session.temp2FASecret) {
      return res.status(400).json({ error: '2FA setup was not initialized. Please request a new setup.' });
    }

    // Verify token
    const verified = speakeasy.totp.verify({
      secret: req.session.temp2FASecret,
      encoding: 'base32',
      token: code.trim()
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code. Please try again.' });
    }

    // Commit secret to Database and enable 2FA
    await dbRun(
      'UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?',
      [req.session.temp2FASecret, req.session.userId]
    );

    // Clean up temporary secret
    delete req.session.temp2FASecret;

    res.json({ success: true, message: 'Two-Factor Authentication activated successfully!' });
  } catch (error) {
    console.error('2FA activation error:', error);
    res.status(500).json({ error: 'Failed to activate 2FA.' });
  }
});

// 8. Disable 2FA (authenticated + requires password validation)
app.post('/api/2fa/disable', requireAuth, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required to disable 2FA.' });
    }

    // Verify identity by fetching complete user details
    const user = await dbGet('SELECT password_hash FROM users WHERE id = ?', [req.session.userId]);
    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }

    const matches = await bcrypt.compare(password, user.password_hash);
    if (!matches) {
      return res.status(400).json({ error: 'Incorrect password. Cannot disable Two-Factor Authentication.' });
    }

    // Update DB to turn off 2FA
    await dbRun(
      'UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0 WHERE id = ?',
      [req.session.userId]
    );

    res.json({ success: true, message: 'Two-Factor Authentication disabled successfully.' });
  } catch (error) {
    console.error('Disable 2FA error:', error);
    res.status(500).json({ error: 'Failed to disable 2FA.' });
  }
});

// Serve frontend for all unhandled routes (fallback to SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start application after initializing database
async function startServer() {
  try {
    await initDb();
    app.listen(PORT, () => {
      console.log(`Server running securely on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to initialize database and start server:', error);
  }
}

startServer();
