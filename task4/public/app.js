// --- APPLICATION STATE ---
const state = {
  user: null,
  loggedIn: false
};

// --- DOM ELEMENTS ---
const sections = {
  login: document.getElementById('login-section'),
  register: document.getElementById('register-section'),
  prompt2FA: document.getElementById('2fa-prompt-section'),
  dashboard: document.getElementById('dashboard-section'),
  setup2FA: document.getElementById('2fa-setup-section'),
  disable2FA: document.getElementById('2fa-disable-section')
};

// Forms
const forms = {
  login: document.getElementById('login-form'),
  register: document.getElementById('register-form'),
  prompt2FA: document.getElementById('2fa-prompt-form'),
  setup2FA: document.getElementById('2fa-setup-form'),
  disable2FA: document.getElementById('2fa-disable-form')
};

// Toast Container
const toastContainer = document.getElementById('toast-container');

// Navigation links
const links = {
  goToRegister: document.getElementById('go-to-register'),
  goToLogin: document.getElementById('go-to-login'),
  cancel2FAPrompt: document.getElementById('cancel-2fa-prompt')
};

// Dashboard Elements
const dbElements = {
  welcome: document.getElementById('dashboard-welcome'),
  email: document.getElementById('dashboard-email'),
  avatar: document.getElementById('dashboard-avatar'),
  statusTag: document.getElementById('2fa-status-tag'),
  statusBox: document.getElementById('two-factor-status-box'),
  toggle2FABtn: document.getElementById('toggle-2fa-btn'),
  protectionText: document.getElementById('protection-level-text'),
  logoutBtn: document.getElementById('logout-btn')
};

// 2FA Setup Elements
const setupElements = {
  qrImage: document.getElementById('2fa-qr-image'),
  secretText: document.getElementById('2fa-secret-text'),
  copyBtn: document.getElementById('copy-secret-btn'),
  cancelBtn: document.getElementById('cancel-2fa-setup-btn')
};

// 2FA Disable Elements
const disableElements = {
  cancelBtn: document.getElementById('cancel-2fa-disable-btn')
};

// --- ROUTER (SPA VIEWS SWITCHING) ---
function showSection(targetSection) {
  // Hide all sections and remove fade-in classes
  Object.values(sections).forEach(section => {
    section.classList.add('hidden');
    section.classList.remove('fade-in');
  });
  
  // Show target section with entrance animation
  targetSection.classList.remove('hidden');
  targetSection.classList.add('fade-in');
}

// --- TOAST NOTIFICATIONS ---
function showToast(title, message, type = 'info', duration = 4000) {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'error') icon = '❌';
  if (type === 'warning') icon = '⚠️';
  
  toast.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <div class="toast-content">
      <div class="toast-title">${title}</div>
      <div class="toast-desc">${message}</div>
    </div>
  `;
  
  toastContainer.appendChild(toast);
  
  // Auto remove toast
  const timer = setTimeout(() => {
    removeToast(toast);
  }, duration);
  
  toast.addEventListener('click', () => {
    clearTimeout(timer);
    removeToast(toast);
  });
}

function removeToast(toast) {
  toast.classList.add('removing');
  toast.addEventListener('animationend', () => {
    toast.remove();
  });
}

// --- CLIENT-SIDE INPUT VALIDATION ---
function setFieldError(fieldId, errorMsg) {
  const inputEl = document.getElementById(fieldId);
  const errEl = document.getElementById(`${fieldId}-err`);
  
  if (errorMsg) {
    inputEl.classList.add('invalid');
    errEl.textContent = errorMsg;
    errEl.classList.add('visible');
  } else {
    inputEl.classList.remove('invalid');
    errEl.textContent = '';
    errEl.classList.remove('visible');
  }
}

function clearFormErrors(form) {
  const inputs = form.querySelectorAll('input');
  inputs.forEach(input => {
    input.classList.remove('invalid');
    const errEl = document.getElementById(`${input.id}-err`);
    if (errEl) {
      errEl.textContent = '';
      errEl.classList.remove('visible');
    }
  });
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function getPasswordStrength(password) {
  let score = 0;
  if (!password) return score;
  
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score++;
  
  return score; // max 4
}

// Live feedback for password strength
const registerPasswordInput = document.getElementById('register-password');
const strengthBars = document.querySelectorAll('.strength-bar');

registerPasswordInput.addEventListener('input', () => {
  const password = registerPasswordInput.value;
  const score = getPasswordStrength(password);
  
  // Reset active classes
  strengthBars.forEach(bar => {
    bar.className = 'strength-bar';
  });
  
  if (score === 0) return;
  
  if (score <= 2) {
    strengthBars[0].classList.add('active-weak');
  } else if (score === 3) {
    strengthBars[0].classList.add('active-medium');
    strengthBars[1].classList.add('active-medium');
  } else if (score >= 4) {
    strengthBars[0].classList.add('active-strong');
    strengthBars[1].classList.add('active-strong');
    strengthBars[2].classList.add('active-strong');
  }
});

// --- HELPER FOR LOADING SPINNERS ---
function setSubmitting(form, isSubmitting) {
  const submitBtn = form.querySelector('button[type="submit"]');
  const textEl = submitBtn.querySelector('span');
  const spinnerEl = submitBtn.querySelector('.spinner');
  
  if (isSubmitting) {
    submitBtn.disabled = true;
    textEl.classList.add('hidden');
    spinnerEl.classList.remove('hidden');
  } else {
    submitBtn.disabled = false;
    textEl.classList.remove('hidden');
    spinnerEl.classList.add('hidden');
  }
}

// --- AUTHENTICATION FLOWS ---

// 1. Initial Session Verification
async function checkSession() {
  try {
    const res = await fetch('/api/session');
    const data = await res.json();
    
    if (res.ok && data.loggedIn) {
      state.user = data.user;
      state.loggedIn = true;
      renderDashboard();
      showSection(sections.dashboard);
    } else {
      state.user = null;
      state.loggedIn = false;
      showSection(sections.login);
    }
  } catch (err) {
    console.error('Session validation failed:', err);
    showSection(sections.login);
  }
}

// 2. Registration Handler
forms.register.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearFormErrors(forms.register);
  
  const username = document.getElementById('register-username').value.trim();
  const email = document.getElementById('register-email').value.trim();
  const password = registerPasswordInput.value;
  const confirmPassword = document.getElementById('register-confirm-password').value;
  
  let valid = true;
  
  // Username check
  if (!username) {
    setFieldError('register-username', 'Username is required.');
    valid = false;
  } else if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    setFieldError('register-username', '3-20 characters, letters, numbers, and underscores only.');
    valid = false;
  }
  
  // Email check
  if (!email) {
    setFieldError('register-email', 'Email is required.');
    valid = false;
  } else if (!validateEmail(email)) {
    setFieldError('register-email', 'Please enter a valid email address.');
    valid = false;
  }
  
  // Password check
  if (!password) {
    setFieldError('register-password', 'Password is required.');
    valid = false;
  } else if (getPasswordStrength(password) < 4) {
    setFieldError('register-password', 'Password must be at least 8 characters, and contain uppercase, lowercase, numbers, and symbols.');
    valid = false;
  }
  
  // Confirm password
  if (password !== confirmPassword) {
    setFieldError('register-confirm-password', 'Passwords do not match.');
    valid = false;
  }
  
  if (!valid) return;
  
  setSubmitting(forms.register, true);
  
  try {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, confirmPassword })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      showToast('Registration Successful', data.message, 'success');
      forms.register.reset();
      // Reset strength bars
      strengthBars.forEach(bar => bar.className = 'strength-bar');
      showSection(sections.login);
    } else {
      showToast('Registration Failed', data.error || 'Check fields and try again.', 'error');
      if (data.error && data.error.includes('Username or Email')) {
        setFieldError('register-email', 'This email or username is already taken.');
        setFieldError('register-username', 'This email or username is already taken.');
      }
    }
  } catch (err) {
    showToast('Network Error', 'Could not reach server. Please try again.', 'error');
  } finally {
    setSubmitting(forms.register, false);
  }
});

// 3. Login Handler
forms.login.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearFormErrors(forms.login);
  
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  
  let valid = true;
  if (!email || !validateEmail(email)) {
    setFieldError('login-email', 'Please enter a valid email address.');
    valid = false;
  }
  if (!password) {
    setFieldError('login-password', 'Password is required.');
    valid = false;
  }
  
  if (!valid) return;
  
  setSubmitting(forms.login, true);
  
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      if (data.twoFactorRequired) {
        showToast('Verification Required', '2FA is active on this account. Please enter your code.', 'info');
        showSection(sections.prompt2FA);
      } else {
        state.user = data.user;
        state.loggedIn = true;
        renderDashboard();
        showToast('Welcome Back!', `Logged in successfully as ${data.user.username}`, 'success');
        showSection(sections.dashboard);
        forms.login.reset();
      }
    } else {
      showToast('Login Failed', data.error || 'Invalid credentials.', 'error');
      setFieldError('login-email', ' ');
      setFieldError('login-password', data.error || 'Invalid email or password.');
    }
  } catch (err) {
    showToast('Network Error', 'Could not reach server. Please try again.', 'error');
  } finally {
    setSubmitting(forms.login, false);
  }
});

// 4. 2FA Code Prompt Verification Handler (Logging In)
forms.prompt2FA.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearFormErrors(forms.prompt2FA);
  
  const code = document.getElementById('2fa-prompt-code').value.trim();
  
  if (!code || code.length !== 6 || isNaN(code)) {
    setFieldError('2fa-prompt-code', 'Please enter a valid 6-digit code.');
    return;
  }
  
  setSubmitting(forms.prompt2FA, true);
  
  try {
    const res = await fetch('/api/verify-2fa-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      state.user = data.user;
      state.loggedIn = true;
      renderDashboard();
      showToast('Login Confirmed', `Welcome back, ${data.user.username}!`, 'success');
      showSection(sections.dashboard);
      forms.prompt2FA.reset();
      forms.login.reset();
    } else {
      showToast('Authentication Failed', data.error || 'Invalid 2FA code.', 'error');
      setFieldError('2fa-prompt-code', 'Incorrect verification code.');
    }
  } catch (err) {
    showToast('Network Error', 'Could not verify code. Please try again.', 'error');
  } finally {
    setSubmitting(forms.prompt2FA, false);
  }
});

// 5. Dashboard Setup & Details Rendering
function renderDashboard() {
  if (!state.user) return;
  
  dbElements.welcome.textContent = `Welcome, ${state.user.username}!`;
  dbElements.email.textContent = state.user.email;
  dbElements.avatar.textContent = state.user.username.charAt(0).toUpperCase();
  
  if (state.user.twoFactorEnabled) {
    dbElements.statusTag.textContent = 'Active';
    dbElements.statusTag.className = 'status-label tag tag-success';
    dbElements.toggle2FABtn.textContent = 'Disable 2FA';
    dbElements.toggle2FABtn.className = 'btn btn-danger btn-small';
    dbElements.protectionText.innerHTML = '<span style="color:var(--success)">High (Password + TOTP 2FA)</span>';
  } else {
    dbElements.statusTag.textContent = 'Disabled';
    dbElements.statusTag.className = 'status-label tag tag-disabled';
    dbElements.toggle2FABtn.textContent = 'Enable 2FA';
    dbElements.toggle2FABtn.className = 'btn btn-primary btn-small';
    dbElements.protectionText.textContent = 'Standard (Password Only)';
  }
}

// 6. Logout Action
dbElements.logoutBtn.addEventListener('click', async () => {
  try {
    const res = await fetch('/api/logout', { method: 'POST' });
    if (res.ok) {
      state.user = null;
      state.loggedIn = false;
      showToast('Logged Out', 'You have been safely signed out.', 'info');
      showSection(sections.login);
    } else {
      showToast('Logout Failed', 'Could not clear server session.', 'error');
    }
  } catch (err) {
    showToast('Network Error', 'Could not reach server to sign out.', 'error');
  }
});

// 7. Toggle 2FA Action (Open Enable/Disable workflows)
dbElements.toggle2FABtn.addEventListener('click', () => {
  if (state.user.twoFactorEnabled) {
    // Open disable confirmation card
    clearFormErrors(forms.disable2FA);
    forms.disable2FA.reset();
    showSection(sections.disable2FA);
  } else {
    // Start 2FA setup flow
    start2FASetup();
  }
});

// 8. 2FA Enablement Setup Flow
async function start2FASetup() {
  try {
    const res = await fetch('/api/2fa/setup', { method: 'POST' });
    const data = await res.json();
    
    if (res.ok) {
      setupElements.qrImage.src = data.qrCodeUrl;
      setupElements.secretText.textContent = data.secretText;
      
      // Clear code field
      clearFormErrors(forms.setup2FA);
      forms.setup2FA.reset();
      
      showSection(sections.setup2FA);
    } else {
      showToast('2FA Setup Failed', data.error || 'Could not generate setup token.', 'error');
    }
  } catch (err) {
    showToast('Network Error', 'Could not reach server to configure 2FA.', 'error');
  }
}

// Secret key Copy Action
setupElements.copyBtn.addEventListener('click', () => {
  const secret = setupElements.secretText.textContent;
  navigator.clipboard.writeText(secret).then(() => {
    const originalText = setupElements.copyBtn.textContent;
    setupElements.copyBtn.textContent = 'Copied!';
    setupElements.copyBtn.disabled = true;
    setTimeout(() => {
      setupElements.copyBtn.textContent = originalText;
      setupElements.copyBtn.disabled = false;
    }, 2000);
  }).catch(err => {
    showToast('Copy Failed', 'Please highlight and copy manually.', 'warning');
  });
});

// Setup Form Submission
forms.setup2FA.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearFormErrors(forms.setup2FA);
  
  const code = document.getElementById('2fa-setup-code').value.trim();
  
  if (!code || code.length !== 6 || isNaN(code)) {
    setFieldError('2fa-setup-code', 'Please enter a 6-digit confirmation code.');
    return;
  }
  
  setSubmitting(forms.setup2FA, true);
  
  try {
    const res = await fetch('/api/2fa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      state.user.twoFactorEnabled = true;
      renderDashboard();
      showToast('2FA Enabled', data.message, 'success');
      showSection(sections.dashboard);
    } else {
      showToast('Activation Failed', data.error || 'Invalid confirmation code.', 'error');
      setFieldError('2fa-setup-code', 'Incorrect code. Check your app and try again.');
    }
  } catch (err) {
    showToast('Network Error', 'Could not complete 2FA activation.', 'error');
  } finally {
    setSubmitting(forms.setup2FA, false);
  }
});

// 9. 2FA Disable Form Submission
forms.disable2FA.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearFormErrors(forms.disable2FA);
  
  const password = document.getElementById('disable-2fa-password').value;
  
  if (!password) {
    setFieldError('disable-2fa-password', 'Password is required to disable 2FA.');
    return;
  }
  
  setSubmitting(forms.disable2FA, true);
  
  try {
    const res = await fetch('/api/2fa/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      state.user.twoFactorEnabled = false;
      renderDashboard();
      showToast('2FA Disabled', data.message, 'info');
      showSection(sections.dashboard);
    } else {
      showToast('Disable Failed', data.error || 'Authentication error.', 'error');
      setFieldError('disable-2fa-password', data.error || 'Incorrect password.');
    }
  } catch (err) {
    showToast('Network Error', 'Could not contact server to deactivate 2FA.', 'error');
  } finally {
    setSubmitting(forms.disable2FA, false);
  }
});

// --- NAVIGATION BINDINGS (SPA CLICKS) ---
links.goToRegister.addEventListener('click', (e) => {
  e.preventDefault();
  clearFormErrors(forms.register);
  forms.register.reset();
  // Reset strength bars
  strengthBars.forEach(bar => bar.className = 'strength-bar');
  showSection(sections.register);
});

links.goToLogin.addEventListener('click', (e) => {
  e.preventDefault();
  clearFormErrors(forms.login);
  forms.login.reset();
  showSection(sections.login);
});

links.cancel2FAPrompt.addEventListener('click', (e) => {
  e.preventDefault();
  // Call logout to clear the session temp states on server too, if any
  fetch('/api/logout', { method: 'POST' }).finally(() => {
    showSection(sections.login);
  });
});

setupElements.cancelBtn.addEventListener('click', () => {
  showSection(sections.dashboard);
});

disableElements.cancelBtn.addEventListener('click', () => {
  showSection(sections.dashboard);
});

// --- INITIALIZE APPLICATION ---
document.addEventListener('DOMContentLoaded', () => {
  checkSession();
});
