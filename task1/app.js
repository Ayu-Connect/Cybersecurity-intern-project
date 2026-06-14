document.addEventListener('DOMContentLoaded', () => {
  // --- STATE VARIABLES ---
  let currentVault = [];

  // --- COMMON PASSWORDS LIST (Top 100) ---
  const COMMON_PASSWORDS = [
    '123456', 'password', '123456789', '12345678', '12345', 'qwerty', '1234567', 'password123',
    '111111', '123123', '1234567890', 'admin', 'letmein', 'welcome', 'sunshine', 'football',
    'dragons', 'monkey', 'secret', 'charlie', 'password1', '12345678901', 'donald', 'mustang',
    'password!', 'superman', 'qwertyuiop', 'joshua', 'shadow', 'princess', 'solo', 'starwars',
    'killer', 'chester', 'hunter', 'cameron', 'master', 'freedom', 'michael', 'jessica',
    'bailey', 'harley', 'andrew', 'thomas', 'nathan', 'ashley', 'daniel', 'soccer',
    'baseball', 'bubble', 'boston', 'dallas', 'denver', 'chelsea', 'cheese', 'cookie',
    'snickers', 'adidas', 'nike', 'jordan', 'batman', 'marvel', 'pokemon', 'super',
    'hacker', 'security', 'database', 'system', 'root', 'login', 'server', 'network',
    'microsoft', 'google', 'apple', 'facebook', 'youtube', 'netflix', 'amazon', 'github',
    'matrix', 'avatar', 'titan', 'dragon', 'wizard', 'phoenix', 'hunter2', 'iloveyou',
    '123456a', 'qwerty123', 'admin123', 'password1234', '1234qwer', 'qwer1234', 'asdfghjkl'
  ];

  // --- KEYBOARD SEQUENCES FOR PATTERN DETECTION ---
  const KEYBOARD_ROWS = [
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
    '1234567890'
  ];

  // --- DOM ELEMENTS ---
  // Header / Navigation
  const tabAnalyzer = document.getElementById('tab-analyzer');
  const tabGenerator = document.getElementById('tab-generator');
  const tabVault = document.getElementById('tab-vault');
  const panelAnalyzer = document.getElementById('panel-analyzer');
  const panelGenerator = document.getElementById('panel-generator');
  const panelVault = document.getElementById('panel-vault');
  const themeToggle = document.getElementById('theme-toggle');

  // Analyzer Panel
  const passwordInput = document.getElementById('password-input');
  const togglePwVisibility = document.getElementById('toggle-pw-visibility');
  const strengthValue = document.getElementById('strength-value');
  const entropyValue = document.getElementById('entropy-value');
  const strengthProgress = document.getElementById('strength-progress');
  const strengthVerdictDesc = document.getElementById('strength-verdict-desc');
  const hashOutput = document.getElementById('hash-output');
  const crackDesktop = document.getElementById('crack-desktop');
  const crackGpu = document.getElementById('crack-gpu');
  const crackSuper = document.getElementById('crack-super');
  const checklistItems = document.querySelectorAll('#rules-checklist li');

  // Generator Panel
  const generatedPasswordBox = document.getElementById('generated-password-box');
  const regenerateBtn = document.getElementById('regenerate-btn');
  const copyBtn = document.getElementById('copy-btn');
  const lengthSlider = document.getElementById('length-slider');
  const lengthValDisplay = document.getElementById('length-val-display');
  const genUppercase = document.getElementById('gen-uppercase');
  const genLowercase = document.getElementById('gen-lowercase');
  const genNumbers = document.getElementById('gen-numbers');
  const genSymbols = document.getElementById('gen-symbols');
  const genReadable = document.getElementById('gen-readable');
  const sendToAnalyzerBtn = document.getElementById('send-to-analyzer-btn');

  // Vault Panel
  const vaultRegisterForm = document.getElementById('vault-register-form');
  const vaultUsername = document.getElementById('vault-username');
  const vaultService = document.getElementById('vault-service');
  const customServiceGroup = document.getElementById('custom-service-group');
  const vaultCustomService = document.getElementById('vault-custom-service');
  const vaultPassword = document.getElementById('vault-password');
  const toggleVaultPwVisibility = document.getElementById('toggle-vault-pw-visibility');
  const vaultHashPreview = document.getElementById('vault-hash-preview');
  const reuseWarningAlert = document.getElementById('reuse-warning-alert');
  const vaultDbBody = document.getElementById('vault-db-body');
  const vaultEmptyState = document.getElementById('vault-empty-state');
  const clearDbBtn = document.getElementById('clear-db-btn');

  // Notification Toast Container
  const toastContainer = document.getElementById('toast-container');

  // --- CRYPTOGRAPHY: SHA-256 HASH FUNCTION ---
  async function calculateSHA256(message) {
    if (!message) return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // hash of empty string
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // --- TOAST ALERTS ---
  function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    
    // Check/Success Icon SVG
    const iconSvg = `
      <svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
    `;
    
    toast.innerHTML = `
      ${iconSvg}
      <span class="toast-message">${message}</span>
    `;
    
    toastContainer.appendChild(toast);
    
    // Smooth remove
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(1rem)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => {
        toast.remove();
      }, 300);
    }, 2500);
  }

  // --- TAB CONTROLLER ---
  function initTabs() {
    const tabs = [
      { btn: tabAnalyzer, panel: panelAnalyzer },
      { btn: tabGenerator, panel: panelGenerator },
      { btn: tabVault, panel: panelVault }
    ];

    tabs.forEach(tab => {
      tab.btn.addEventListener('click', () => {
        tabs.forEach(t => {
          t.btn.classList.remove('active');
          t.btn.setAttribute('aria-selected', 'false');
          t.panel.style.display = 'none';
        });
        
        tab.btn.classList.add('active');
        tab.btn.setAttribute('aria-selected', 'true');
        tab.panel.style.display = tab.panel.id === 'panel-analyzer' ? 'grid' : 'block';
        
        // Refresh items on tab switch if needed
        if (tab.panel.id === 'panel-generator') {
          triggerGeneration();
        }
      });
    });
  }

  // --- THEME MANAGEMENT ---
  function initTheme() {
    const savedTheme = localStorage.getItem('fortress_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcons(savedTheme);

    themeToggle.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('fortress_theme', newTheme);
      updateThemeIcons(newTheme);
      showToast(`Switched to ${newTheme} mode!`, 'info');
    });
  }

  function updateThemeIcons(theme) {
    const sunIcon = themeToggle.querySelector('.sun-icon');
    const moonIcon = themeToggle.querySelector('.moon-icon');
    if (theme === 'dark') {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    } else {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    }
  }

  // --- ANALYZER COMPONENT ---
  function checkChecklist(password) {
    const results = {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      symbol: /[^A-Za-z0-9]/.test(password),
      pattern: true,
      common: !COMMON_PASSWORDS.includes(password.toLowerCase())
    };

    // Sequential & Repeating Pattern Detection
    // 1. Repeated characters (e.g. aaa, 111)
    if (/(.)\1\1/.test(password)) {
      results.pattern = false;
    }
    
    // 2. Keyboard rows and sequential steps
    const lowerPw = password.toLowerCase();
    
    // Sequences check (e.g. 1234, abcd)
    for (let i = 0; i < password.length - 3; i++) {
      const charCode1 = password.charCodeAt(i);
      const charCode2 = password.charCodeAt(i + 1);
      const charCode3 = password.charCodeAt(i + 2);
      const charCode4 = password.charCodeAt(i + 3);
      
      // Ascending sequence
      if (charCode2 === charCode1 + 1 && charCode3 === charCode2 + 1 && charCode4 === charCode3 + 1) {
        results.pattern = false;
        break;
      }
      // Descending sequence
      if (charCode2 === charCode1 - 1 && charCode3 === charCode2 - 1 && charCode4 === charCode3 - 1) {
        results.pattern = false;
        break;
      }
    }

    // Keyboard paths (e.g. qwer, asdf)
    if (results.pattern) {
      for (const row of KEYBOARD_ROWS) {
        for (let i = 0; i < row.length - 3; i++) {
          const chunk = row.substring(i, i + 4);
          const revChunk = chunk.split('').reverse().join('');
          if (lowerPw.includes(chunk) || lowerPw.includes(revChunk)) {
            results.pattern = false;
            break;
          }
        }
        if (!results.pattern) break;
      }
    }

    // Update Checklist DOM
    checklistItems.forEach(item => {
      const rule = item.getAttribute('data-rule');
      const passed = results[rule];
      if (password.length === 0) {
        item.classList.remove('passed', 'failed');
      } else if (passed) {
        item.classList.remove('failed');
        item.classList.add('passed');
      } else {
        item.classList.remove('passed');
        item.classList.add('failed');
      }
    });

    return results;
  }

  function calculateEntropy(password, rules) {
    if (!password) return 0;
    
    let R = 0;
    if (rules.lowercase) R += 26;
    if (rules.uppercase) R += 26;
    if (rules.number) R += 10;
    if (rules.symbol) R += 32; // Standard special characters count
    
    // If characters entered don't fall into basic buckets (e.g. space or foreign characters)
    if (R === 0) {
      R = 10; 
    }

    // Shannon Entropy formula: E = L * log2(R)
    return password.length * (Math.log(R) / Math.log(2));
  }

  function getVerdict(entropy, rules, password) {
    if (!password) {
      return {
        label: 'Empty',
        class: 'strength-text-empty',
        color: 'var(--strength-empty)',
        pct: 0,
        desc: 'Type something to begin calculating password strength and security score.'
      };
    }

    // Common passwords are forced to weak
    if (!rules.common) {
      return {
        label: 'Very Compromised',
        class: 'strength-text-very-weak',
        color: 'var(--strength-very-weak)',
        pct: 15,
        desc: 'Warning: This password is on the list of most common leaked passwords. Hackers will crack it in milliseconds!'
      };
    }

    // Check caps based on size/complexity
    if (entropy < 28) {
      return {
        label: 'Very Weak',
        class: 'strength-text-very-weak',
        color: 'var(--strength-very-weak)',
        pct: 20,
        desc: 'Critical risk. This password is too short or simple. It is vulnerable to basic dictionaries and instant brute force.'
      };
    } else if (entropy < 40) {
      return {
        label: 'Weak',
        class: 'strength-text-weak',
        color: 'var(--strength-weak)',
        pct: 40,
        desc: 'Weak protection. Try adding uppercase letters, special symbols, numbers, or increasing its overall length.'
      };
    } else if (entropy < 60) {
      return {
        label: 'Medium',
        class: 'strength-text-medium',
        color: 'var(--strength-medium)',
        pct: 60,
        desc: 'Decent protection. Fairly resistant to simple attacks, but could easily be breached by a dedicated GPU rig.'
      };
    } else if (entropy < 80) {
      return {
        label: 'Strong',
        class: 'strength-text-strong',
        color: 'var(--strength-strong)',
        pct: 80,
        desc: 'High security. Very difficult to crack. Good for personal accounts, emails, and general security vaults.'
      };
    } else {
      return {
        label: 'Excellent',
        class: 'strength-text-excellent',
        color: 'var(--strength-excellent)',
        pct: 100,
        desc: 'Fortress status! This password has exceptional mathematical complexity. Safe for online banks and high-value servers.'
      };
    }
  }

  function formatTime(seconds) {
    if (seconds === Infinity) return 'Infinity';
    if (seconds < 1) return 'Instantly';
    if (seconds < 60) return `${Math.round(seconds)} second${Math.round(seconds) > 1 ? 's' : ''}`;
    
    const minutes = seconds / 60;
    if (minutes < 60) return `${Math.round(minutes)} minute${Math.round(minutes) > 1 ? 's' : ''}`;
    
    const hours = minutes / 60;
    if (hours < 24) return `${Math.round(hours)} hour${Math.round(hours) > 1 ? 's' : ''}`;
    
    const days = hours / 24;
    if (days < 365) return `${Math.round(days)} day${Math.round(days) > 1 ? 's' : ''}`;
    
    const years = days / 365;
    if (years < 1000) return `${Math.round(years)} year${Math.round(years) > 1 ? 's' : ''}`;
    
    const thousandYears = years / 1000;
    if (thousandYears < 1000) return `${Math.round(thousandYears)} thousand years`;
    
    const millionYears = thousandYears / 1000;
    if (millionYears < 1000) return `${Math.round(millionYears)} million years`;
    
    const billionYears = millionYears / 1000;
    if (billionYears < 1000) return `${Math.round(billionYears)} billion years`;
    
    const trillionYears = billionYears / 1000;
    return `${Math.round(trillionYears)} trillion years`;
  }

  function estimateCrackTimes(entropy, password) {
    if (!password) {
      crackDesktop.textContent = 'Instantly';
      crackGpu.textContent = 'Instantly';
      crackSuper.textContent = 'Instantly';
      return;
    }

    // Guesses spaces = 2^entropy
    const totalGuesses = Math.pow(2, entropy);

    // Compute attempts per second
    const desktopSpeed = 1e10; // 10 billion guesses/sec
    const gpuSpeed = 1e13;     // 10 trillion guesses/sec
    const superSpeed = 1e17;   // 100 quadrillion guesses/sec

    // Worst-case scenario: brute force takes on average half the key-space
    const avgGuesses = totalGuesses / 2;

    crackDesktop.textContent = formatTime(avgGuesses / desktopSpeed);
    crackGpu.textContent = formatTime(avgGuesses / gpuSpeed);
    crackSuper.textContent = formatTime(avgGuesses / superSpeed);
  }

  async function handlePasswordAnalysis() {
    const password = passwordInput.value;
    
    // 1. Perform structural evaluation
    const rules = checkChecklist(password);
    
    // 2. Compute numeric Shannon Entropy
    const entropy = calculateEntropy(password, rules);
    entropyValue.textContent = `${entropy.toFixed(2)} bits`;

    // 3. Update Strength bar and texts
    const verdict = getVerdict(entropy, rules, password);
    strengthValue.textContent = verdict.label;
    strengthValue.className = verdict.class;
    strengthProgress.style.width = `${verdict.pct}%`;
    strengthProgress.style.backgroundColor = verdict.color;
    strengthVerdictDesc.textContent = verdict.desc;

    // 4. Calculate cracking attempts
    estimateCrackTimes(entropy, password);

    // 5. Update cryptographic hash
    const hash = await calculateSHA256(password);
    hashOutput.textContent = hash;
  }

  // --- PASSWORD GENERATOR COMPONENT ---
  function triggerGeneration() {
    const length = parseInt(lengthSlider.value);
    const useUpper = genUppercase.checked;
    const useLower = genLowercase.checked;
    const useNumbers = genNumbers.checked;
    const useSymbols = genSymbols.checked;
    const avoidAmbiguous = genReadable.checked;

    const upperPool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowerPool = 'abcdefghijklmnopqrstuvwxyz';
    const numberPool = '0123456789';
    const symbolPool = '!@#$%^&*()_+{}|:"<>?-=[]\\;\',./';

    let characterPool = '';
    const guaranteedChars = [];

    // Filter pools if "Easy to Read" is toggled
    const filterAmbiguous = (str) => {
      if (!avoidAmbiguous) return str;
      // Remove ambiguous letters: I, l, 1, O, 0, o, etc.
      return str.replace(/[Il1O0o]/g, '');
    };

    if (useUpper) {
      const p = filterAmbiguous(upperPool);
      characterPool += p;
      if (p.length > 0) guaranteedChars.push(getRandomChar(p));
    }
    if (useLower) {
      const p = filterAmbiguous(lowerPool);
      characterPool += p;
      if (p.length > 0) guaranteedChars.push(getRandomChar(p));
    }
    if (useNumbers) {
      const p = filterAmbiguous(numberPool);
      characterPool += p;
      if (p.length > 0) guaranteedChars.push(getRandomChar(p));
    }
    if (useSymbols) {
      const p = filterAmbiguous(symbolPool);
      characterPool += p;
      if (p.length > 0) guaranteedChars.push(getRandomChar(p));
    }

    // Fallback if no checkboxes selected
    if (characterPool.length === 0) {
      const p = filterAmbiguous(lowerPool);
      characterPool = p;
      guaranteedChars.push(getRandomChar(p));
    }

    let generatedPassword = '';
    const neededLength = length - guaranteedChars.length;

    // Cryptographically secure pseudorandom numbers
    const randomArray = new Uint32Array(neededLength);
    window.crypto.getRandomValues(randomArray);

    for (let i = 0; i < neededLength; i++) {
      const randomIndex = randomArray[i] % characterPool.length;
      generatedPassword += characterPool[randomIndex];
    }

    // Blend standard characters with guaranteed ones
    let mergedArray = (generatedPassword + guaranteedChars.join('')).split('');
    mergedArray = shuffleArray(mergedArray);

    generatedPasswordBox.textContent = mergedArray.join('');
  }

  function getRandomChar(pool) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return pool[array[0] % pool.length];
  }

  function shuffleArray(array) {
    // Fisher-Yates Shuffle using crypto values
    const randomVals = new Uint32Array(array.length);
    window.crypto.getRandomValues(randomVals);
    
    for (let i = array.length - 1; i > 0; i--) {
      const j = randomVals[i] % (i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
  }

  // --- VAULT & DATABASE SIMULATOR ---
  function loadVault() {
    const stored = localStorage.getItem('fortress_mock_vault');
    if (stored) {
      try {
        currentVault = JSON.parse(stored);
      } catch (e) {
        currentVault = [];
      }
    } else {
      // Seed with some mock data for better educational presentation
      currentVault = [
        { id: '1', service: 'GitHub', username: 'dev_alex', passwordHash: '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918' }, // 'admin123'
        { id: '2', service: 'Online Banking', username: 'alex_cash', passwordHash: 'b913d12aee1e1cf6b3f7f45778b660c6d5952d76f0d7e63e2646c2db57f72288' } // 'ComplexBanking99!!'
      ];
      saveVaultToStorage();
    }
    renderVaultTable();
  }

  function saveVaultToStorage() {
    localStorage.setItem('fortress_mock_vault', JSON.stringify(currentVault));
  }

  function renderVaultTable() {
    vaultDbBody.innerHTML = '';
    if (currentVault.length === 0) {
      vaultEmptyState.style.display = 'flex';
    } else {
      vaultEmptyState.style.display = 'none';
      currentVault.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHtml(item.service)}</strong></td>
          <td>${escapeHtml(item.username)}</td>
          <td><code class="mono-font word-break select-all" style="font-size: 0.78rem;">${item.passwordHash}</code></td>
        `;
        vaultDbBody.appendChild(tr);
      });
    }
  }

  async function handleVaultPasswordInput() {
    const password = vaultPassword.value;
    const hash = await calculateSHA256(password);
    vaultHashPreview.textContent = hash;

    // Real-time check: does this hash already exist in the database?
    const isDuplicate = currentVault.some(item => item.passwordHash === hash);
    if (password.length > 0 && isDuplicate) {
      reuseWarningAlert.style.display = 'flex';
      vaultSubmitBtn.classList.remove('btn-primary');
      vaultSubmitBtn.classList.add('btn-danger');
      vaultSubmitBtn.textContent = 'Force Register Compromised Reuse';
    } else {
      reuseWarningAlert.style.display = 'none';
      vaultSubmitBtn.classList.add('btn-primary');
      vaultSubmitBtn.classList.remove('btn-danger');
      vaultSubmitBtn.textContent = 'Register Credentials Securely';
    }
  }

  async function handleVaultSubmit(e) {
    e.preventDefault();
    const service = vaultService.value === 'Custom Service' ? vaultCustomService.value.trim() : vaultService.value;
    const username = vaultUsername.value.trim();
    const password = vaultPassword.value;

    if (!service || !username || !password) {
      alert('Please fill out all fields.');
      return;
    }

    const hash = await calculateSHA256(password);
    const isDuplicate = currentVault.some(item => item.passwordHash === hash);

    const newItem = {
      id: Date.now().toString(),
      service: service,
      username: username,
      passwordHash: hash
    };

    currentVault.push(newItem);
    saveVaultToStorage();
    renderVaultTable();

    // Reset Form
    vaultPassword.value = '';
    vaultUsername.value = '';
    vaultCustomService.value = '';
    customServiceGroup.style.display = 'none';
    vaultService.selectedIndex = 0;
    
    // Clear warning state
    reuseWarningAlert.style.display = 'none';
    vaultSubmitBtn.className = 'btn btn-primary btn-block';
    vaultSubmitBtn.textContent = 'Register Credentials Securely';
    vaultHashPreview.textContent = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    if (isDuplicate) {
      showToast('Compromised credential registered (Reuse detected!).', 'warning');
    } else {
      showToast('Credential successfully registered with secure hashing!', 'success');
    }
  }

  function escapeHtml(string) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return string.replace(/[&<>"']/g, function(m) { return map[m]; });
  }

  // --- EVENT LISTENERS BINDING ---

  // Theme Toggler & Navigation initialized
  initTheme();
  initTabs();

  // Analyzer Listeners
  passwordInput.addEventListener('input', handlePasswordAnalysis);
  
  togglePwVisibility.addEventListener('click', () => {
    const isPw = passwordInput.getAttribute('type') === 'password';
    passwordInput.setAttribute('type', isPw ? 'text' : 'password');
    
    const eyeOpen = togglePwVisibility.querySelector('.eye-open-icon');
    const eyeClosed = togglePwVisibility.querySelector('.eye-closed-icon');
    
    if (isPw) {
      eyeOpen.style.display = 'none';
      eyeClosed.style.display = 'block';
    } else {
      eyeOpen.style.display = 'block';
      eyeClosed.style.display = 'none';
    }
  });

  // Generator Listeners
  lengthSlider.addEventListener('input', () => {
    lengthValDisplay.textContent = lengthSlider.value;
    triggerGeneration();
  });

  [genUppercase, genLowercase, genNumbers, genSymbols, genReadable].forEach(toggle => {
    toggle.addEventListener('change', triggerGeneration);
  });

  regenerateBtn.addEventListener('click', () => {
    triggerGeneration();
    showToast('New password generated!', 'info');
  });

  copyBtn.addEventListener('click', () => {
    const textToCopy = generatedPasswordBox.textContent;
    if (textToCopy && textToCopy !== 'Select options below...') {
      navigator.clipboard.writeText(textToCopy)
        .then(() => {
          showToast('Copied to clipboard!');
        })
        .catch(err => {
          console.error('Failed to copy text: ', err);
        });
    }
  });

  sendToAnalyzerBtn.addEventListener('click', () => {
    const textToSend = generatedPasswordBox.textContent;
    if (textToSend && textToSend !== 'Select options below...') {
      passwordInput.value = textToSend;
      
      // If input type is hidden, reveal it so user sees what was sent
      passwordInput.setAttribute('type', 'text');
      togglePwVisibility.querySelector('.eye-open-icon').style.display = 'none';
      togglePwVisibility.querySelector('.eye-closed-icon').style.display = 'block';

      // Switch to analyzer tab
      tabAnalyzer.click();
      
      // Trigger analysis
      handlePasswordAnalysis();
      
      showToast('Sent generated password to Analyzer!');
    }
  });

  // Vault/Reuse Listeners
  loadVault();
  
  vaultPassword.addEventListener('input', handleVaultPasswordInput);
  
  vaultService.addEventListener('change', () => {
    if (vaultService.value === 'Custom Service') {
      customServiceGroup.style.display = 'block';
      vaultCustomService.focus();
    } else {
      customServiceGroup.style.display = 'none';
    }
  });

  toggleVaultPwVisibility.addEventListener('click', () => {
    const isPw = vaultPassword.getAttribute('type') === 'password';
    vaultPassword.setAttribute('type', isPw ? 'text' : 'password');
    
    const eyeOpen = toggleVaultPwVisibility.querySelector('.eye-open-icon');
    const eyeClosed = toggleVaultPwVisibility.querySelector('.eye-closed-icon');
    
    if (isPw) {
      eyeOpen.style.display = 'none';
      eyeClosed.style.display = 'block';
    } else {
      eyeOpen.style.display = 'block';
      eyeClosed.style.display = 'none';
    }
  });

  vaultRegisterForm.addEventListener('submit', handleVaultSubmit);

  clearDbBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to reset your vault? This will clear all stored credentials.')) {
      currentVault = [];
      saveVaultToStorage();
      renderVaultTable();
      showToast('Security vault reset!', 'info');
    }
  });

  // Run analyzer check on load to clear/set initial state
  handlePasswordAnalysis();
});
