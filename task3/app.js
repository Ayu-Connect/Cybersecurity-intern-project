// API base URL - resolved dynamically to support local development ports (e.g. Live Server) and relative paths in production
const API_URL = window.location.port && window.location.port !== '5000'
    ? `${window.location.protocol}//${window.location.hostname}:5000`
    : '';

// Global state variables
let modelMetrics = null;
let currentWeightsTab = 'phishing';
const customSubmissions = [];

// Urgency keywords for UI highlighting (matches Python list)
const URGENT_WORDS = [
    "urgent", "immediate", "suspend", "verify", "security", "action", 
    "restricted", "login", "expire", "billing", "declined", "refund", 
    "lottery", "win", "payment", "prize", "alert", "attention"
];

// Presets templates database
const TEMPLATES = {
    phish_paypal: {
        sender: "security-alert@paypal-update.net",
        subject: "URGENT: Your account has been temporarily restricted",
        body: "Dear Customer,\n\nWe detected a suspicious login attempt on your account from an unrecognized device in Russia. Please click the link below to verify your identity immediately:\nhttp://paypal-update.net/login?token=9827364\n\nFailure to confirm your profile within 24 hours will result in permanent account suspension.\n\nBest regards,\nPayPal Security Team"
    },
    phish_netflix: {
        sender: "billing@netflix-verify.com",
        subject: "Unlock your subscription - Payment declined",
        body: "Dear Valued Member,\n\nWe were unable to process your latest payment. Please verify your payment details by visiting our secure portal:\nhttp://bit.ly/nf-billing-update\n\nIf you do not resolve this in time, your account will be closed and you will lose access to all Netflix features.\n\nThank you,\nNetflix Billing Division"
    },
    phish_delivery: {
        sender: "no-reply@amazn-delivery-support.com",
        subject: "Important notice regarding your shipment update",
        body: "Your package could not be delivered due to incomplete or incorrect address details. Please update your delivery preferences and pay a re-routing fee of $1.50 at:\nhttp://192.168.4.88/postal-alert\n\nOtherwise, your item will be returned to the sender. Act quickly."
    },
    safe_meeting: {
        sender: "notifications@github.com",
        subject: "Your weekly code review summary",
        body: "Hi developer,\n\nI've reviewed your pull request and left a few comments on the database migration logic. Most of it looks great, just check the indexing on the email column.\n\nYou can see the full review directly on GitHub at https://github.com/acme/repo/pull/42.\n\nThanks,\nCode Reviewer"
    },
    safe_news: {
        sender: "newsletter@techbytes.dev",
        subject: "Acme Corp Newsletter - June 2026",
        body: "Hi team,\n\nThanks for signing up for our weekly tech newsletter. In this issue, we explore the latest updates in Python 3.13, Scikit-learn pipelines, and best practices in frontend design.\n\nRead the full post on our blog at https://techbytes.dev/blog/pipeline-guide.\n\nTalk soon!"
    }
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    fetchStats();
});

// Fetch Model Statistics from API
async function fetchStats() {
    updateConnectionStatus(true, "Connecting...");
    try {
        const response = await fetch(`${API_URL}/api/stats`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        if (data.status === "success") {
            modelMetrics = data.metrics;
            renderDashboard();
            updateConnectionStatus(true, "Connected to API");
        } else {
            throw new Error(data.message || "Failed to load metrics");
        }
    } catch (error) {
        console.error("Error fetching stats:", error);
        updateConnectionStatus(false, "Connection Failed");
    }
}

// Update Connection Badge
function updateConnectionStatus(isOnline, text) {
    const badge = document.getElementById("conn-badge");
    const indicator = badge.querySelector(".indicator-dot");
    const label = document.getElementById("conn-text");
    
    if (isOnline) {
        badge.classList.remove("offline");
        indicator.classList.remove("offline");
        indicator.classList.add("online");
    } else {
        badge.classList.add("offline");
        indicator.classList.remove("online");
        indicator.classList.add("offline");
    }
    label.textContent = text;
}

// Switch Sidebar Tabs
function switchTab(viewId) {
    // Update active nav button
    document.querySelectorAll(".nav-item").forEach(btn => {
        btn.classList.remove("active");
    });
    document.getElementById(`btn-${viewId}`).classList.add("active");
    
    // Update active view content
    document.querySelectorAll(".content-view").forEach(view => {
        view.classList.remove("active");
    });
    document.getElementById(`view-${viewId}`).classList.add("active");
    
    // Update Header Text
    const titleEl = document.getElementById("view-title");
    const subEl = document.getElementById("view-subtitle");
    
    if (viewId === 'dashboard') {
        titleEl.textContent = "Model Performance Dashboard";
        subEl.textContent = "Monitor real-time training metrics, feature weights, and classifications.";
        // Refresh stats if visiting dashboard
        fetchStats();
    } else if (viewId === 'scanner') {
        titleEl.textContent = "Email Security Scanner";
        subEl.textContent = "Analyze specific emails using the custom-trained machine learning pipeline.";
    } else if (viewId === 'retrain') {
        titleEl.textContent = "Model Retraining Portal";
        subEl.textContent = "Expand the training set with user submissions and retrain the classifier.";
    }
}

// Render Dashboard Data
function renderDashboard() {
    if (!modelMetrics) return;
    
    // KPI Cards
    const accPercent = (modelMetrics.accuracy * 100).toFixed(1);
    const f1Percent = (modelMetrics.f1_score * 100).toFixed(1);
    
    document.getElementById("kpi-accuracy").textContent = `${accPercent}%`;
    document.getElementById("kpi-accuracy-fill").style.width = `${accPercent}%`;
    
    document.getElementById("kpi-f1").textContent = `${f1Percent}%`;
    document.getElementById("kpi-f1-fill").style.width = `${f1Percent}%`;
    
    document.getElementById("kpi-total-emails").textContent = modelMetrics.dataset_size;
    document.getElementById("kpi-safe-count").textContent = `${modelMetrics.safe_count} Safe`;
    document.getElementById("kpi-phishing-count").textContent = `${modelMetrics.phishing_count} Phish`;
    
    // Confusion Matrix Cells
    const cm = modelMetrics.confusion_matrix;
    const totalTest = cm.tn + cm.fp + cm.fn + cm.tp;
    
    const formatCell = (elementId, countId, pctId, value) => {
        document.getElementById(countId).textContent = value;
        const pct = ((value / totalTest) * 100).toFixed(1);
        document.getElementById(pctId).textContent = `${pct}%`;
    };
    
    formatCell("cell-tn", "val-tn", "pct-tn", cm.tn);
    formatCell("cell-fp", "val-fp", "pct-fp", cm.fp);
    formatCell("cell-fn", "val-fn", "pct-fn", cm.fn);
    formatCell("cell-tp", "val-tp", "pct-tp", cm.tp);
    
    // Feature Weights
    renderFeatureWeights();
}

// Toggle Weights View (Phishing vs Safe)
function toggleWeights(tab) {
    currentWeightsTab = tab;
    document.getElementById("toggle-phishing-weights").classList.toggle("active", tab === 'phishing');
    document.getElementById("toggle-safe-weights").classList.toggle("active", tab === 'safe');
    
    renderFeatureWeights();
}

// Render Feature Weights List
function renderFeatureWeights() {
    if (!modelMetrics) return;
    
    const indicators = currentWeightsTab === 'phishing' 
        ? modelMetrics.top_phishing_indicators 
        : modelMetrics.top_safe_indicators;
        
    const listEl = currentWeightsTab === 'phishing'
        ? document.getElementById("weights-phishing-list")
        : document.getElementById("weights-safe-list");
        
    // Hide other list, show current list
    document.getElementById("weights-phishing-list").classList.toggle("active", currentWeightsTab === 'phishing');
    document.getElementById("weights-safe-list").classList.toggle("active", currentWeightsTab === 'safe');
    
    listEl.innerHTML = "";
    
    if (indicators.length === 0) {
        listEl.innerHTML = `<div class="table-placeholder">No coefficients loaded.</div>`;
        return;
    }
    
    // Find maximum absolute coefficient value for scale capping
    const maxVal = Math.max(...indicators.map(item => Math.abs(item.weight)), 1.0);
    
    indicators.forEach(item => {
        const absVal = Math.abs(item.weight);
        const percent = ((absVal / maxVal) * 100).toFixed(0);
        const fillClass = currentWeightsTab === 'phishing' ? 'phish-fill' : 'safe-fill';
        const weightSign = item.weight > 0 ? `+${item.weight.toFixed(3)}` : item.weight.toFixed(3);
        
        const row = document.createElement("div");
        row.className = "weight-row";
        row.innerHTML = `
            <div class="weight-info">
                <span class="weight-name">${escapeHTML(item.feature)}</span>
                <span class="weight-val">${weightSign}</span>
            </div>
            <div class="weight-bar-bg">
                <div class="weight-bar-fill ${fillClass}" style="width: ${percent}%"></div>
            </div>
        `;
        listEl.appendChild(row);
    });
}

// Load Predefined Templates in Scanner
function loadTemplate(templateKey) {
    const template = TEMPLATES[templateKey];
    if (!template) return;
    
    document.getElementById("scan-sender").value = template.sender;
    document.getElementById("scan-subject").value = template.subject;
    document.getElementById("scan-body").value = template.body;
    
    // Flash fields to indicate load
    const fields = [
        document.getElementById("scan-sender"),
        document.getElementById("scan-subject"),
        document.getElementById("scan-body")
    ];
    fields.forEach(el => {
        el.style.borderColor = "var(--accent-cyan)";
        setTimeout(() => el.style.borderColor = "", 800);
    });
}

// Run Email Scanner Inference
async function runInference(event) {
    event.preventDefault();
    
    const sender = document.getElementById("scan-sender").value;
    const subject = document.getElementById("scan-subject").value;
    const body = document.getElementById("scan-body").value;
    
    const submitBtn = document.getElementById("btn-submit-scan");
    const originalBtnText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> <span>Analyzing features...</span>`;
    
    try {
        const response = await fetch(`${API_URL}/api/predict`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ sender, subject, body })
        });
        
        if (!response.ok) {
            throw new Error(`Inference request failed: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === "success") {
            displayResults(data.prediction, sender, subject, body);
        } else {
            alert("Model error: " + data.message);
        }
    } catch (error) {
        console.error("Scan error:", error);
        alert("Failed to reach scanner server. Check connection.");
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnText;
    }
}

// Display Prediction Results
function displayResults(prediction, sender, subject, body) {
    // Hide placeholder, show active results
    document.getElementById("results-placeholder").style.display = "none";
    document.getElementById("results-active").style.display = "block";
    
    const badge = document.getElementById("classification-badge");
    const banner = document.getElementById("res-banner");
    const bannerIcon = document.getElementById("res-banner-icon");
    const verdict = document.getElementById("res-verdict");
    const subVerdict = document.getElementById("res-sub-verdict");
    const findingsList = document.getElementById("res-findings-list");
    
    // Clear lists
    findingsList.innerHTML = "";
    
    // Set classification badge & banner themes
    if (prediction.classification === "Phishing") {
        badge.textContent = "CLASSIFIED: PHISHING";
        badge.className = "card-badge dist-pill phishing";
        
        banner.className = "result-banner phish";
        bannerIcon.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i>`;
        verdict.textContent = "PHISHING DETECTED";
        subVerdict.textContent = "High danger flagged by the machine learning classifier.";
    } else {
        badge.textContent = "CLASSIFIED: SAFE";
        badge.className = "card-badge dist-pill safe";
        
        banner.className = "result-banner safe";
        bannerIcon.innerHTML = `<i class="fa-solid fa-shield-check"></i>`;
        verdict.textContent = "SAFE EMAIL";
        subVerdict.textContent = "Matches safe communication structures and word matrices.";
    }
    
    // Confidence Gauge update
    const confidencePct = Math.round(prediction.confidence * 100);
    document.getElementById("res-probability").textContent = `${confidencePct}%`;
    document.getElementById("res-probability-label").textContent = prediction.classification === "Phishing" ? "Threat Prob" : "Safety Prob";
    
    // Gauge circle offset
    const circle = document.getElementById("res-gauge-circle");
    const radius = circle.r.baseVal.value;
    const circumference = 2 * Math.PI * radius; // ~314.16
    const offset = circumference - (prediction.confidence * circumference);
    
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = prediction.classification === "Phishing" ? "var(--accent-rose)" : "var(--accent-emerald)";
    
    // Display Findings bullets
    if (prediction.reasons.length > 0) {
        prediction.reasons.forEach(reason => {
            const li = document.createElement("li");
            li.textContent = reason;
            findingsList.appendChild(li);
        });
    } else {
        const li = document.createElement("li");
        li.textContent = "No highly suspicious structural features triggered.";
        findingsList.appendChild(li);
    }
    
    // Show top suspicious words flagged (if any)
    if (prediction.classification === "Phishing" && prediction.words_found.length > 0) {
        const topWords = prediction.words_found.slice(0, 3).map(w => `"${w.word}"`).join(", ");
        const li = document.createElement("li");
        li.innerHTML = `Significant word triggers: <strong>${topWords}</strong>`;
        findingsList.appendChild(li);
    }
    
    // Render Highlighted Email Preview
    document.getElementById("preview-sender").textContent = sender;
    document.getElementById("preview-subject").textContent = subject;
    
    const highlightedBody = getHighlightedBody(body, prediction.words_found);
    document.getElementById("preview-body-content").innerHTML = highlightedBody;
}

// Generate Highlighted HTML for Email Preview
function getHighlightedBody(bodyText, wordAssets) {
    let text = escapeHTML(bodyText);
    
    // 1. Extract and format URLs (so they aren't corrupted by keyword highlights)
    const urls = [];
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    
    text = text.replace(urlRegex, (match) => {
        const urlId = `__URL_PLACEHOLDER_${urls.length}__`;
        urls.push(match);
        return urlId;
    });
    
    // 2. Highlight phishing words flagged by model
    const wordsToHighlight = wordAssets.map(w => w.word.toLowerCase());
    
    // Add generic urgency words just in case to provide richer highlighting
    const combinedWords = Array.from(new Set([...wordsToHighlight, ...URGENT_WORDS]));
    
    combinedWords.forEach(word => {
        if (word.length < 3) return; // Ignore very short words to prevent false matching
        
        // Escape regex special chars
        const safeWord = word.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const regex = new RegExp(`\\b(${safeWord})\\b`, 'gi');
        
        text = text.replace(regex, (match) => {
            return `<span class="highlight-phish-word">${match}</span>`;
        });
    });
    
    // 3. Inject formatted links back into placeholders
    urls.forEach((url, index) => {
        const placeholder = `__URL_PLACEHOLDER_${index}__`;
        // Format link
        const formattedLink = `<span class="highlight-phish-link" title="Flagged Link URL Details">${url}</span>`;
        text = text.replace(placeholder, formattedLink);
    });
    
    return text;
}

// Submit Retraining Form
async function submitRetrain(event) {
    event.preventDefault();
    
    const sender = document.getElementById("retrain-sender").value;
    const subject = document.getElementById("retrain-subject").value;
    const body = document.getElementById("retrain-body").value;
    const label = parseInt(document.getElementById("retrain-label").value);
    
    const backdrop = document.getElementById("loading-backdrop");
    backdrop.classList.add("active");
    
    try {
        const response = await fetch(`${API_URL}/api/train`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ sender, subject, body, label })
        });
        
        if (!response.ok) {
            throw new Error(`Retraining request failed: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === "success") {
            modelMetrics = data.metrics;
            
            // Record custom submission log
            customSubmissions.push({ sender, subject, label });
            renderCustomSubmissionsLog();
            
            // Re-render dashboard
            renderDashboard();
            
            // Clear Form
            document.getElementById("retrain-form").reset();
            
            // Smooth delay
            setTimeout(() => {
                backdrop.classList.remove("active");
                alert("Model retraining completed successfully!");
            }, 1000);
        } else {
            backdrop.classList.remove("active");
            alert("Retraining error: " + data.message);
        }
    } catch (error) {
        console.error("Retrain error:", error);
        backdrop.classList.remove("active");
        alert("Failed to submit retraining data. Check network.");
    }
}

// Render Log of Custom Submissions
function renderCustomSubmissionsLog() {
    const countEl = document.getElementById("custom-entries-count");
    const tbody = document.getElementById("custom-entries-tbody");
    
    countEl.textContent = `${customSubmissions.length} Custom Entries`;
    
    if (customSubmissions.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="table-placeholder">No custom emails added yet. Use the form on the left to inject training data.</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = "";
    
    // Show in reverse chronological order
    const reversedList = [...customSubmissions].reverse();
    
    reversedList.forEach(entry => {
        const badgeClass = entry.label === 1 ? 'b-phish' : 'b-safe';
        const badgeText = entry.label === 1 ? 'Phish' : 'Safe';
        
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td title="${escapeHTML(entry.sender)}">${escapeHTML(entry.sender)}</td>
            <td title="${escapeHTML(entry.subject)}">${escapeHTML(entry.subject)}</td>
            <td><span class="badge-label ${badgeClass}">${badgeText}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Helper: Escape HTML string to avoid injection
function escapeHTML(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
