# PHISHSHIELD // AI Phishing Email Detection Model

PhishShield is an end-to-end machine learning-powered cybersecurity engine designed to identify, analyze, and explain phishing email threats. It features a high-fidelity **interactive web dashboard** and a **Flask-based REST API** that integrates standard natural language processing (NLP) techniques with specialized heuristic security features. 

Users can run real-time email scans, inspect the classification decision path, explore feature weights, and dynamically inject new custom email training data to retrain the underlying Scikit-Learn model on the fly.

---

## 🚀 Key Features

### 1. Web Security Dashboard (`index.html`, `app.js`, `style.css`)
A sleek, dark-themed cyber operations dashboard that includes three main views:
*   **Model Performance Dashboard:** Monitor live performance metrics (Accuracy, F1-Score, and Dataset Size/Distribution). It features an interactive **Confusion Matrix** showing percentages of True/False Positives and Negatives, alongside an interactive **Model Coefficients Bar Chart** showcasing the top words associated with safe or phishing classifications.
*   **Email Security Scanner:** Perform instant inference on custom messages. It supports template presets (such as PayPal Urgency, Netflix Billing, Post Office Alert, Work Meeting, and Tech Newsletters), displays threat/safety confidence levels on a circular gauge, gives key structural findings, and generates a **Highlighted Email Preview** marking suspicious keywords and masked URLs.
*   **Model Retraining Portal:** Add custom labeled emails directly into the dataset. Clicking submit triggers an asynchronous server-side pipeline training run, updating dashboard coefficients and accuracy metrics in real-time. Features a persistent **Custom Submissions Log** tracking user-contributed samples.

### 2. Machine Learning Pipeline (`model.py`, `dataset.py`)
A robust hybrid classifier combining mathematical text representation and expert security heuristics:
*   **NLP Text Representation:** Combines the subject and body, strips English stop words, and fits a `TfidfVectorizer` (vocabulary capped at 1,200 terms) to capture word associations.
*   **Manual/Heuristic Feature Engineering:** Extracts 6 numerical and boolean security indicators:
    1.  `subject_has_urgency`: Flags urgent terms (e.g., *verify, immediate, restricted, lottery*) in the subject line.
    2.  `body_has_urgency`: Flags urgent/threat-inducing keywords in the body content.
    3.  `url_count`: Integer count of links embedded in the body.
    4.  `has_ip_in_url`: Flags URLs using raw numerical IP addresses (e.g., `http://192.168.4.88/`) instead of standard domains.
    5.  `has_shortener`: Detects standard masking shorteners (e.g., `bit.ly`, `tinyurl.com`, `t.co`).
    6.  `sender_brand_mismatch`: Compares mentions of popular brands (e.g., *PayPal, Amazon, Bank of America, IRS*) in the message against the sender's domain address to identify brand impersonation.
*   **Hybrid Classification:** Normalizes the manual features using a `StandardScaler`, combines them with the sparse TF-IDF text matrix, and fits a `LogisticRegression` classifier.
*   **Pipeline Serialization:** Saves and loads vectorizers, scalers, and classifier weights using `joblib` as a serialized payload (`model_assets.joblib`).

### 3. API Service & Backend (`app.py`)
A lightweight Flask backend acting as the bridge between model inference and the frontend dashboard:
*   **Automatic Bootstrapping:** Automatically runs initial pipeline training on startup if the serialized model assets are missing.
*   **REST API Endpoints:**
    *   `GET /api/stats`: Returns current performance statistics, feature coefficients, and dataset summaries.
    *   `POST /api/predict`: Runs real-time inference on a sender, subject, and body payload, returning confidence levels, triggered manual features, and vocabulary triggers.
    *   `POST /api/train`: Appends custom emails to a JSON database (`custom_emails.json`), triggers a model retraining pipeline, and returns updated metrics.

### 4. Companion Test Suite (`test_model.py`)
An automated `unittest` module verifying the functionality and math of the backend components:
*   Validates synthetic dataset balancing (1200 synthetic emails split 50/50 safe and phishing).
*   Audits manual feature extraction arrays and indicators logic.
*   Enforces classification accuracy thresholds ($> 85\%$ accuracy and F1-score).
*   Confirms inference correctness under mock phishing and safe scenarios.
*   Handles teardown isolation by backing up and restoring existing database/model assets to prevent state pollution.

---

## 📂 Project Architecture

```
task3/
├── app.py                  # Flask REST API server and static asset host
├── model.py                # ML training pipeline, inference, and feature extraction
├── dataset.py              # Synthetic dataset generator and custom data IO handler
├── test_model.py           # Python unittest suite for verifying pipeline accuracy
├── index.html              # Main frontend layout (Outfit/Inter typography & FontAwesome icons)
├── style.css               # Cyberpunk dark styling with custom charts, gauges & transitions
├── app.js                  # State manager, chart renderer, and API connection handler
├── model_assets.joblib     # Serialized vectorizer, scaler, classifier, and metrics (Generated)
├── custom_emails.json      # Persistent local database of user-added training data (Generated)
└── README.md               # Project documentation (This file)
```

---

## ⚙️ Installation & Prerequisites

### Setup Requirements
1.  **Python 3.8+** must be installed on your system.
2.  Install required dependencies via `pip`:
    ```bash
    pip install Flask Flask-CORS pandas scikit-learn joblib numpy scipy
    ```

---

## 🛠️ Usage Instructions

### 1. Launching the Application

Start the Flask backend server from the project directory:
```bash
python app.py
```
*   The API server will launch at `http://127.0.0.1:5000/`.
*   Flask will automatically serve the frontend dashboard directly at `http://127.0.0.1:5000/`.
*   *(Optional)* If you are running the frontend via a separate dev server (e.g., VS Code Live Server on port 5500), `app.js` will dynamically detect it and route API requests back to port 5000.

### 2. Testing the Pipeline

To run the automated tests and verify model behavior locally, execute:
```bash
python test_model.py
```

### 3. API Specifications

#### `GET /api/stats`
*   **Description:** Returns the current model evaluation statistics and coefficient listings.
*   **Response Snippet:**
    ```json
    {
      "status": "success",
      "metrics": {
        "accuracy": 0.985,
        "f1_score": 0.984,
        "dataset_size": 1200,
        "phishing_count": 600,
        "safe_count": 600,
        "top_phishing_indicators": [
          { "feature": "Sender-Content Brand Mismatch", "weight": 2.45 },
          { "feature": "subject", "weight": 1.87 }
        ]
      }
    }
    ```

#### `POST /api/predict`
*   **Description:** Classifies a provided email sample.
*   **Request Body:**
    ```json
    {
      "sender": "support@paypal-security-alert.net",
      "subject": "URGENT: Verify credit card details",
      "body": "Your PayPal account has been locked. Verify immediately: http://bit.ly/update-pay"
    }
    ```
*   **Response Snippet:**
    ```json
    {
      "status": "success",
      "prediction": {
        "classification": "Phishing",
        "confidence": 0.992,
        "reasons": [
          "Urgent keywords detected in the Subject line.",
          "Uses a shortened URL service (e.g. bit.ly, tinyurl) which masks the destination.",
          "Sender domain does not match official domain of the brand mentioned in email body."
        ],
        "words_found": [
          { "word": "paypal", "weight": 0.85 },
          { "word": "verify", "weight": 0.62 }
        ]
      }
    }
    ```

#### `POST /api/train`
*   **Description:** Appends a new training sample to the database and retrains the model.
*   **Request Body:**
    ```json
    {
      "sender": "legit-sender@github.com",
      "subject": "New pull request submitted",
      "body": "A new pull request is open for code review.",
      "label": 0
    }
    ```

---

## 🛡️ Feature Weight Coefficients

The model evaluates threats by computing logistic regression weights. Standard text tokens and security features correlate differently:
*   **Positive Weights (Phishing Indicators):** Higher weights increase phishing probability. Features like **Sender-Content Brand Mismatch** and words like *urgent*, *verify*, *claim*, and *suspended* hold strong positive coefficients.
*   **Negative Weights (Safe Indicators):** Features/words like *meeting*, *sync*, *onboarding*, or *thanks* pull the classification score downward, indicating legitimate communication patterns.

---

## ⚠️ Legal & Ethical Disclaimer

**Educational Sandbox & Defensive Tooling.**
PhishShield is intended strictly for security awareness, training, and defensive screening integrations. The classifier is trained on synthetic and user-submitted data and should not be used as the sole defense mechanism against active, production-grade email threat vectors. Always combine automated classifications with robust SPF, DKIM, and DMARC verification policies.
