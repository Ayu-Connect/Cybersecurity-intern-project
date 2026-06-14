import numpy as np
import pandas as pd
import re
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import scipy.sparse as sp

import dataset

MODEL_PATH = "model_assets.joblib"

# Brand list for mismatch check
BRANDS = ["paypal", "netflix", "amazon", "chase", "apple", "google", "bankofamerica", "irs", "microsoft", "facebook", "instagram", "twitter"]

# Standardized set of urgency terms
URGENT_WORDS = [
    "urgent", "immediate", "suspend", "verify", "security", "action", 
    "restricted", "login", "expire", "billing", "declined", "refund", 
    "lottery", "win", "payment", "prize", "alert", "attention"
]

def extract_manual_features(df):
    """
    Extracts numerical and boolean features from emails.
    Returns a 2D numpy array of shape (num_samples, 6).
    Features:
    1. subject_has_urgency (0 or 1)
    2. body_has_urgency (0 or 1)
    3. url_count (integer)
    4. has_ip_in_url (0 or 1)
    5. has_shortener (0 or 1)
    6. sender_brand_mismatch (0 or 1)
    """
    features = []
    
    for _, row in df.iterrows():
        sender = str(row.get('sender', '')).lower()
        subject = str(row.get('subject', '')).lower()
        body = str(row.get('body', '')).lower()
        
        # 1. subject urgency check
        subject_urgent = 1 if any(word in subject for word in URGENT_WORDS) else 0
        
        # 2. body urgency check
        body_urgent = 1 if any(word in body for word in URGENT_WORDS) else 0
        
        # Extract URLs
        # Basic URL regex
        urls = re.findall(r'https?://[^\s/$.?#].[^\s]*', body)
        url_count = len(urls)
        
        # 4. has IP in URL
        has_ip = 0
        # 5. has shortener
        has_shortener = 0
        
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl"]
        
        for url in urls:
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                has_ip = 1
            if any(sh in url for sh in shorteners):
                has_shortener = 1
                
        # 6. Sender brand mismatch check
        # Check if the email body mentions a brand, but the sender domain does not belong to that brand
        mismatch = 0
        body_text = subject + " " + body
        
        # Try to find if sender is from a generic domain
        is_generic_sender = any(g in sender for g in ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com", "@aol.com"])
        
        for brand in BRANDS:
            # Check if brand mentioned in text (e.g. "paypal")
            if brand in body_text:
                # If brand is in text, sender domain should contain the brand name
                # E.g. sender is "security@paypal-update.net" (suspicious domain) or "support@gmail.com" (generic sender)
                sender_domain = sender.split('@')[-1] if '@' in sender else sender
                
                # If sender domain does not contain the brand name (or is generic), it's a mismatch
                if brand not in sender_domain or is_generic_sender:
                    mismatch = 1
                    break
        
        features.append([
            subject_urgent,
            body_urgent,
            url_count,
            has_ip,
            has_shortener,
            mismatch
        ])
        
    return np.array(features, dtype=float)

def train_model():
    """Trains the model pipeline and saves the artifacts."""
    df = dataset.get_full_dataset()
    
    # Combined text for TF-IDF
    df['combined_text'] = df['subject'] + " " + df['body']
    
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        df, df['label'], test_size=0.2, random_state=42, stratify=df['label']
    )
    
    # 1. TF-IDF Fit & Transform
    vectorizer = TfidfVectorizer(max_features=1200, stop_words='english', lowercase=True)
    X_train_tfidf = vectorizer.fit_transform(X_train_df['combined_text'])
    X_test_tfidf = vectorizer.transform(X_test_df['combined_text'])
    
    # 2. Extract manual features
    X_train_manual = extract_manual_features(X_train_df)
    X_test_manual = extract_manual_features(X_test_df)
    
    # Scale manual features (specifically URL count)
    scaler = StandardScaler()
    X_train_manual_scaled = scaler.fit_transform(X_train_manual)
    X_test_manual_scaled = scaler.transform(X_test_manual)
    
    # 3. Combine TF-IDF and manual features
    X_train_combined = sp.hstack([X_train_tfidf, X_train_manual_scaled], format='csr')
    X_test_combined = sp.hstack([X_test_tfidf, X_test_manual_scaled], format='csr')
    
    # 4. Train Logistic Regression
    clf = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    clf.fit(X_train_combined, y_train)
    
    # 5. Evaluate
    y_pred = clf.predict(X_test_combined)
    y_prob = clf.predict_proba(X_test_combined)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    
    # Extract feature weights to show "Top Phishing Words" and "Top Safe Words"
    feature_names = vectorizer.get_feature_names_out().tolist()
    manual_names = [
        "Subject Urgency Indicator",
        "Body Urgency Indicator",
        "URL Count",
        "IP Address in Link",
        "Link Shortener Domain",
        "Sender-Content Brand Mismatch"
    ]
    all_feature_names = feature_names + manual_names
    
    coefficients = clf.coef_[0]
    
    # Create sorted list of (feature, coef)
    feature_weights = list(zip(all_feature_names, coefficients))
    
    # Top Phishing indicators (highest positive coefficients)
    top_phishing = sorted(feature_weights, key=lambda x: x[1], reverse=True)[:15]
    # Top Safe indicators (most negative coefficients)
    top_safe = sorted(feature_weights, key=lambda x: x[1], reverse=False)[:15]
    
    # Format coefficients for JSON response (convert float64 to float)
    top_phishing_formatted = [{ "feature": f, "weight": float(w) } for f, w in top_phishing]
    top_safe_formatted = [{ "feature": f, "weight": float(w) } for f, w in top_safe]
    
    metrics = {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        },
        "dataset_size": len(df),
        "phishing_count": int(df['label'].sum()),
        "safe_count": int(len(df) - df['label'].sum()),
        "top_phishing_indicators": top_phishing_formatted,
        "top_safe_indicators": top_safe_formatted
    }
    
    # Save assets
    model_assets = {
        "vectorizer": vectorizer,
        "scaler": scaler,
        "classifier": clf,
        "metrics": metrics
    }
    joblib.dump(model_assets, MODEL_PATH)
    
    return metrics

def get_model_assets():
    """Loads and returns the model assets, training them if not already present."""
    if not os.path.exists(MODEL_PATH):
        print("Model assets not found. Training model now...")
        train_model()
    return joblib.load(MODEL_PATH)

def predict_email(sender, subject, body):
    """
    Classifies a single email.
    Returns:
    - classification: "Phishing" or "Safe"
    - probability: float (0.0 to 1.0 confidence of being Phishing)
    - reasons: list of strings detailing triggered features
    - words_found: list of dictionary of { word, weight } flagged as suspicious in the email
    """
    assets = get_model_assets()
    vectorizer = assets["vectorizer"]
    scaler = assets["scaler"]
    clf = assets["classifier"]
    
    # Single sample df
    single_df = pd.DataFrame([{ "sender": sender, "subject": subject, "body": body }])
    single_df['combined_text'] = single_df['subject'] + " " + single_df['body']
    
    # Transform TF-IDF
    X_tfidf = vectorizer.transform(single_df['combined_text'])
    
    # Manual features
    manual_feats = extract_manual_features(single_df)
    
    # Check manual features before scaling to list them in explanation reasons
    # 0: subject_urgent, 1: body_urgent, 2: url_count, 3: has_ip, 4: has_shortener, 5: mismatch
    reasons = []
    if manual_feats[0, 0] > 0:
        reasons.append("Urgent keywords detected in the Subject line.")
    if manual_feats[0, 1] > 0:
        reasons.append("Urgent/threat-inducing words detected in the Email Body.")
    if manual_feats[0, 2] > 0:
        reasons.append(f"Contains multiple links ({int(manual_feats[0, 2])} links).")
    if manual_feats[0, 3] > 0:
        reasons.append("Suspicious numeric IP address used in link URL instead of domain name.")
    if manual_feats[0, 4] > 0:
        reasons.append("Uses a shortened URL service (e.g. bit.ly, tinyurl) which masks the destination.")
    if manual_feats[0, 5] > 0:
        reasons.append("Sender domain does not match official domain of the brand mentioned in email body.")
        
    X_manual_scaled = scaler.transform(manual_feats)
    
    # Combine features
    X_combined = sp.hstack([X_tfidf, X_manual_scaled], format='csr')
    
    # Run prediction
    pred_label = int(clf.predict(X_combined)[0])
    pred_prob = float(clf.predict_proba(X_combined)[0, 1])
    
    # Identify which individual words in the email have positive phishing weights in our model
    words_found = []
    email_words = set(re.findall(r'\b\w+\b', single_df['combined_text'].iloc[0].lower()))
    
    # Map vectorizer vocabulary to coefficients
    vocab = vectorizer.vocabulary_
    coefficients = clf.coef_[0]
    
    for word in email_words:
        if word in vocab:
            word_idx = vocab[word]
            weight = float(coefficients[word_idx])
            # If weight is positively high (phishing indicator)
            if weight > 0.2:
                words_found.append({ "word": word, "weight": weight })
                
    # Sort words by weight desc
    words_found = sorted(words_found, key=lambda x: x["weight"], reverse=True)
    
    classification = "Phishing" if pred_label == 1 else "Safe"
    
    return {
        "classification": classification,
        "confidence": pred_prob if classification == "Phishing" else (1.0 - pred_prob),
        "reasons": reasons,
        "words_found": words_found
    }
