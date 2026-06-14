from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import model
import dataset

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)  # Enable Cross-Origin Resource Sharing

# Automatically train model on startup if model assets don't exist
print("Checking model assets status...")
model.get_model_assets()
print("Model assets verified.")

@app.route('/')
def index():
    """Serves the main application page."""
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    """Serves static files like CSS and JS from the root folder."""
    return send_from_directory('.', path)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Returns the model performance metrics, dataset statistics, and top features."""
    try:
        assets = model.get_model_assets()
        return jsonify({
            "status": "success",
            "metrics": assets["metrics"]
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/predict', methods=['POST'])
def predict():
    """Classifies a user-provided email."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
            
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        body = data.get('body', '')
        
        if not sender or not subject or not body:
            return jsonify({"status": "error", "message": "Missing sender, subject, or body fields"}), 400
            
        result = model.predict_email(sender, subject, body)
        return jsonify({
            "status": "success",
            "prediction": result
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/train', methods=['POST'])
def train():
    """Adds a new custom email to the dataset and retrains the model."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
            
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        body = data.get('body', '')
        label = data.get('label')  # Expect 0 or 1
        
        if not sender or not subject or not body or label is None:
            return jsonify({"status": "error", "message": "Missing sender, subject, body, or label fields"}), 400
            
        if int(label) not in [0, 1]:
            return jsonify({"status": "error", "message": "Label must be 0 (Safe) or 1 (Phishing)"}), 400
            
        # Save custom email
        dataset.save_custom_email(sender, subject, body, int(label))
        
        # Retrain the model
        print("Retraining model with new custom email...")
        metrics = model.train_model()
        print("Retraining completed successfully.")
        
        return jsonify({
            "status": "success",
            "message": "Custom email added and model retrained successfully.",
            "metrics": metrics
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    # Run server on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
