"""
Health check endpoint for Vercel
"""
from http.server import BaseHTTPRequestHandler
import json
import sys
import os

# Add paths for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ml-model'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

try:
    from backend.ml.fraud_detector import FraudDetector
    detector = FraudDetector()
    model_loaded = detector.is_loaded()
except Exception as e:
    model_loaded = False
    print(f"Error loading detector: {e}")

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = {
            "status": "healthy",
            "model_loaded": model_loaded
        }
        
        self.wfile.write(json.dumps(response).encode())
        return


