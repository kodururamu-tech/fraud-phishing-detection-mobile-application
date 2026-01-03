"""
Call scanning endpoint for Vercel
"""
from http.server import BaseHTTPRequestHandler
import json
import sys
import os

# Add paths for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'ml-model'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

try:
    from backend.ml.fraud_detector import FraudDetector
    detector = FraudDetector()
except Exception as e:
    detector = None
    print(f"Error loading detector: {e}")

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        return
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            phone_number = data.get('phone_number', '')
            
            if not phone_number:
                raise ValueError("Phone number is required")
            
            if detector:
                result = detector.detect_call(phone_number)
            else:
                # Fallback response
                result = {
                    "is_fraud": False,
                    "confidence": 0.5,
                    "risk_level": "MEDIUM",
                    "message": "Service temporarily unavailable",
                    "details": {"type": "CALL"}
                }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            
            self.wfile.write(json.dumps(result).encode())
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            error_response = {"error": str(e)}
            self.wfile.write(json.dumps(error_response).encode())
        
        return


