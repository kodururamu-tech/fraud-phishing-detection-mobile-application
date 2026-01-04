"""
Fraud Detection Engine
Main ML model integration for fraud detection
"""
import os
import sys
import joblib
import re
from typing import Dict, Optional

# Add parent directory to path for imports (flexible paths for Render)
ml_model_paths = [
    os.path.join(os.path.dirname(__file__), '..', '..', 'ml-model'),
    os.path.join(os.path.dirname(__file__), '..', 'ml-model'),
    os.path.join(os.getcwd(), 'ml-model'),
    'ml-model'
]
for path in ml_model_paths:
    abs_path = os.path.abspath(path)
    if os.path.exists(abs_path) and abs_path not in sys.path:
        sys.path.append(abs_path)

from preprocess import clean_text, extract_features, preprocess_url


class FraudDetector:
    """Main fraud detection class"""
    
    def __init__(self):
        """Initialize fraud detector with ML models"""
        self.model = None
        self.vectorizer = None
        self.model_loaded = False
        self._load_model()
    
    def _load_model(self):
        """Load trained ML model and vectorizer with robust path handling and logging for Render/local."""
        try:
            base_dir = os.path.dirname(__file__)
            cwd = os.getcwd()
            possible_paths = [
                os.path.join(base_dir, '..', '..', 'ml-model'),  # From backend/ml/ -> root/ml-model
                os.path.join(base_dir, '..', 'ml-model'),        # From backend/ -> ml-model
                os.path.join(cwd, 'ml-model'),                   # Current working directory
                os.path.join(base_dir, 'ml-model'),              # backend/ml/ml-model
                os.path.join(base_dir, '..', 'ml-model'),        # backend/ml/../ml-model
                os.path.join(cwd, 'backend', 'ml-model'),        # cwd/backend/ml-model
                'ml-model',                                      # Relative to cwd
                os.path.join('backend', 'ml-model'),             # backend/ml-model
            ]

            model_path = None
            vectorizer_path = None
            found = False
            print("[Model Loader] Attempting to load model and vectorizer. Current working directory:", cwd)
            for path in possible_paths:
                mp = os.path.abspath(os.path.join(path, 'model.pkl'))
                vp = os.path.abspath(os.path.join(path, 'vectorizer.pkl'))
                print(f"[Model Loader] Checking: {mp} and {vp}")
                if os.path.exists(mp) and os.path.exists(vp):
                    model_path = mp
                    vectorizer_path = vp
                    found = True
                    print(f"[Model Loader] Found model at: {model_path}")
                    print(f"[Model Loader] Found vectorizer at: {vectorizer_path}")
                    break
            if found and model_path and vectorizer_path:
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                self.model_loaded = True
                print(f"[Model Loader] ML model loaded successfully from {os.path.dirname(model_path)}")
            else:
                print("[Model Loader] ERROR: Model files not found in any known location. Using rule-based detection only.")
                self.model_loaded = False
        except Exception as e:
            print(f"[Model Loader] Exception while loading model: {e}")
            self.model_loaded = False
    
    def is_loaded(self) -> bool:
        """Check if ML model is loaded"""
        return self.model_loaded
    
    def _predict_with_ml(self, text: str) -> tuple:
        """
        Predict using ML model
        
        Args:
            text: Input text
            
        Returns:
            Tuple of (is_fraud, confidence)
        """
        if not self.model_loaded:
            return self._rule_based_detection(text)
        
        try:
            cleaned = clean_text(text)
            text_vec = self.vectorizer.transform([cleaned])
            
            prediction = self.model.predict(text_vec)[0]
            probabilities = self.model.predict_proba(text_vec)[0]
            
            is_fraud = bool(prediction == 1)
            confidence = float(probabilities[1] if is_fraud else probabilities[0])
            
            return is_fraud, confidence
        except Exception as e:
            print(f"ML prediction error: {e}")
            return self._rule_based_detection(text)
    
    def _rule_based_detection(self, text: str) -> tuple:
        """
        Fallback rule-based detection
        
        Args:
            text: Input text
            
        Returns:
            Tuple of (is_fraud, confidence)
        """
        text_lower = text.lower()
        
        # Fraud indicators
        fraud_keywords = [
            'urgent', 'suspended', 'verify', 'click here', 'act now',
            'limited time', 'expire', 'congratulations', 'won', 'prize',
            'claim now', 'update immediately', 'payment failed',
            'account compromised', 'deactivated', 'verify identity'
        ]
        
        suspicious_patterns = [
            r'http[s]?://[^\s]+',  # URLs
            r'www\.[^\s]+',  # www links
            r'\d{4,}',  # Long numbers (OTP, codes)
            r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}',  # Phone numbers
        ]
        
        fraud_score = 0
        max_score = 10
        
        # Check keywords
        for keyword in fraud_keywords:
            if keyword in text_lower:
                fraud_score += 1
        
        # Check patterns
        for pattern in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                fraud_score += 1
        
        # Check for currency mentions
        if re.search(r'[\$₹€£]|\brupee\b|\bdollar\b', text_lower):
            fraud_score += 0.5
        
        # Normalize score
        confidence = min(fraud_score / max_score, 1.0)
        is_fraud = confidence > 0.3
        
        return is_fraud, confidence
    
    def _get_risk_level(self, confidence: float) -> str:
        """
        Determine risk level from confidence score
        
        Args:
            confidence: Confidence score (0.0 to 1.0)
            
        Returns:
            Risk level string
        """
        if confidence >= 0.7:
            return "HIGH"
        elif confidence >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def detect_sms(self, text: str, phone_number: Optional[str] = None) -> Dict:
        """
        Detect fraud in SMS
        
        Args:
            text: SMS text content
            phone_number: Optional sender phone number
            
        Returns:
            Dictionary with detection results
        """
        is_fraud, confidence = self._predict_with_ml(text)
        risk_level = self._get_risk_level(confidence)
        
        # Additional phone number check
        if phone_number:
            phone_risk = self._check_phone_number(phone_number)
            if phone_risk:
                confidence = max(confidence, 0.6)
                is_fraud = True if confidence > 0.4 else is_fraud
        
        message = "⚠️ FRAUD DETECTED" if is_fraud else "✅ Safe"
        if is_fraud:
            message += f" - High risk of phishing/scam (Confidence: {confidence:.1%})"
        else:
            message += f" - No threats detected (Confidence: {confidence:.1%})"
        
        return {
            "is_fraud": is_fraud,
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "message": message,
            "details": {
                "type": "SMS",
                "phone_number": phone_number,
                "text_length": len(text)
            }
        }
    
    def detect_call(self, phone_number: str) -> Dict:
        """
        Detect fraud/scam in phone number
        
        Args:
            phone_number: Phone number to check
            
        Returns:
            Dictionary with detection results
        """
        # Check phone number patterns
        is_fraud, confidence = self._check_phone_number(phone_number)
        risk_level = self._get_risk_level(confidence)
        
        message = "⚠️ SCAM NUMBER" if is_fraud else "✅ Safe Number"
        if is_fraud:
            message += f" - This number is likely a scam/fraud (Confidence: {confidence:.1%})"
        else:
            message += f" - Number appears safe (Confidence: {confidence:.1%})"
        
        return {
            "is_fraud": is_fraud,
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "message": message,
            "details": {
                "type": "CALL",
                "phone_number": phone_number
            }
        }
    
    def _check_phone_number(self, phone_number: str) -> tuple:
        """
        Check if phone number is suspicious
        
        Args:
            phone_number: Phone number to check
            
        Returns:
            Tuple of (is_fraud, confidence)
        """
        # Remove non-digits
        digits = re.sub(r'\D', '', phone_number)
        
        # Known scam patterns (simplified)
        suspicious_patterns = [
            r'^\+91[0-9]{10}$',  # Indian numbers (can be legitimate)
            r'^\+1[0-9]{10}$',   # US numbers
        ]
        
        # Very short numbers are suspicious
        if len(digits) < 10:
            return True, 0.8
        
        # Check for repeated digits (common in scam numbers)
        if len(set(digits[-6:])) < 3:
            return True, 0.6
        
        # Default: low risk (in production, use a phone number database)
        return False, 0.2
    
    def detect_email(self, subject: str, body: str, sender: Optional[str] = None) -> Dict:
        """
        Detect phishing/fraud in email
        
        Args:
            subject: Email subject
            body: Email body
            sender: Optional sender email address
            
        Returns:
            Dictionary with detection results
        """
        # Combine subject and body
        full_text = f"{subject} {body}"
        
        is_fraud, confidence = self._predict_with_ml(full_text)
        risk_level = self._get_risk_level(confidence)
        
        # Check sender domain
        if sender:
            sender_risk = self._check_email_sender(sender)
            if sender_risk:
                confidence = max(confidence, 0.7)
                is_fraud = True
        
        message = "⚠️ PHISHING EMAIL" if is_fraud else "✅ Safe Email"
        if is_fraud:
            message += f" - High risk of phishing (Confidence: {confidence:.1%})"
        else:
            message += f" - No threats detected (Confidence: {confidence:.1%})"
        
        return {
            "is_fraud": is_fraud,
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "message": message,
            "details": {
                "type": "EMAIL",
                "sender": sender,
                "subject": subject[:50]  # Truncate for display
            }
        }
    
    def _check_email_sender(self, sender: str) -> bool:
        """
        Check if email sender is suspicious
        
        Args:
            sender: Email address
            
        Returns:
            True if suspicious
        """
        sender_lower = sender.lower()
        
        # Suspicious patterns
        suspicious_domains = [
            'gmail.com',  # Common for phishing
            'yahoo.com',
            'hotmail.com',
        ]
        
        # Check for typosquatting (simplified)
        if '@' in sender:
            domain = sender.split('@')[1]
            if any(susp in domain for susp in ['bank', 'paypal', 'amazon', 'microsoft']):
                # Could be legitimate, but check for typos
                if len(domain) > 20:  # Long domains are suspicious
                    return True
        
        return False
    
    def detect_url(self, url: str) -> Dict:
        """
        Detect malicious URL
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with detection results
        """
        # Preprocess URL
        processed_url = preprocess_url(url)
        
        # Check URL patterns
        is_fraud, confidence = self._check_url_patterns(url, processed_url)
        risk_level = self._get_risk_level(confidence)
        
        message = "⚠️ MALICIOUS URL" if is_fraud else "✅ Safe URL"
        if is_fraud:
            message += f" - This URL is likely malicious (Confidence: {confidence:.1%})"
        else:
            message += f" - URL appears safe (Confidence: {confidence:.1%})"
        
        return {
            "is_fraud": is_fraud,
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "message": message,
            "details": {
                "type": "URL",
                "url": url,
                "domain": processed_url
            }
        }
    
    def _check_url_patterns(self, url: str, domain: str) -> tuple:
        """
        Check URL for malicious patterns
        
        Args:
            url: Full URL
            domain: Extracted domain
            
        Returns:
            Tuple of (is_fraud, confidence)
        """
        url_lower = url.lower()
        domain_lower = domain.lower()
        
        # Suspicious patterns
        suspicious_keywords = [
            'verify', 'secure', 'update', 'login', 'account',
            'bank', 'payment', 'claim', 'prize', 'won'
        ]
        
        # Check for IP addresses (suspicious)
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            return True, 0.8
        
        # Check for suspicious keywords in domain
        fraud_score = 0
        for keyword in suspicious_keywords:
            if keyword in domain_lower:
                fraud_score += 1
        
        # Check for very long domains (typosquatting)
        if len(domain) > 30:
            fraud_score += 2
        
        # Check for multiple subdomains (suspicious)
        if domain.count('.') > 2:
            fraud_score += 1
        
        # Check for HTTP (not HTTPS) - less secure
        if url.startswith('http://') and not url.startswith('https://'):
            fraud_score += 0.5
        
        confidence = min(fraud_score / 5.0, 1.0)
        is_fraud = confidence > 0.4
        
        return is_fraud, confidence


