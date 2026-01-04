/**
 * Firebase Configuration
 * Replace these values with your Firebase project credentials
 * Get them from: Firebase Console > Project Settings > General > Your apps
 */

// Firebase configuration object
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_PROJECT_ID.appspot.com",
  messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
  appId: "YOUR_APP_ID"
};

// Render backend URL - can be overridden by environment variable
const RENDER_API_URL = window.RENDER_API_URL || "https://fraud-phishing-detection-mobile-ixnh.onrender.com";

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { firebaseConfig, RENDER_API_URL };
}

