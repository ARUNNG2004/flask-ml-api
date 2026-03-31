import random
from flask import Flask, request, jsonify

app = Flask(__name__)

# =========================
# RULES WITH MULTIPLE RESPONSES
# =========================

RULES = [
    {
        "category": "phishing_definition",
        "triggers": ['what is phishing', 'phishing mean', 'define phishing'],
        "responses": [
            "Phishing is a cyber attack using fake messages.",
            "Attackers pretend to be trusted companies.",
            "It tries to steal passwords or bank details.",
            "Usually comes via email, SMS, or fake websites.",
            "Always verify before clicking any link."
        ],
        "suggestions": ["How to detect phishing?", "Check a URL"]
    },

    {
        "category": "url_safety",
        "triggers": ['safe url', 'check link', 'verify link', 'is this url'],
        "responses": [
            "Check if the URL uses HTTPS.",
            "Look for spelling mistakes in domain.",
            "Avoid clicking shortened links blindly.",
            "Hover over links before clicking.",
            "Use scanners to verify URLs."
        ],
        "suggestions": ["What is phishing?", "Scan a URL"]
    },

    {
        "category": "phishing_signs",
        "triggers": ['phishing signs', 'spot phishing', 'red flags'],
        "responses": [
            "Urgent messages asking for quick action are suspicious.",
            "Fake domains often mimic real brands.",
            "Too many subdomains can indicate phishing.",
            "Requests for passwords are a red flag.",
            "Check for unusual domain endings."
        ],
        "suggestions": ["Check a URL", "What is brand hijacking?"]
    },

    {
        "category": "ssl_https",
        "triggers": ['https', 'ssl', 'secure'],
        "responses": [
            "HTTPS encrypts your connection.",
            "SSL protects data during transfer.",
            "But HTTPS alone doesn’t mean safe.",
            "Many phishing sites also use HTTPS.",
            "Always check more than just the lock icon."
        ],
        "suggestions": ["What else to check?", "Scan URL"]
    },

    {
        "category": "tips",
        "triggers": ['tips', 'stay safe', 'security tips'],
        "responses": [
            "Always enable 2FA on accounts.",
            "Never click unknown links.",
            "Use strong passwords.",
            "Keep your system updated.",
            "Avoid entering data on unknown sites."
        ],
        "suggestions": ["What is phishing?", "Check URL"]
    },

    {
        "category": "greeting",
        "triggers": ['hi', 'hello', 'hey'],
        "responses": [
            "Hello! How can I help you with cybersecurity?",
            "Hi there! Want to check a URL?",
            "Hey! Ask me anything about phishing.",
            "Hello! I can help you stay safe online.",
            "Hi! Ready to analyze a link?"
        ],
        "suggestions": ["What is phishing?", "Check URL safety"]
    }
]

FALLBACK = {
    "category": "fallback",
    "responses": [
        "I didn't understand that.",
        "Try asking about phishing or URL safety.",
        "I can help with cybersecurity questions.",
        "Please rephrase your question.",
        "Ask something about online safety."
    ],
    "suggestions": ["What is phishing?", "Check URL"]
}

# =========================
# RESPONSE ENGINE
# =========================

def get_response(user_message: str) -> dict:
    if not user_message:
        return {
            "response": random.choice(FALLBACK["responses"]),
            "category": FALLBACK["category"],
            "suggestions": FALLBACK["suggestions"]
        }

    msg = user_message.lower().strip()

    for rule in RULES:
        for trigger in rule["triggers"]:
            if trigger in msg:
                return {
                    "response": random.choice(rule["responses"]),
                    "category": rule["category"],
                    "suggestions": rule["suggestions"]
                }

    return {
        "response": random.choice(FALLBACK["responses"]),
        "category": FALLBACK["category"],
        "suggestions": FALLBACK["suggestions"]
    }

# =========================
# API ROUTE
# =========================

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        user_message = data.get("message", "")

        bot_response = get_response(user_message)

        return jsonify({
            "success": True,
            "data": {
                "response": bot_response["response"],
                "suggestions": bot_response["suggestions"]
            }
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# =========================
# RUN SERVER
# =========================

if __name__ == '__main__':
    app.run(debug=True)
