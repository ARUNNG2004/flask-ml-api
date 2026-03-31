RULES = [
    {
        "category": "phishing_definition",
        "triggers": ['what is phishing', 'phishing mean', 'define phishing', 'define phish', 'explain phishing', 'explain phish'],
        "response": "Phishing is a type of cyber attack where criminals impersonate legitimate organizations (via spoofed emails, texts, or fake websites) to trick you into revealing sensitive information. This often leads to credential theft, financial loss, or malware installation.",
        "suggestions": ["How do I spot a phishing URL?", "What are common phishing tricks?", "Is this URL safe?"]
    },
    {
        "category": "url_safety",
        "triggers": ['how to check', 'is this url', 'safe url', 'check link', 'url safe', 'verify link', 'how do i check'],
        "response": "Here are 5 tips for checking URL safety: 1) Look for HTTPS and a valid SSL padlock. 2) Carefully check the domain spelling for slight typos (e.g., g00gle.com instead of google.com). 3) Always hover over links before clicking to see the actual destination. 4) Be cautious of URL shorteners like bit.ly. 5) Use a URL scanner tool like ours to analyze deeper signals.",
        "suggestions": ["What is URL shortening?", "How does SSL work?", "Scan a URL for me"]
    },
    {
        "category": "phishing_signs",
        "triggers": ['spot phishing', 'phishing signs', 'recognize phishing', 'identify phishing', 'red flags', 'phishing tricks'],
        "response": "6 common red flags to watch out for: 1) Urgent or threatening language to force quick action. 2) Mismatched domains where the link doesn't lead to the real company's site. 3) Suspicious TLDs that are offered for free to attackers. 4) Brand names hidden deep inside subdomains rather than the main host. 5) An abnormally high number of subdomains. 6) Unusual requests for passwords or sensitive personal information.",
        "suggestions": ["What is a suspicious TLD?", "What is brand hijacking?"]
    },
    {
        "category": "brand_hijacking",
        "triggers": ['brand hijack', 'fake amazon', 'fake paypal', 'impersonation', 'lookalike'],
        "response": "Brand hijacking occurs when attackers include a familiar, legitimate brand name inside a URL's subdomain or path to deceive you (e.g., 'amazon.secure-login-fakesite.com'). Remember that the real domain is always the part immediately to the left of the TLD (like '.com' or '.org').",
        "suggestions": ["How to read a URL correctly?", "What are suspicious TLDs?"]
    },
    {
        "category": "suspicious_tld",
        "triggers": ['tld', 'suspicious domain', '.tk', '.ml', '.xyz', 'free domain', '.ga', '.cf', '.gq', '.top', '.info', '.biz'],
        "response": "Some top-level domains (TLDs) are frequently abused because they are cheap or free to register without verification. Examples include .tk, .ml, .ga, .cf, .gq, .xyz, and .top. Proceed with extreme caution if a supposedly reputable service uses one of these TLDs.",
        "suggestions": ["What is brand hijacking?", "How to check if a site is safe?"]
    },
    {
        "category": "ssl_https",
        "triggers": ['https', 'ssl', 'padlock', 'certificate', 'secure connection'],
        "response": "HTTPS uses SSL/TLS certificates to encrypt the connection between your browser and the server, keeping your data private from eavesdroppers. However, HTTPS alone does NOT guarantee safety—many modern phishing sites now obtain free SSL certificates to look secure.",
        "suggestions": ["What else should I check?", "What is CSP?"]
    },
    {
        "category": "security_headers",
        "triggers": ['csp', 'hsts', 'x-frame', 'security header', 'content security'],
        "response": "Security headers help protect users. CSP (Content-Security-Policy) restricts where scripts can load from to prevent XSS. HSTS forces browsers to only use encrypted HTTPS connections. X-Frame-Options prevents attackers from trapping the site in a transparent iframe (Clickjacking), and X-Content-Type-Options blocks malicious content-type sniffing.",
        "suggestions": ["What is SSL?", "How do I scan a URL?"]
    },
    {
        "category": "scan_help",
        "triggers": ['how to use', 'scan url', 'use this tool', 'how does this work', 'analyze', 'show me', 'not working', 'error'],
        "response": "How to use this tool: Paste the suspect URL in the scanner tab, then choose your mode. 'Fast' mode provides instant ML predictions based purely on URL string patterns. 'Full' mode actually connects to the site to check security headers like SSL and CSP. After scanning, you can view the risk score, the predictions from both models, and explore past records in the history tab.",
        "suggestions": ["What do the risk scores mean?", "What is Random Forest?"]
    },
    {
        "category": "ml_explanation",
        "triggers": ['machine learning', 'random forest', 'decision tree', 'how model', 'ai detect', 'algorithm', 'accuracy', 'how accurate', 'false positive'],
        "response": "This scanner uses two separate Machine Learning models trained on dozens of URL features. The Decision Tree model is fast and highly interpretable, making decisions based on direct threshold splits. The Random Forest model is an ensemble of many decision trees working together, making it much more robust against edge cases. Both models cast a vote, and the overarching ensemble decides the final verdict. The models are trained with SMOTE oversampling and balanced class weights to ensure both safe and malicious URLs are detected accurately.",
        "suggestions": ["What features does it use?", "How accurate is it?"]
    },
    {
        "category": "features_explanation",
        "triggers": ['features', 'what does it check', 'what is analyzed', 'how analyze url'],
        "response": "The scanner analyzes 5 main categories of features: 1) Lexical traits (like URL length, special characters, digit ratios). 2) Web security headers (checking CSP, X-Frame, HSTS, SSL). 3) Phishing heuristics (spotting deceptive keywords or suspicious TLDs). 4) Entropy (measuring the randomness of characters, which often indicates obfuscation). 5) Structural ratios (like vowel-to-consonant ratios or external link counts).",
        "suggestions": ["What is entropy?", "What is brand hijacking?"]
    },
    {
        "category": "tips",
        "triggers": ['tips', 'stay safe', 'online safety', 'protect myself', 'best practice', 'safety tips'],
        "response": "Here are 7 essential online safety tips: 1) Always hover over links before clicking. 2) Start using a reputable password manager. 3) Enable 2FA (Two-Factor Authentication) everywhere. 4) Double-check the exact sender email address, not just the display name. 5) Never enter credentials directly from an email link—navigate there manually. 6) Use tools like this scanner to analyze suspicious links. 7) Keep your browser and OS fully updated.",
        "suggestions": ["What is phishing?", "How to check a URL?"]
    },
    {
        "category": "greeting",
        "triggers": ['hi', 'hello', 'hey', 'good morning', 'good afternoon', 'help'],
        "response": "Hello there! I am your friendly cybersecurity awareness bot, here to help you identify online threats and understand how our ML URL scanner works. What would you like to know today?",
        "suggestions": ["What is phishing?", "How to check if a URL is safe?", "Give me online safety tips"]
    }
]

FALLBACK = {
    "category": "fallback",
    "response": "I'm sorry, I don't quite understand that. I specialize in answering questions about phishing, URL safety, and how our machine learning models work. Could you please rephrase, or pick one of these starting topics?",
    "suggestions": ["What is phishing?", "How to spot a phishing URL?", "How does this tool work?"]
}

def get_response(user_message: str) -> dict:
    if not user_message:
        return FALLBACK.copy()

    msg = user_message.lower().strip()

    for rule in RULES:
        for trigger in rule["triggers"]:
            if trigger in msg:
                return {
                    "response": rule["response"],
                    "category": rule["category"],
                    "suggestions": list(rule["suggestions"])
                }

    return FALLBACK.copy()

if __name__ == "__main__":
    # Test script directly
    tests = ["What is phishing?", "Explain machine learning", "show me", "not working", "accuracy", "how accurate", "false positive", "Random unknown query"]
    for t in tests:
        res = get_response(t)
        print(f"User: {t}\nBot ({res['category']}): {res['response'][:80]}...\nSuggestions: {res['suggestions']}\n")
