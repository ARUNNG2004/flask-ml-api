"""
feature_extractor.py
Extracts all 49 features matching feature_columns.json exactly.
Two modes:
  - extract_features_fast(url)  — no network, instant
  - extract_features(url)       — includes live web security checks
"""

import re
import math
import socket
from urllib.parse import urlparse, parse_qs

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── constants ─────────────────────────────────────────────────────────────────

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'is.gd', 'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc',
    'lnkd.in', 'adf.ly', 'bc.vc', 'trib.al', 'dlvr.it',
    'soo.gd', 'clck.ru', 'vzturl.com', 'qr.ae', 'po.st',
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.info',
    '.biz', '.ru', '.pw', '.cc', '.su', '.ws', '.rest',
}

BRANDS = [
    'paypal', 'amazon', 'google', 'apple', 'microsoft',
    'facebook', 'netflix', 'bankofamerica', 'wellsfargo',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'ebay',
    'paytm', 'hdfc', 'icici', 'sbi', 'yahoo',
]

URGENCY_WORDS = [
    'verify', 'urgent', 'account', 'suspended', 'confirm',
    'login', 'update', 'click', 'expire', 'warning',
    'immediately', 'reset', 'alert', 'validate', 'required',
    'action', 'limited', 'unusual', 'unauthorized', 'blocked',
]

SECURITY_WORDS = [
    'secure', 'security', 'safe', 'protected', 'trust',
    'ssl', 'encrypted', 'official', 'genuine', 'authentic',
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _ngram_entropy(s: str, n: int = 3) -> float:
    if len(s) < n:
        return 0.0
    ngrams = [s[i:i + n] for i in range(len(s) - n + 1)]
    return _shannon_entropy(''.join(ngrams))


def _tokenize(url: str):
    return [t for t in re.split(r'[/.\-_?=&#+%@!]', url) if t]


def _is_ip(host: str) -> bool:
    ip4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ip6 = re.compile(r'^\[?[0-9a-fA-F:]+\]?$')
    return bool(ip4.match(host) or ip6.match(host))


# ── core lexical extractor (no network) ───────────────────────────────────────

def _lexical_features(url: str) -> dict:
    parsed = urlparse(url if '://' in url else 'http://' + url)
    host = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    url_lower = url.lower()

    # ── basic counts ──────────────────────────────────────────────────────────
    f = {
        'url_len':           len(url),
        '@':                 url.count('@'),
        '?':                 url.count('?'),
        '-':                 url.count('-'),
        '=':                 url.count('='),
        '.':                 url.count('.'),
        '#':                 url.count('#'),
        '%':                 url.count('%'),
        '+':                 url.count('+'),
        '$':                 url.count('$'),
        '!':                 url.count('!'),
        '*':                 url.count('*'),
        ',':                 url.count(','),
        '//':                url.count('//'),
        'digits':            sum(c.isdigit() for c in url),
        'letters':           sum(c.isalpha() for c in url),
        'https':             1 if url_lower.startswith('https://') else 0,
    }

    # ── binary heuristics ─────────────────────────────────────────────────────
    # abnormal_url: host not found in url path/query
    f['abnormal_url'] = 0 if host and host in (path + query) else 1 if host else 0

    # IP address as host
    f['having_ip_address'] = 1 if _is_ip(host) else 0

    # URL shortener
    registered = '.'.join(host.split('.')[-2:]) if host.count('.') >= 1 else host
    f['Shortining_Service'] = 1 if registered in SHORTENER_DOMAINS else 0

    # ── subdomains ────────────────────────────────────────────────────────────
    parts = host.split('.') if host else []
    # subdomains = everything except last two parts (domain + TLD)
    subdomains = parts[:-2] if len(parts) > 2 else []
    f['subdomain_count']  = len(subdomains)
    f['avg_subdomain_len'] = (
        sum(len(s) for s in subdomains) / len(subdomains) if subdomains else 0.0
    )

    # ── tokens ────────────────────────────────────────────────────────────────
    tokens = _tokenize(url)
    f['token_count']      = len(tokens)
    f['avg_token_length'] = sum(len(t) for t in tokens) / len(tokens) if tokens else 0.0

    # ── path ──────────────────────────────────────────────────────────────────
    path_parts = [p for p in path.split('/') if p]
    f['path_depth']   = len(path_parts)
    f['path_entropy'] = _shannon_entropy(path)

    # ── domain entropy ────────────────────────────────────────────────────────
    f['domain_ngram_entropy'] = _ngram_entropy(host, 3)

    # ── character ratios (over full url) ─────────────────────────────────────
    total = len(url) if url else 1
    alpha = [c for c in url_lower if c.isalpha()]
    vowels = set('aeiou')
    f['vowel_ratio']     = sum(1 for c in alpha if c in vowels)     / total
    f['consonant_ratio'] = sum(1 for c in alpha if c not in vowels) / total
    f['digit_ratio']     = sum(1 for c in url if c.isdigit())       / total

    # ── phishing heuristics ───────────────────────────────────────────────────
    f['phish_urgency_words']   = sum(1 for w in URGENCY_WORDS   if w in url_lower)
    f['phish_security_words']  = sum(1 for w in SECURITY_WORDS  if w in url_lower)
    f['phish_brand_mentions']  = sum(1 for b in BRANDS          if b in url_lower)

    # brand hijack: brand in url but NOT the registered domain
    registered_domain = parts[-2].lower() if len(parts) >= 2 else ''
    brand_in_url = any(b in url_lower for b in BRANDS)
    brand_is_registered = any(registered_domain == b for b in BRANDS)
    f['phish_brand_hijack'] = 1 if (brand_in_url and not brand_is_registered) else 0

    f['phish_multiple_subdomains'] = 1 if f['subdomain_count'] > 3 else 0
    f['phish_long_path']           = 1 if len(path) > 100 else 0
    f['phish_many_params']         = 1 if len(parse_qs(query)) > 4 else 0

    tld = '.' + parts[-1].lower() if parts else ''
    f['phish_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

    # ── web security defaults (will be overwritten in full mode) ─────────────
    f['web_ssl_valid']       = 0
    f['web_csp']             = 0
    f['web_xframe']          = 0
    f['web_hsts']            = 0
    f['web_xcontent']        = 0
    f['web_security_score']  = 0
    f['web_favicon']         = 0
    f['web_ext_ratio']       = 0.0
    f['web_unique_domains']  = 0
    f['web_forms_count']     = 0
    f['web_password_fields'] = 0
    f['web_hidden_inputs']   = 0
    f['web_has_login']       = 0

    return f


# ── web security check (live HTTP) ────────────────────────────────────────────

def _web_features(url: str) -> dict:
    """
    Makes a real HTTP request and extracts security-related features.
    All values default to 0 on any failure.
    """
    defaults = {
        'web_ssl_valid': 0, 'web_csp': 0, 'web_xframe': 0,
        'web_hsts': 0, 'web_xcontent': 0, 'web_security_score': 0,
        'web_favicon': 0, 'web_ext_ratio': 0.0, 'web_unique_domains': 0,
        'web_forms_count': 0, 'web_password_fields': 0,
        'web_hidden_inputs': 0, 'web_has_login': 0,
    }
    try:
        import requests
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse as _up

        fetch_url = url if '://' in url else 'http://' + url
        resp = requests.get(
            fetch_url, timeout=5, verify=False, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; URLScanner/1.0)'}
        )
        headers = resp.headers
        parsed  = _up(resp.url)
        base_domain = parsed.netloc

        f = dict(defaults)

        # SSL valid: final URL must be https
        f['web_ssl_valid'] = 1 if resp.url.startswith('https://') else 0

        # Security headers
        f['web_csp']      = 1 if 'Content-Security-Policy'     in headers else 0
        f['web_xframe']   = 1 if 'X-Frame-Options'             in headers else 0
        f['web_hsts']     = 1 if 'Strict-Transport-Security'   in headers else 0
        f['web_xcontent'] = 1 if 'X-Content-Type-Options'      in headers else 0
        f['web_security_score'] = (
            f['web_ssl_valid'] + f['web_csp'] +
            f['web_xframe'] + f['web_hsts'] + f['web_xcontent']
        )

        # Parse HTML
        soup = BeautifulSoup(resp.text, 'html.parser')

        # Favicon
        favicons = soup.find_all('link', rel=lambda r: r and 'icon' in ' '.join(r).lower())
        f['web_favicon'] = 1 if favicons else 0

        # External links
        all_links = soup.find_all('a', href=True)
        ext_links = [
            a['href'] for a in all_links
            if a['href'].startswith('http') and base_domain not in a['href']
        ]
        total_links = len(all_links)
        f['web_ext_ratio'] = len(ext_links) / total_links if total_links > 0 else 0.0
        f['web_unique_domains'] = len({
            _up(lnk).netloc for lnk in ext_links if _up(lnk).netloc
        })

        # Forms & inputs
        forms = soup.find_all('form')
        f['web_forms_count']     = len(forms)
        f['web_password_fields'] = len(soup.find_all('input', type='password'))
        f['web_hidden_inputs']   = len(soup.find_all('input', type='hidden'))

        # Login heuristic
        login_inputs = soup.find_all('input', type=lambda t: t and t.lower() in ['email', 'text'])
        f['web_has_login'] = 1 if (f['web_password_fields'] > 0 or len(login_inputs) > 0) else 0

        return f

    except Exception:
        return defaults


# ── public API ────────────────────────────────────────────────────────────────

def extract_features_fast(url: str) -> dict:
    """
    Instant feature extraction — lexical features only, no network calls.
    All web_* features are set to 0.
    """
    return _lexical_features(url)


def extract_features(url: str) -> dict:
    """
    Full feature extraction — lexical + live web security check.
    Web check has a 5-second timeout; on failure web_* features fall back to 0.
    """
    features = _lexical_features(url)
    web = _web_features(url)
    features.update(web)
    return features


# ── quick smoke test ──────────────────────────────────────────────────────────

if __name__ == '__main__':
    test_urls = [
        'https://www.google.com',
        'https://www.amazon.in',
        'http://amaz0n-login-security.com',
        'http://paytm-verify-account.xyz',
        'http://faceb00k-authentication.net',
        'http://secure-bank-login.freehost.ru',
        'http://bit.ly/urgent-login-reset',
        'http://192.168.1.1/phishing/login.php?verify=true&account=suspend',
        'http://paypal.verify-account-login.tk/secure/update',
    ]

    key_features = [
        'url_len', 'https', 'having_ip_address', 'Shortining_Service',
        'phish_brand_hijack', 'phish_suspicious_tld', 'phish_urgency_words',
        'phish_brand_mentions', 'subdomain_count', 'domain_ngram_entropy',
    ]

    print(f"\n{'URL':<55} | " + " | ".join(f"{k[:12]:<12}" for k in key_features))
    print('-' * (55 + 3 + len(key_features) * 15))

    for u in test_urls:
        feats = extract_features_fast(u)
        vals  = " | ".join(f"{str(feats.get(k, '?')):<12}" for k in key_features)
        print(f"{u[:54]:<55} | {vals}")