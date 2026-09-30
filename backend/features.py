import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cli.gs",
    "yfrog.com", "ow.ly", "bit.do", "tiny.cc", "cutt.ly", "shorte.st"
}

SUSPICIOUS_WORDS = [
    "secure", "account", "update", "banking", "login", "verify",
    "signin", "webscr", "ebayisapi", "cmd", "confirm", "password",
    "credential", "suspend", "recover", "authenticate"
]

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_slashes",
    "count_question_marks",
    "count_equal_signs",
    "count_at_symbols",
    "count_digits",
    "count_special_chars",
    "is_https",
    "has_ip_address",
    "count_subdomains",
    "has_suspicious_words",
    "is_shortened"
]

def has_ip(hostname: str) -> int:
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    if re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname):
        return 1
    return 0

def extract_features(url: str) -> dict:
    url_clean = str(url).strip()
    
    # Check original scheme
    is_https = 1 if url_clean.lower().startswith("https://") else 0

    if not url_clean.startswith(("http://", "https://")):
        url_to_parse = "http://" + url_clean
    else:
        url_to_parse = url_clean

    parsed = urlparse(url_to_parse)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    url_length = len(url_clean)
    hostname_length = len(hostname)
    path_length = len(path)

    # Subdomain calculation: strip 'www.' so standard root domains are not penalized
    clean_host = hostname[4:] if hostname.startswith("www.") else hostname
    parts = clean_host.split(".")
    count_subdomains = max(0, len(parts) - 2) if len(parts) > 2 else 0

    # Lexical character counts on URL body
    body = re.sub(r"^https?://", "", url_clean, flags=re.IGNORECASE)
    body_clean = body[4:] if body.lower().startswith("www.") else body

    count_dots = body_clean.count(".")
    count_hyphens = body_clean.count("-")
    count_underscores = body_clean.count("_")
    count_slashes = body_clean.count("/")
    count_question_marks = body_clean.count("?")
    count_equal_signs = body_clean.count("=")
    count_at_symbols = body_clean.count("@")
    count_digits = sum(c.isdigit() for c in body_clean)
    count_special_chars = len(re.findall(r"[\$\%\&\*\+\,\;\:\@]", body_clean))

    has_ip_address = has_ip(hostname)

    url_lower = url_clean.lower()
    has_suspicious_words = 1 if any(word in url_lower for word in SUSPICIOUS_WORDS) else 0
    is_shortened = 1 if hostname in SHORTENERS else 0

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_underscores": count_underscores,
        "count_slashes": count_slashes,
        "count_question_marks": count_question_marks,
        "count_equal_signs": count_equal_signs,
        "count_at_symbols": count_at_symbols,
        "count_digits": count_digits,
        "count_special_chars": count_special_chars,
        "is_https": is_https,
        "has_ip_address": has_ip_address,
        "count_subdomains": count_subdomains,
        "has_suspicious_words": has_suspicious_words,
        "is_shortened": is_shortened
    }