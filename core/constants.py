CLASSIFICATION_THRESHOLDS = {"low": 25, "medium": 60}

RULE_WEIGHTS = {
    "ip_hostname": 28,
    "userinfo": 25,
    "unusual_port": 12,
    "long_url": 10,
    "many_subdomains": 10,
    "hostname_hyphens": 7,
    "punycode": 18,
    "suspicious_tld": 13,
    "brand_impersonation": 25,
    "phishing_terms": 14,
    "encoded_obfuscation": 12,
    "misleading_slashes": 10,
    "shortener": 11,
    "http_scheme": 6,
    "executable_extension": 9,
}

SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "work", "country", "gq", "tk", "ml"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"}
BRAND_DOMAINS = {
    "google": {"google.com", "google.co.uk"},
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
}
BRAND_TERMS = tuple(BRAND_DOMAINS)
PHISHING_TERMS = {
    "account", "authenticate", "billing", "confirm", "credential", "invoice",
    "login", "mfa", "password", "payment", "secure", "signin", "unlock", "verify",
}
