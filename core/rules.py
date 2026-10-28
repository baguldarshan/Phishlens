import re
from dataclasses import dataclass

from .constants import (
    BRAND_DOMAINS, BRAND_TERMS, PHISHING_TERMS, RULE_WEIGHTS, SHORTENERS,
    SUSPICIOUS_TLDS,
)


@dataclass(frozen=True)
class RuleResult:
    key: str
    name: str
    category: str
    severity: str
    triggered: bool
    weight: int
    explanation: str

    def as_dict(self):
        return self.__dict__.copy()


def evaluate_rules(features: dict) -> list[RuleResult]:
    host = features["hostname"]
    text = f'{host}{features["path"]}'.lower()
    path = features["path"].lower()
    domain = features["registered_domain"]
    brand = next((term for term in BRAND_TERMS if term in host), None)
    brand_impersonation = bool(brand and domain not in BRAND_DOMAINS[brand])
    checks = [
        ("ip_hostname", "IP address hostname", "Host", "high", features["is_ip_hostname"],
         "The hostname is a numeric IP address rather than a recognizable domain."),
        ("userinfo", "Embedded user information", "Structure", "high", features["has_userinfo"],
         "User information appears before the hostname and can disguise the true destination."),
        ("unusual_port", "Unusual network port", "Network", "medium",
         bool(features["port"] and features["port"] not in {80, 443}),
         "The URL specifies a non-standard HTTP(S) port."),
        ("long_url", "Unusually long URL", "Structure", "medium", features["url_length"] > 150,
         "Long URLs can hide important destination details."),
        ("many_subdomains", "Excessive subdomains", "Domain", "medium",
         len(features["subdomain"].split(".")) >= 3,
         "Several subdomain levels make the destination harder to read."),
        ("hostname_hyphens", "Multiple hostname hyphens", "Domain", "low",
         host.count("-") >= 2, "Multiple hyphens can be used in lookalike domains."),
        ("punycode", "Punycode hostname", "Domain", "high", "xn--" in host,
         "Internationalized hostname encoding can conceal lookalike characters."),
        ("suspicious_tld", "Uncommon top-level domain", "Domain", "medium",
         features["top_level_domain"] in SUSPICIOUS_TLDS,
         "This top-level domain is frequently seen in disposable or deceptive links."),
        ("brand_impersonation", "Possible brand impersonation", "Identity", "high",
         brand_impersonation,
         f"The hostname contains {brand.title()} but is not a known {brand.title()} domain."
         if brand else "The hostname resembles a known brand without matching its registered domain."),
        ("phishing_terms", "Phishing-related language", "Content", "medium",
         bool(set(re.findall(r"[a-z0-9]+", text)) & PHISHING_TERMS),
         "The hostname or path includes language commonly used in credential lures."),
        ("encoded_obfuscation", "Encoded or obfuscated URL", "Structure", "medium",
         bool(features["has_percent_encoding"] and len(re.findall("%[0-9a-fA-F]{2}", features["original_url"])) >= 3),
         "Repeated percent-encoding makes the destination harder to inspect."),
        ("misleading_slashes", "Misleading slash structure", "Structure", "medium",
         bool(re.search(r"https?://[^/]+//", features["original_url"])),
         "Extra slash structures may visually separate a hostname from the intended path."),
        ("shortener", "URL shortening service", "Reputation", "medium",
         domain in SHORTENERS or host in SHORTENERS,
         "The short link hides the final destination until it is opened."),
        ("http_scheme", "Unencrypted HTTP", "Transport", "low", features["scheme"] == "http",
         "HTTP does not encrypt data in transit; HTTPS is preferable for sensitive actions."),
        ("executable_extension", "Executable or application path", "Content", "medium",
         bool(re.search(r"\.(exe|scr|apk|dmg|msi)(?:$|[?#])", path)),
         "The path ends with a file type that can deliver executable content."),
    ]
    return [RuleResult(key, name, category, severity, bool(triggered),
                       RULE_WEIGHTS[key], explanation) for
            key, name, category, severity, triggered, explanation in checks]
