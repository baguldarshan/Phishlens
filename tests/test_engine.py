from core.analyzer import analyze_url
from core.parser import URLParseError, parse_url


def test_parser_extracts_features():
    result = parse_url("https://login.example.com:8443/path?a=1")
    assert result["hostname"] == "login.example.com"
    assert result["subdomain"] == "login"
    assert result["port"] == 8443
    assert result["query_parameters"] == 1


def test_ip_and_userinfo_rules_trigger():
    result = analyze_url("http://admin:secret@192.0.2.10:8080/verify")
    keys = {rule["key"] for rule in result["rules"] if rule["triggered"]}
    assert {"ip_hostname", "userinfo", "unusual_port", "http_scheme"} <= keys
    assert result["classification"] == "High"


def test_legitimate_brand_domain_is_not_impersonation():
    result = analyze_url("https://www.paypal.com/signin")
    rule = next(rule for rule in result["rules"] if rule["key"] == "brand_impersonation")
    assert rule["triggered"] is False


def test_brand_impersonation_and_shortener():
    result = analyze_url("https://paypal-login.verify-user.top/login")
    keys = {rule["key"] for rule in result["rules"] if rule["triggered"]}
    assert {"brand_impersonation", "suspicious_tld", "phishing_terms"} <= keys


def test_invalid_port_is_graceful():
    result = analyze_url("https://example.com:bad/")
    assert result["status"] == "invalid"
    assert result["classification"] == "Invalid"


def test_empty_input_is_parse_error():
    try:
        parse_url(" ")
    except URLParseError:
        pass
    else:
        raise AssertionError("Expected URLParseError")
