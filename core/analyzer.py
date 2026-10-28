from .constants import CLASSIFICATION_THRESHOLDS
from .parser import URLParseError, parse_url
from .rules import evaluate_rules


DISCLAIMER = (
    "PhishLens provides a preliminary risk assessment based on URL structure and "
    "heuristic rules. A low-risk result does not guarantee that a website is safe."
)


def analyze_url(value: str) -> dict:
    try:
        features = parse_url(value)
    except URLParseError as exc:
        return {
            "status": "invalid", "submitted_url": value if isinstance(value, str) else "",
            "score": 0, "classification": "Invalid", "summary": str(exc),
            "recommendation": "Check the URL and try again.", "triggered_rule_count": 0,
            "total_rule_count": 0, "rules": [], "features": None, "disclaimer": DISCLAIMER,
        }
    rules = evaluate_rules(features)
    triggered = [rule for rule in rules if rule.triggered]
    score = min(100, sum(rule.weight for rule in triggered))
    if score <= CLASSIFICATION_THRESHOLDS["low"]:
        classification = "Low"
        recommendation = "No major structural warning signs were found, but verify the domain before sharing sensitive information."
    elif score <= CLASSIFICATION_THRESHOLDS["medium"]:
        classification = "Medium"
        recommendation = "Review the highlighted characteristics carefully before interacting with this URL."
    else:
        classification = "High"
        recommendation = "Multiple suspicious URL characteristics were detected. Avoid visiting this URL or entering sensitive information."
    summary = f"{len(triggered)} of {len(rules)} heuristic rules were triggered."
    return {
        "status": "ok", "submitted_url": features["original_url"],
        "normalized_url": features["normalized_url"], "score": score,
        "classification": classification, "summary": summary,
        "recommendation": recommendation, "triggered_rule_count": len(triggered),
        "total_rule_count": len(rules), "rules": [rule.as_dict() for rule in rules],
        "features": features, "disclaimer": DISCLAIMER,
    }
