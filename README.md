# PhishLens

PhishLens is an educational, explainable phishing URL detection dashboard. It
passively inspects URL text with weighted heuristic rules; it never visits,
resolves, redirects to, or embeds submitted URLs.

## Run locally

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. Run the test suite with `pytest`.

## Project structure

- `core/parser.py` extracts URL features with the Python standard library.
- `core/rules.py` evaluates 15 transparent, weighted indicators.
- `core/analyzer.py` aggregates evidence into a 0-100 score and classification.
- `app.py` provides the Flask dashboard and JSON API.
- `static/` and `templates/` contain the responsive dashboard.
- `tests/` covers engine behavior, API schema, and security headers.

Risk thresholds are Low (0-25), Medium (26-60), and High (61-100). A low-risk
result is not proof that a website is safe, and the manually maintained brand
list can produce false positives or negatives. Browser history is kept in
localStorage and may be visible to other users of the browser.
