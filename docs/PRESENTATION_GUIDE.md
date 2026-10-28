# Demonstration guide

1. Start the Flask server and show the clean dashboard.
2. Analyze `https://www.google.com` to show a low-risk result and the evaluated
   rules.
3. Analyze `http://paypal-login.verify-user.top/login` to demonstrate brand
   impersonation, phishing language, HTTP, and a suspicious TLD.
4. Open the URL information and rule panels to explain feature extraction and
   weighted evidence aggregation.
5. Show history persistence, deletion, and JSON export.
6. Explain that the app performs a passive textual scan and makes no outbound
   request to the submitted URL.

## Viva talking points

- The rules are interpretable and each triggered rule supplies an explanation.
- A score is an aggregate heuristic score, not a probability.
- A legitimate domain can still be compromised, and suspicious-looking URL
  features can occur on legitimate sites.
- Future work includes larger labeled evaluation sets, false-positive analysis,
  internationalized-domain improvements, and optional trusted intelligence
  integrations.
