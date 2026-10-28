# Architecture

The application has three layers:

1. **Parsing** — `core.parser.parse_url` normalizes a submitted HTTP(S) URL and
   extracts hostname, domain, port, path, query count, user information,
   encoding, and IP indicators. It performs no network operation.
2. **Rules** — `core.rules.evaluate_rules` evaluates 15 independent rules.
   Every result includes a key, category, severity, weight, trigger state, and
   explanation.
3. **Decision** — `core.analyzer.analyze_url` sums triggered weights, caps the
   result at 100, assigns a stable threshold classification, and returns the
   complete explanation to the frontend.

The Flask layer validates JSON and size limits and adds restrictive security
headers. The frontend renders API data as text and stores only a 20-item
summary history in browser localStorage. It never navigates to submitted URLs.

The system is intentionally heuristic rather than a trained or calibrated
machine-learning model. It should be evaluated with a labeled dataset before
being used for any operational security decision.
