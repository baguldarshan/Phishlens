# 🔎 PhishLens

**PhishLens** is an educational, explainable phishing URL detection web application. It analyzes URL text using transparent, weighted heuristic rules and explains the indicators that influence the result.

🌐 **Live Demo:** https://phishlens-chi.vercel.app/  
📦 **GitHub Repository:** https://github.com/baguldarshan/Phishlens

> **Disclaimer:** PhishLens is a learning and awareness tool, not a guarantee of website safety. A low-risk result does not prove that a URL is safe.

## ✨ Features

- **URL Risk Scoring:** Calculates a risk score from 0–100.
- **Explainable Results:** Shows the indicators contributing to each result.
- **Risk Classification:** Classifies results as Low, Medium, High, or Invalid.
- **Heuristic Analysis:** Checks suspicious URL patterns, including IP-based hosts, unusual ports, excessive subdomains, punycode, phishing-related keywords, URL shorteners, and obfuscation.
- **Responsive Dashboard:** Provides a web interface for desktop and mobile screens.
- **Scan History:** Stores recent scans in browser localStorage, with export and clear options.
- **Security-Conscious Design:** Analyzes URL text without visiting or resolving submitted URLs.

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| Detection | Weighted heuristic rules |
| Testing | pytest |
| Deployment | Vercel |

## 🌐 Live Demo

Try the application here:

**https://phishlens-chi.vercel.app/**

Enter a URL to view its risk score, classification, and detected indicators.

## 💻 Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/baguldarshan/Phishlens.git
cd Phishlens
```

### 2. Create a Virtual Environment

**Windows PowerShell:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

Open the application at:

`http://127.0.0.1:5000`

## 🔌 API Endpoints

### Health Check

**Endpoint:** `GET /api/health`

Example response:

```json
{
  "status": "ok",
  "service": "PhishLens"
}
```

### Analyze a URL

**Endpoint:** `POST /api/analyze`

Example request:

```json
{
  "url": "https://example.com/login"
}
```

The endpoint returns a JSON analysis result containing the assessment information. Invalid input may return an appropriate HTTP error status.

## 🧪 Run Tests

Install the project dependencies, then execute:

```bash
pytest -q
```

## 📁 Project Structure

```text
Phishlens/
├── app.py
├── config.py
├── requirements.txt
├── core/
│   ├── __init__.py
│   ├── constants.py
│   ├── parser.py
│   ├── rules.py
│   └── analyzer.py
├── templates/
│   ├── base.html
│   └── index.html
├── static/
│   ├── css/
│   │   └── dashboard.css
│   └── js/
│       ├── app.js
│       └── storage.js
├── tests/
└── README.md
```

## 📊 Risk Score Guide

| Score | Classification |
|---|---|
| 0–25 | Low |
| 26–60 | Medium |
| 61–100 | High |
| — | Invalid URL or input |

The score represents detected URL patterns, not the probability that a URL is malicious. Heuristic systems can produce false positives and false negatives.

## 🔐 Privacy and Safety

- PhishLens analyzes submitted URLs as text.
- It does not visit, resolve, redirect to, or embed submitted URLs during analysis.
- Scan history is stored in browser localStorage rather than a server-side user account.
- Other people using the same browser profile may be able to access the saved history.
- Do not rely on this tool as a replacement for browser protections or professional security analysis.

## 🎓 Project Purpose

PhishLens is an **Intelligent Systems mini-project** demonstrating explainable rule-based classification, URL feature extraction, web development, and cybersecurity awareness.

## 📄 License

No license has been specified yet. Unless a license is added, standard copyright restrictions apply.
