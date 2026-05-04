URL Threat Scanner - Beginner Guide

What this implementation now includes:
1) Secure URL validation + redirect gate
2) Selenium-based reachability + DOM extraction
3) Domain host metadata extraction (DNS + WHOIS when available)
4) ML-based phishing inference (model bundle)
6) API endpoint: POST /api/scan

Main routes:
- /                  Main scanner UI
- /api/scan          Canonical JSON scan API

Requirements:
- Python 3.10+
- Google Chrome or Firefox installed

First-time setup:
1) python3 -m venv .venv
2) source .venv/bin/activate            (Windows: .venv\Scripts\activate)
3) pip install -r requirements.txt

Train model bundle (required once):
1) python train_model.py --dataset ./phishing.csv
2) This creates:
   - artifacts/phishing_model_bundle.pkl
   - EVIDENCE_PACK.md

Run app:
1) python app.py
2) Open http://127.0.0.1:5000

API scan example:
POST /api/scan
Body: {"url": "https://example.com"}
Response keys:
- validation
- reachability
- features
- prediction
- confidence
- top_signals
- errors

Run automated tests:
- python -m unittest discover -s tests -v

Run runtime benchmark (for performance evidence):
- python benchmark_scans.py --repeats 1
- Output file: BENCHMARK_REPORT.md

Presentation quick script:
1) test@gmail.com      -> Validation Error
2) localhost           -> Validation Error
3) example.com         -> Full scan (reachability + features + prediction)

If Selenium returns setup_required:
- Ensure Chrome/Firefox exists
- Re-run pip install -r requirements.txt
