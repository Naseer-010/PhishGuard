# Deep Risk Model (No VirusTotal)

This model is for deep analysis when user clicks **Analyze Deeply**.

## What it does
- Trains URL ML model from `data/phishing.csv` (Random Forest).
- Extracts 30 phishing URL features from raw URL.
- Scrapes the website and evaluates deep criteria.
- Performs infrastructure checks (DNS, HTTPS, SSL certificate, suspicious TLD, IP host).
- Returns full deep report + final risk score.

## Train URL model
```bash
python3 models/deep_risk_model/train_url_model.py
```

Artifacts are stored in:
- `models/deep_risk_model/artifacts/url_rf.joblib`
- `models/deep_risk_model/artifacts/metrics.json`

## Run deep analysis
```bash
python3 models/deep_risk_model/run_deep_model.py --url "https://example.com"
```

## Scoring criteria used
- URL ML score from phishing.csv
- URL heuristic score from feature flags
- Content risk score from forms/scripts/keywords
- Infrastructure risk score from protocol + DNS + SSL checks

No VirusTotal API is used.
