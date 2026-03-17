# Quick Content Threat Model

This model is for extension-side quick analysis.

## What it does
- Accepts a URL.
- Scrapes page content.
- Counts threat-oriented words vs safe-oriented words.
- Returns `threat_percentage` (0-100).

## Run
```bash
python3 models/quick_content_model/run_quick_model.py --url "https://example.com"
```

## Output
JSON with:
- `threat_percentage`
- keyword hit counts
- form/password indicators
- fetch status
