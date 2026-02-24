# PhishGaurd

**SIH Problem Statement ID:** `SIH25159`  
**Theme:** Cybersecurity  
**Title:** Real-Time AI/ML-Based Phishing Detection and Prevention System

PishGuard is an AI/ML-driven cybersecurity system designed to detect and prevent phishing attempts in real time. The platform analyzes URLs, webpage signals, content patterns, and behavioral indicators to classify threats and protect users before they interact with malicious resources.

## Problem Overview

Phishing remains one of the most common cyberattack vectors, targeting users through fake links, spoofed websites, and deceptive content. Traditional blacklist-based systems often miss newly generated (zero-day) phishing domains.

PishGuard addresses this challenge with intelligent detection that can generalize beyond known malicious domains.

## Objectives

- Build a robust ML-based phishing detection engine.
- Enable low-latency (real-time) risk scoring for suspicious links/content.
- Support prevention workflows such as user alerts and blocking recommendations.
- Reduce false positives while maintaining strong detection recall.

## Key Features

- **Real-time detection pipeline** for phishing risk analysis.
- **AI/ML classification** for malicious vs. legitimate resources.
- **Feature-driven analysis** including URL, domain, and content-based signals.
- **Extensible architecture** for future browser/email/security integrations.
- **Explainable outputs** (risk score + classification rationale) for trust and auditing.

## High-Level Architecture

1. **Input Layer**
   - URL/text/content input from user or security workflow.
2. **Preprocessing Layer**
   - Normalization, feature extraction, encoding.
3. **ML Inference Layer**
   - Trained phishing detection model predicts risk class/score.
4. **Decision Layer**
   - Action policy: allow, warn, or block.
5. **Monitoring & Feedback**
   - Logging and dataset feedback loop for continuous improvement.

## Tech Stack (Planned/Typical)

- **Language:** Python
- **ML/Data:** scikit-learn, pandas, NumPy
- **Modeling Support:** XGBoost / LightGBM (optional)
- **API/Serving:** FastAPI or Flask
- **Deployment:** Docker / Cloud VM / Edge integration

## Project Structure

```text
PishGaurd/
├── README.md
├── data/                  # Raw and processed datasets
├── notebooks/             # EDA and experimentation
├── src/
│   ├── preprocessing/     # Feature engineering and cleaning
│   ├── models/            # Training, evaluation, inference
│   ├── api/               # Real-time serving endpoints
│   └── utils/             # Shared utilities
├── tests/                 # Unit/integration tests
└── requirements.txt       # Python dependencies
```

> Note: Some folders are planned as part of ongoing development.

## Setup

```bash
git clone <repository-url>
cd PishGaurd
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage (Target Flow)

1. Train or load the phishing detection model.
2. Start the inference service/API.
3. Submit a URL or text payload for classification.
4. Receive a prediction (`phishing` / `legitimate`) and risk score.

## Evaluation Metrics

- Accuracy
- Precision
- Recall
- F1-Score
- ROC-AUC
- Inference latency (for real-time constraints)

## Future Scope

- Browser extension for live protection.
- Email/SMS phishing detection module.
- Threat intelligence feed integration.
- Online learning from analyst feedback.
- Multilingual phishing content detection.

## Impact

PishGuard aims to strengthen proactive cyber defense by combining ML intelligence with real-time intervention, helping individuals and organizations reduce successful phishing incidents.

## Contributors

Add team member names, roles, and contact details here.

## License

Specify project license (e.g., MIT) here.
