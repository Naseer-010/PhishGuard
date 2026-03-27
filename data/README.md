# Model Data Requirements

This project now supports two model-training manifests:

- `data/manifests/quick_samples.csv`
- `data/manifests/deep_samples.csv`

## Quick Model Manifest

Required columns:

- `sample_id`
- `url`
- `label`
- `html_path`

Optional columns:

- `final_url`
- `label_source`
- `collected_at`
- `status_code`
- `redirect_count`

`label` values accepted:

- `1`, `phishing`, `malicious`, `dangerous`
- `0`, `legitimate`, `benign`, `safe`

## Deep Model Manifest

Same columns as the quick manifest, plus:

- `network_path` optional JSON path for saved DNS/TLS/reputation snapshots

If `network_path` is missing, the deep dataset builder derives infrastructure features directly from the URL and local feed snapshots in `data/raw/feeds/`.

## Feed Snapshot Folder

The deep model can enrich training and inference from local feed files stored in:

- `data/raw/feeds/`

Supported formats:

- `.txt` with one URL/domain per line
- `.csv` with `url` and/or `domain`-style columns

Suggested files:

- `openphish.txt`
- `phishtank.csv`
- `urlhaus.csv`

## Build Datasets

```bash
python3 models/datasets/build_quick_dataset.py
python3 models/datasets/build_deep_dataset.py
```

## Train Models

```bash
python3 models/quick_content_model/train_quick_model.py
python3 models/quick_content_model/train_text_tfidf_model.py --dataset data/processed/quick_text.csv
python3 models/quick_content_model/train_distilbert_model.py --dataset data/processed/quick_text.csv
python3 models/deep_risk_model/train_url_model.py
python3 models/deep_risk_model/train_deep_model.py
python3 models/deep_risk_model/train_text_tfidf_model.py --dataset data/processed/deep_text.csv
python3 models/deep_risk_model/train_distilbert_model.py --dataset data/processed/deep_text.csv
```

Text-model datasets should contain at least:

- `text`
- `label`

Recommended optional column:

- `domain_group`
