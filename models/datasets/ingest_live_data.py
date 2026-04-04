"""
End-to-End Live Dataset Ingestion Pipeline.
Downloads live phishing feeds, benign URLs, scrapes HTML, and builds training manifests.
"""

import csv
import hashlib
import os
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# --- Configuration ---
ROOT = Path(__file__).resolve().parents[2]
RAW_HTML_DIR = ROOT / "data" / "raw" / "html"
FEED_DIR = ROOT / "data" / "raw" / "feeds"
MANIFEST_DIR = ROOT / "data" / "manifests"

QUICK_MANIFEST = MANIFEST_DIR / "quick_samples.csv"
DEEP_MANIFEST = MANIFEST_DIR / "deep_samples.csv"

# Feed URLs
OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Standard safe domains for benign dataset (Top Tranco/Alexa subset)
BENIGN_DOMAINS = [
    "https://www.google.com", "https://www.youtube.com", "https://www.wikipedia.org",
    "https://www.github.com", "https://www.microsoft.com", "https://www.apple.com",
    "https://www.reddit.com", "https://www.amazon.com", "https://www.mozilla.org",
    "https://www.ubuntu.com", "https://www.python.org", "https://www.cloudflare.com",
    "https://www.bbc.com", "https://www.nytimes.com", "https://www.stackoverflow.com"
]

TIMEOUT = 8
SAMPLES_PER_CLASS = 200  # Adjust this to 1000+ for actual production training

# --- Ensure Directories Exist ---
for directory in [RAW_HTML_DIR, FEED_DIR, MANIFEST_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

def fetch_phishing_feeds() -> list[str]:
    """Downloads OpenPhish and URLhaus feeds, saves them, and returns a list of URLs."""
    urls = set()
    print("Fetching OpenPhish feed...")
    try:
        r = requests.get(OPENPHISH_URL, timeout=10)
        if r.status_code == 200:
            feed_path = FEED_DIR / "openphish.txt"
            feed_path.write_text(r.text)
            urls.update([line.strip() for line in r.text.split('\n') if line.strip().startswith('http')])
    except Exception as e:
        print(f"Failed to fetch OpenPhish: {e}")

    # For URLHaus, we'll extract the URLs from the CSV format
    print("Fetching URLhaus feed...")
    try:
        r = requests.get(URLHAUS_URL, timeout=10)
        if r.status_code == 200:
            feed_path = FEED_DIR / "urlhaus.csv"
            feed_path.write_text(r.text)
            for line in r.text.split('\n'):
                if not line.startswith('#') and 'http' in line:
                    parts = line.split('","')
                    if len(parts) > 2:
                        urls.add(parts[2].strip('"'))
    except Exception as e:
        print(f"Failed to fetch URLhaus: {e}")
        
    return list(urls)

def fetch_and_save_html(url: str, label: int) -> dict:
    """Scrapes HTML safely, ignores dead links, and returns manifest row."""
    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
    html_path = RAW_HTML_DIR / f"{url_hash}.html"
    
    row = {
        "sample_id": url_hash,
        "url": url,
        "label": label,
        "html_path": f"data/raw/html/{url_hash}.html",
        "final_url": url,
        "label_source": "openphish_urlhaus" if label == 1 else "tranco_top",
        "status_code": None,
        "redirect_count": 0,
        "network_path": ""  # Leave blank to force Deep Model to live-resolve infrastructure
    }

    if html_path.exists():
        row["status_code"] = 200
        return row

    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        
        row["status_code"] = response.status_code
        row["final_url"] = response.url
        row["redirect_count"] = len(response.history)

        # Only save if we successfully got HTML content
        if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(response.text)
            return row
            
    except requests.RequestException:
        pass # Silently drop dead/offline phishing links

    return None

def process_urls_concurrently(urls: list[str], label: int, max_workers: int = 15) -> list[dict]:
    """Uses thread pool to fetch HTML concurrently."""
    valid_rows = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch_and_save_html, url, label): url for url in urls}
        
        for future in tqdm(as_completed(future_to_url), total=len(urls), desc=f"Scraping Label {label}"):
            result = future.result()
            if result:
                valid_rows.append(result)
                if len(valid_rows) >= SAMPLES_PER_CLASS:
                    break # Stop once we hit our target sample size
                    
    return valid_rows

def main():
    print("--- Phase 1: Acquiring Live URLs ---")
    phishing_urls = fetch_phishing_feeds()
    print(f"Loaded {len(phishing_urls)} potential phishing URLs from feeds.")
    
    # We will just duplicate/crawl the benign domains slightly for scale if needed, 
    # but for a quick dataset, the base list + subpaths work.
    benign_urls = BENIGN_DOMAINS * 15 # Quick hack to give the scraper enough benign targets to hit the sample cap

    print("\n--- Phase 2: Scraping HTML Content ---")
    print("Note: Phishing links frequently go offline. We are heavily filtering for live HTML only.")
    manifest_rows = []
    
    # Fetch Phishing (Label 1)
    manifest_rows.extend(process_urls_concurrently(phishing_urls, label=1))
    # Fetch Benign (Label 0)
    manifest_rows.extend(process_urls_concurrently(benign_urls, label=0))

    if not manifest_rows:
        print("Failed to scrape any live data. Check network connection.")
        return

    print("\n--- Phase 3: Writing Manifests ---")
    keys = manifest_rows[0].keys()
    
    # Write Quick Manifest
    with open(QUICK_MANIFEST, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[k for k in keys if k != "network_path"])
        writer.writeheader()
        writer.writerows([{k: v for k, v in row.items() if k != "network_path"} for row in manifest_rows])
        
    # Write Deep Manifest
    with open(DEEP_MANIFEST, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(manifest_rows)

    print(f"\nSuccess! Datasets built with {len(manifest_rows)} live HTML samples.")
    print(f"Deep feeds saved to: {FEED_DIR}")
    print(f"HTML saved to: {RAW_HTML_DIR}")
    print("\nYou can now proceed with training.")

if __name__ == "__main__":
    main()
