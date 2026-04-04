import requests
import pandas as pd
from tqdm import tqdm

OUTPUT_FILE = "data/manifests/quick_samples.csv"


def fetch_html(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, timeout=5, headers=headers)
        if r.status_code == 200:
            return r.text
    except:
        return None


def build_dataset(urls, label):
    rows = []

    for url in tqdm(urls):
        html = fetch_html(url)

        if html is None:
            continue

        rows.append({
            "url": url,
            "label": label,
            "html": html   # STORE HTML DIRECTLY
        })

    return rows


# Load URLs
phishing_urls = pd.read_csv("data/phishing.csv")["url"].tolist()
legit_urls = pd.read_csv("data/legit.csv")["url"].tolist()

rows = []
rows += build_dataset(phishing_urls, 1)
rows += build_dataset(legit_urls, 0)

pd.DataFrame(rows).to_csv(OUTPUT_FILE, index=False)

print("Dataset created")