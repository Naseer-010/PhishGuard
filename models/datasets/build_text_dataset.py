"""Extract raw visible text from scraped HTML to train TF-IDF and DistilBERT models."""

import csv
import json
import argparse
import re
from pathlib import Path
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_DIR = ROOT / "data" / "manifests"
PROCESSED_DIR = ROOT / "data" / "processed"

# The expanded, ultra-aggressive kill list for dead/parked/blocked pages
ERROR_SIGNATURES = [
    "404 not found",
    "403 forbidden",
    "406 not acceptable",
    "500 internal server error",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "the requested url was not found",
    "the requested url could not be retrieved",
    "account suspended",
    "this account has been suspended",
    "domain has expired",
    "this site can’t be reached",
    "apache2 ubuntu default page",
    "welcome to nginx",
    "cloudflare",
    "attention required!",
    "one more step",
    "please enable cookies",
    "access denied",
    "server error",
    "index of /",
    "directory listing for",
    "domain parking",
    "this domain is available",
    "this domain is registered",
    "parking page",
    "page not found",
    "web server is down",
    "default web page",
    "cgi-sys/defaultwebpage"
]

def is_valid_page(text: str) -> bool:
    """Checks if the extracted text is actually a webpage and not an error/block page."""
    text_lower = text.lower()
    
    # 1. Drop pages with too little text (useless for DistilBERT anyway)
    # A real phishing page needs enough text to trick a user.
    if len(text.strip()) < 100:
        return False
        
    # 2. Check for the expanded known error signatures
    for signature in ERROR_SIGNATURES:
        if signature in text_lower:
            return False
            
    # 3. Check for pages that are literally just repeating "Not Found"
    # Sometimes servers just spit out "Not Found Not Found"
    if text_lower.count("not found") > 2 and len(text.strip()) < 300:
        return False
            
    return True

def extract_visible_text(html_content: str) -> str:
    """Strips tags, removes massive whitespace, and returns clean visible text."""
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Destroy elements that don't contribute to human-readable text
        for element in soup(["script", "style", "noscript", "meta", "head", "input", "svg", "button"]):
            element.decompose()
            
        text = soup.get_text(separator=" ", strip=True)
        
        # Clean up massive gaps of whitespace/newlines that some scrapers leave behind
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text[:5000] 
    except Exception:
        return ""

def build_text_dataset(manifest_path: Path, output_path: Path):
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    rows = []
    dropped_count = 0
    
    with open(manifest_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("html_path"):
                continue
                
            html_file = ROOT / "data" / "raw" / "html" / Path(row["html_path"]).name
            
            if html_file.exists():
                with open(html_file, "r", encoding="utf-8", errors="ignore") as hf:
                    text = extract_visible_text(hf.read())
                    
                    if is_valid_page(text):
                        rows.append({
                            "sample_id": row["sample_id"],
                            "domain_group": row.get("url", "").split("/")[2] if "//" in row.get("url", "") else row.get("url", ""),
                            "text": text,
                            "label": row["label"]
                        })
                    else:
                        dropped_count += 1

    if not rows:
        raise ValueError("No valid text extracted. All pages were filtered out as errors.")

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "domain_group", "text", "label"])
        writer.writeheader()
        writer.writerows(rows)
        
    return len(rows), dropped_count

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(MANIFEST_DIR / "deep_samples.csv"))
    parser.add_argument("--output", default=str(PROCESSED_DIR / "deep_text.csv"))
    args = parser.parse_args()
    
    valid_count, dropped = build_text_dataset(Path(args.manifest), Path(args.output))
    
    print("\n--- Aggressive Text Extraction Complete ---")
    print(f"Clean samples saved for NLP: {valid_count}")
    print(f"Junk/Error pages dropped: {dropped}")
    print(f"Output saved to: {args.output}")

if __name__ == "__main__":
    main()
