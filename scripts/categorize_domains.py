#!/usr/bin/env python3
"""Categorize Tranco top-1M domains using Gemini Flash Lite.

Reads top-1m.csv (rank,domain), sends batches to Gemini for categorization,
writes domains_categorized.csv (domain,category). Supports resuming from
a previous partial run.

Usage:
    python3 scripts/categorize_domains.py [--batch-size 200] [--concurrency 20]
    python3 scripts/categorize_domains.py --reprocess-other  # re-categorize "other" entries
"""

import argparse
import asyncio
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API_KEY = os.environ.get("GEMINI_API_KEY", "")
if not API_KEY:
    sys.exit("Error: GEMINI_API_KEY environment variable is required")
MODEL = "gemini-3.1-flash-lite-preview"
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={API_KEY}"

ROOT = Path(__file__).resolve().parent.parent
CATEGORIES_FILE = ROOT / "categories.txt"
CATEGORIES = [line.strip() for line in CATEGORIES_FILE.read_text().splitlines() if line.strip()]

SYSTEM_PROMPT = f"""You are a domain categorizer. For each domain, output ONLY the domain and its category separated by a comma. One per line. No headers, no explanations, no extra text.

Categories: {', '.join(CATEGORIES)}

Rules:
- Use ONLY the categories listed above
- If unsure, use "other"
- CDN, DNS, hosting infrastructure → cdn_infrastructure
- Ad networks, analytics, tracking pixels → advertising_tracking
- VPN, proxy, anonymizer services → vpn_proxy
- Telcos, ISPs, mobile carriers → telecom_isp
- Domain registrars, DNS registries, hosting providers → domain_hosting
- Crypto, blockchain, Web3 RPC providers → crypto_blockchain
- SSL/TLS certificates, CAPTCHAs, fraud prevention → security_pki
- Travel, hotels, rideshare, logistics, shipping → travel_transport
- Job boards, freelance marketplaces → jobs_freelance
- Nonprofits, archives, standards bodies, wikis, weather → reference
- Stock media, document sharing, blogs, CMS, publishing platforms → media_publishing
- Consulting, reviews, crowdfunding, B2B SaaS → business_services
- File hosting, torrents, cloud storage → file_sharing
- URL shorteners, link redirectors → technology
- Output nothing except domain,category lines"""

INPUT_CSV = ROOT / "top-1m.csv"
OUTPUT_CSV = ROOT / "domains_categorized.csv"
PROGRESS_FILE = ROOT / "scripts" / ".categorize_progress"


def load_domains(path: Path) -> list[tuple[int, str]]:
    domains = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                domains.append((int(row[0]), row[1].strip()))
    return domains


def load_categorized_csv() -> tuple[list[dict], list[dict]]:
    """Load existing categorized CSV, split into kept and 'other' rows."""
    kept = []
    others = []
    with open(OUTPUT_CSV, newline="") as f:
        # Handle \r\n line endings
        content = f.read().replace("\r\n", "\n")
        reader = csv.DictReader(content.splitlines())
        for row in reader:
            cat = row["category"].strip()
            if cat == "other":
                others.append(row)
            else:
                kept.append(row)
    return kept, others


def load_progress() -> int:
    """Return the number of domains already categorized."""
    if PROGRESS_FILE.exists():
        return int(PROGRESS_FILE.read_text().strip())
    return 0


def save_progress(n: int):
    PROGRESS_FILE.write_text(str(n))


def build_request_body(domains: list[str]) -> bytes:
    domain_list = "\n".join(domains)
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"{SYSTEM_PROMPT}\n\nCategorize these domains:\n{domain_list}"}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.0,
            "maxOutputTokens": 8192,
        },
    }
    return json.dumps(payload).encode()


def parse_response(text: str, expected_domains: list[str]) -> dict[str, str]:
    """Parse model response into domain -> category mapping."""
    results = {}
    valid_cats = set(CATEGORIES)
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle various formats: "domain,category" or "domain, category"
        parts = [p.strip().lower() for p in line.split(",", 1)]
        if len(parts) == 2:
            domain, cat = parts
            if cat in valid_cats:
                results[domain] = cat
            else:
                results[domain] = "other"

    # Fill in any missing domains
    for d in expected_domains:
        if d.lower() not in results:
            results[d.lower()] = "other"

    return results


async def call_gemini(domains: list[str], semaphore: asyncio.Semaphore, max_retries: int = 3) -> dict[str, str]:
    body = build_request_body(domains)

    for attempt in range(max_retries):
        try:
            async with semaphore:
                resp_text = await asyncio.to_thread(_sync_request, body)
            resp = json.loads(resp_text)

            # Extract text from response
            candidates = resp.get("candidates", [])
            if not candidates:
                error_info = resp.get("error", {})
                if error_info:
                    raise Exception(f"API error: {error_info.get('message', resp_text[:200])}")
                raise Exception(f"No candidates in response: {resp_text[:200]}")

            text = candidates[0]["content"]["parts"][0]["text"]
            return parse_response(text, domains)

        except Exception as e:
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                    wait = 15 * (attempt + 1)  # Back off harder on rate limits
                print(f"  Retry {attempt + 1}/{max_retries} after {wait}s: {e}", file=sys.stderr)
                await asyncio.sleep(wait)
            else:
                print(f"  Failed batch after {max_retries} retries: {e}", file=sys.stderr)
                return {d.lower(): "other" for d in domains}


def _sync_request(body: bytes) -> str:
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode()


async def reprocess_other(batch_size: int, concurrency: int):
    """Re-categorize domains currently marked as 'other'."""
    print(f"Loading {OUTPUT_CSV}...")
    kept, others = load_categorized_csv()
    print(f"  {len(kept):,} already categorized, {len(others):,} marked 'other' to reprocess")

    if not others:
        print("Nothing to reprocess!")
        return

    # Build list of (rank, domain) tuples from "other" rows
    domains_to_process = [(int(row["rank"]), row["domain"]) for row in others]

    semaphore = asyncio.Semaphore(concurrency)
    total = len(domains_to_process)
    processed = 0
    recategorized = 0
    t_start = time.time()

    # Collect results
    updated = {}

    chunk_size = batch_size * concurrency
    for chunk_start in range(0, total, chunk_size):
        chunk = domains_to_process[chunk_start : chunk_start + chunk_size]

        batches = []
        for i in range(0, len(chunk), batch_size):
            batch = chunk[i : i + batch_size]
            batches.append(batch)

        tasks = []
        for batch in batches:
            domain_names = [d[1] for d in batch]
            tasks.append(call_gemini(domain_names, semaphore))

        results = await asyncio.gather(*tasks)

        for batch, result in zip(batches, results):
            for rank, domain in batch:
                cat = result.get(domain.lower(), "other")
                updated[domain.lower()] = cat
                if cat != "other":
                    recategorized += 1
            processed += len(batch)

        elapsed = time.time() - t_start
        rate = processed / elapsed if elapsed > 0 else 0
        pct = (processed / total) * 100
        eta = (total - processed) / rate if rate > 0 else 0
        print(f"  {processed:>8,} / {total:,} ({pct:5.1f}%) | {rate:,.0f} domains/s | ETA {eta/60:.1f}m | {recategorized:,} recategorized")

    # Rebuild the full CSV: kept rows + updated other rows
    print(f"\nWriting updated {OUTPUT_CSV}...")
    all_rows = []
    for row in kept:
        all_rows.append(row)
    for row in others:
        domain = row["domain"]
        new_cat = updated.get(domain.lower(), "other")
        all_rows.append({"domain": domain, "rank": row["rank"], "category": new_cat})

    # Sort by rank
    all_rows.sort(key=lambda r: int(r["rank"]))

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "rank", "category"])
        writer.writeheader()
        writer.writerows(all_rows)

    elapsed = time.time() - t_start
    print(f"Done! {recategorized:,} / {total:,} domains recategorized in {elapsed:.0f}s")
    print(f"Output: {OUTPUT_CSV}")


async def main():
    parser = argparse.ArgumentParser(description="Categorize Tranco top-1M domains")
    parser.add_argument("--batch-size", type=int, default=200, help="Domains per API call")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent API requests")
    parser.add_argument("--limit", type=int, default=0, help="Only process first N domains (0=all)")
    parser.add_argument("--resume", action="store_true", help="Resume from previous run")
    parser.add_argument("--reprocess-other", action="store_true", help="Re-categorize 'other' entries with expanded categories")
    args = parser.parse_args()

    if args.reprocess_other:
        await reprocess_other(args.batch_size, args.concurrency)
        return

    print(f"Loading domains from {INPUT_CSV}...")
    all_domains = load_domains(INPUT_CSV)
    if args.limit > 0:
        all_domains = all_domains[: args.limit]
    print(f"Loaded {len(all_domains):,} domains")

    # Resume support
    start_idx = 0
    if args.resume:
        start_idx = load_progress()
        if start_idx > 0:
            print(f"Resuming from domain #{start_idx:,}")

    domains_to_process = all_domains[start_idx:]
    if not domains_to_process:
        print("Nothing to process!")
        return

    # Open output file in append mode if resuming
    mode = "a" if args.resume and start_idx > 0 else "w"
    outfile = open(OUTPUT_CSV, mode, newline="")
    writer = csv.writer(outfile)
    if mode == "w":
        writer.writerow(["domain", "rank", "category"])

    semaphore = asyncio.Semaphore(args.concurrency)
    total = len(domains_to_process)
    processed = 0
    batch_num = 0
    t_start = time.time()

    # Process in chunks of (batch_size * concurrency) for progress reporting
    chunk_size = args.batch_size * args.concurrency
    for chunk_start in range(0, total, chunk_size):
        chunk = domains_to_process[chunk_start : chunk_start + chunk_size]

        # Split chunk into batches
        batches = []
        for i in range(0, len(chunk), args.batch_size):
            batch = chunk[i : i + args.batch_size]
            batches.append(batch)

        # Fire all batches in this chunk concurrently
        tasks = []
        for batch in batches:
            domain_names = [d[1] for d in batch]
            tasks.append(call_gemini(domain_names, semaphore))

        results = await asyncio.gather(*tasks)

        # Write results
        for batch, result in zip(batches, results):
            for rank, domain in batch:
                cat = result.get(domain.lower(), "other")
                writer.writerow([domain, rank, cat])
            processed += len(batch)

        outfile.flush()
        save_progress(start_idx + chunk_start + len(chunk))

        elapsed = time.time() - t_start
        rate = processed / elapsed if elapsed > 0 else 0
        pct = (processed / total) * 100
        eta = (total - processed) / rate if rate > 0 else 0
        print(f"  {processed:>8,} / {total:,} ({pct:5.1f}%) | {rate:,.0f} domains/s | ETA {eta/60:.1f}m")

    outfile.close()
    elapsed = time.time() - t_start
    print(f"\nDone! {processed:,} domains categorized in {elapsed:.0f}s")
    print(f"Output: {OUTPUT_CSV}")

    # Clean up progress file
    if PROGRESS_FILE.exists():
        PROGRESS_FILE.unlink()


if __name__ == "__main__":
    asyncio.run(main())
