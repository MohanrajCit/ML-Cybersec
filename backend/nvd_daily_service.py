"""
NVD Daily CVE Fetching Service
================================
Fetches CVEs published today (UTC) from the NVD API with automatic
fallback to the last N days if no CVEs are found for today.

Uses the same ML pipeline from cve_realtime_processor for risk prediction.
"""

import os
import logging
import time
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from cve_realtime_processor import predict_risk, detect_anomaly

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RETRIES = 3
INITIAL_BACKOFF = 2  # seconds


def _fetch_nvd_page(
    pub_start: str,
    pub_end: str,
    start_index: int = 0,
    results_per_page: int = 50,
    api_key: Optional[str] = None,
) -> dict:
    """
    Fetch a single page of CVEs from the NVD API 2.0.

    Implements exponential backoff for 429 (rate limit) and 5xx errors.
    """
    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    backoff = INITIAL_BACKOFF
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=30
            )

            if resp.status_code == 429 or resp.status_code >= 500:
                logger.warning(
                    f"NVD API returned {resp.status_code}, retrying in {backoff}s "
                    f"(attempt {attempt}/{MAX_RETRIES})"
                )
                time.sleep(backoff)
                backoff *= 2
                continue

            resp.raise_for_status()
            return resp.json()

        except requests.RequestException as exc:
            if attempt == MAX_RETRIES:
                raise
            logger.warning(f"Request failed ({exc}), retrying in {backoff}s")
            time.sleep(backoff)
            backoff *= 2

    return {"vulnerabilities": [], "totalResults": 0}


def _extract_cves(data: dict) -> List[dict]:
    """Extract CVE items with id, description, published, and lastModified."""
    items = []
    for vuln in data.get("vulnerabilities", []):
        cve_obj = vuln.get("cve", {})
        cve_id = cve_obj.get("id", "Unknown")

        descriptions = cve_obj.get("descriptions", [])
        desc_text = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), None
        )
        if not desc_text or len(desc_text) < 20:
            continue

        items.append(
            {
                "cve_id": cve_id,
                "description": desc_text,
                "published": cve_obj.get("published"),
                "lastModified": cve_obj.get("lastModified"),
            }
        )
    return items


def _fetch_all_cves_in_window(
    pub_start: str, pub_end: str, api_key: Optional[str] = None
) -> List[dict]:
    """Paginate through all CVEs in the given date window."""
    all_cves: List[dict] = []
    start_index = 0
    results_per_page = 50

    while True:
        data = _fetch_nvd_page(
            pub_start, pub_end, start_index, results_per_page, api_key
        )
        page_cves = _extract_cves(data)
        all_cves.extend(page_cves)

        total_results = data.get("totalResults", 0)
        start_index += results_per_page

        if start_index >= total_results:
            break

        # Respect NVD rate limits
        time.sleep(0.6 if api_key else 6)

    return all_cves


def fetch_cves_daily_with_fallback(
    fallback_days: int = 3,
    api_key: Optional[str] = None,
) -> Dict:
    """
    Fetch CVEs published today (UTC). If none found, fall back to the
    last ``fallback_days`` days.

    Returns a dict with:
        mode  – "daily" or "fallback"
        window – {"pubStartDate": ..., "pubEndDate": ...}
        count – number of CVE items
        items – list of CVE predictions
    """
    if api_key is None:
        api_key = os.getenv("NVD_API_KEY")

    now_utc = datetime.now(timezone.utc)

    # --- Try today first ---
    today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    pub_start = today_start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    logger.info(f"Fetching CVEs for today ({pub_start} → {pub_end})")

    try:
        cves = _fetch_all_cves_in_window(pub_start, pub_end, api_key)
    except Exception as exc:
        logger.error(f"NVD API error: {exc}")
        cves = []

    mode = "daily"

    if not cves:
        # --- Fallback ---
        fallback_start = (now_utc - timedelta(days=fallback_days)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        pub_start = fallback_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        mode = "fallback"
        logger.info(
            f"No CVEs today, falling back to last {fallback_days} days "
            f"({pub_start} → {pub_end})"
        )

        try:
            cves = _fetch_all_cves_in_window(pub_start, pub_end, api_key)
        except Exception as exc:
            logger.error(f"Fallback fetch also failed: {exc}")
            cves = []

    # --- Run ML predictions ---
    items: List[dict] = []
    for cve in cves:
        try:
            risk = predict_risk(cve["description"])
            anomaly = detect_anomaly(cve["description"])
            items.append(
                {
                    "cve_id": cve["cve_id"],
                    "published": cve.get("published"),
                    "lastModified": cve.get("lastModified"),
                    "risk": str(risk["risk"]),
                    "confidence": float(risk["confidence"]),
                    "anomalous": bool(anomaly["anomalous"]),
                }
            )
        except Exception as exc:
            logger.error(f"Prediction failed for {cve['cve_id']}: {exc}")
            continue

    return {
        "mode": mode,
        "window": {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        },
        "count": len(items),
        "items": items,
    }
