"""Evaluate 8 enrichment endpoints for overlap and produce cascade ranking."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scanner_lite.classifier import classify_outcome
from scanner_lite.endpoints.registry import ADAPTERS, ENDPOINT_ORDER

EVAL_DIR = Path(__file__).resolve().parent
GOLDEN_PATH = EVAL_DIR / "golden_ips.json"
RANKING_PATH = EVAL_DIR / "ranking.json"

# Cost weights for ranking (lower is better)
COST_WEIGHTS = {
    "local_csv": 0.0,
    "ripestat": 0.01,
    "ip_api": 0.01,
    "greynoise": 0.02,
    "abuseipdb": 0.05,
    "shodan_internetdb": 0.02,
    "otx": 0.02,
    "ipinfo": 0.02,
}


def _category_from_endpoint(endpoint_name: str, data: dict) -> str:
    signals = {}
    if endpoint_name == "local_csv":
        signals["scanner_tag"] = data
    elif endpoint_name == "greynoise":
        signals["greynoise"] = data
    elif endpoint_name == "abuseipdb":
        signals["abuseipdb"] = data
    elif endpoint_name == "otx":
        signals["otx"] = data
    else:
        return "unknown"
    return classify_outcome(signals).get("outcome_category", "unknown")


def run_overlap_eval(*, write_ranking: bool = True) -> dict:
    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    ips = [entry["ip"] for entry in golden.get("ips", [])]

    endpoint_categories: dict[str, dict[str, str]] = defaultdict(dict)
    endpoint_success: dict[str, int] = defaultdict(int)

    for endpoint_name in ENDPOINT_ORDER:
        adapter = ADAPTERS[endpoint_name]
        for ip in ips:
            result = adapter.query(ip)
            if result.success:
                endpoint_success[endpoint_name] += 1
                endpoint_categories[endpoint_name][ip] = _category_from_endpoint(
                    endpoint_name, result.data
                )
            else:
                endpoint_categories[endpoint_name][ip] = "error"

    # Pairwise agreement on category labels (exclude local_csv and errors)
    paid_endpoints = [e for e in ENDPOINT_ORDER if e != "local_csv"]
    overlap_matrix: dict[str, dict[str, float]] = {}
    for a in paid_endpoints:
        overlap_matrix[a] = {}
        for b in paid_endpoints:
            if a == b:
                overlap_matrix[a][b] = 1.0
                continue
            agree = 0
            total = 0
            for ip in ips:
                ca = endpoint_categories[a].get(ip)
                cb = endpoint_categories[b].get(ip)
                if ca in ("error", None) or cb in ("error", None):
                    continue
                total += 1
                if ca == cb:
                    agree += 1
            overlap_matrix[a][b] = round(agree / total, 2) if total else 0.0

    # Score endpoints: success rate - cost
    scores = []
    for endpoint_name in paid_endpoints:
        success_rate = endpoint_success[endpoint_name] / len(ips) if ips else 0
        cost = COST_WEIGHTS.get(endpoint_name, 0.05)
        score = round(success_rate * 0.9 - cost, 3)
        scores.append({"endpoint": endpoint_name, "score": score, "success_rate": success_rate})

    scores.sort(key=lambda x: x["score"], reverse=True)
    for index, entry in enumerate(scores, start=1):
        entry["rank"] = index

    # GreyNoise is intentionally last in the paid cascade (cost / overlap policy).
    paid_ranked = [entry["endpoint"] for entry in scores if entry["endpoint"] != "greynoise"]
    cascade_order = paid_ranked[:2] + ["greynoise"]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "golden_ip_count": len(ips),
        "endpoint_success": dict(endpoint_success),
        "overlap_matrix": overlap_matrix,
        "ranking": scores,
        "cascade_order": cascade_order,
        "endpoint_categories": {k: dict(v) for k, v in endpoint_categories.items()},
    }

    if write_ranking:
        RANKING_PATH.write_text(
            json.dumps(
                {
                    "generated_at": report["generated_at"],
                    "cascade_order": cascade_order,
                    "ranking": scores[:3],
                    "overlap_matrix": overlap_matrix,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return report


def main() -> None:
    report = run_overlap_eval()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
