from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from scan_engine import run_canonical_scan


DEFAULT_CASES = [
    {"name": "Example", "url": "https://example.com"},
    {"name": "Wikipedia", "url": "https://www.wikipedia.org"},
    {"name": "Python", "url": "https://www.python.org"},
    {"name": "GitHub", "url": "https://github.com"},
    {"name": "OpenAI", "url": "https://openai.com"},
]

VALIDATION_CASES = [
    {"name": "Email input", "url": "test@gmail.com"},
    {"name": "Localhost", "url": "http://localhost"},
    {"name": "Private IP", "url": "http://10.0.0.1"},
]


@dataclass
class BenchmarkRow:
    suite: str
    name: str
    url: str
    elapsed_s: float
    validation_ok: bool
    reachability_state: str
    extraction_status: str
    verdict: str
    risk_score: str
    confidence: str
    errors: int



def _format_float(value: float | None, digits: int = 2) -> str:
    if value is None:
        return "N/A"
    return f"{value:.{digits}f}"



def _to_percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    idx = max(0, min(len(values) - 1, int(round((percentile / 100.0) * (len(values) - 1)))))
    ordered = sorted(values)
    return ordered[idx]



def _to_markdown_table(rows: list[BenchmarkRow]) -> str:
    header = (
        "| Suite | Case | URL | Total Time (s) | Validation | Reachability | Extraction | Verdict | "
        "Risk % | Confidence % | Errors |\n"
        "|---|---|---|---:|---|---|---|---|---:|---:|---:|"
    )
    body_lines: list[str] = []
    for row in rows:
        body_lines.append(
            "| {suite} | {name} | `{url}` | {elapsed} | {valid} | {reachability} | {extract} | {verdict} | {risk} | {conf} | {errors} |".format(
                suite=row.suite,
                name=row.name,
                url=row.url,
                elapsed=_format_float(row.elapsed_s, 2),
                valid="PASS" if row.validation_ok else "FAIL",
                reachability=row.reachability_state or "N/A",
                extract=row.extraction_status or "N/A",
                verdict=row.verdict or "N/A",
                risk=row.risk_score,
                conf=row.confidence,
                errors=row.errors,
            )
        )
    return header + "\n" + "\n".join(body_lines)



def run_case(suite: str, name: str, url: str) -> BenchmarkRow:
    start = perf_counter()
    scan = run_canonical_scan(url)
    elapsed = perf_counter() - start

    prediction = scan.get("prediction", {})
    risk = prediction.get("risk_score")
    confidence = prediction.get("confidence")

    return BenchmarkRow(
        suite=suite,
        name=name,
        url=url,
        elapsed_s=round(elapsed, 3),
        validation_ok=bool(scan.get("validation", {}).get("ok")),
        reachability_state=str(scan.get("reachability", {}).get("state", "")),
        extraction_status=str(scan.get("features", {}).get("status", "")),
        verdict=str(prediction.get("verdict", "")),
        risk_score=_format_float(float(risk), 2) if risk is not None else "N/A",
        confidence=_format_float(float(confidence), 2) if confidence is not None else "N/A",
        errors=len(scan.get("errors", []) or []),
    )



def build_report(rows: list[BenchmarkRow], repeats: int, output_path: Path) -> str:
    total_times = [r.elapsed_s for r in rows]
    valid_times = [r.elapsed_s for r in rows if r.validation_ok]

    reachability_counts: dict[str, int] = {}
    verdict_counts: dict[str, int] = {}
    extraction_counts: dict[str, int] = {}

    for row in rows:
        reachability_counts[row.reachability_state or "N/A"] = reachability_counts.get(row.reachability_state or "N/A", 0) + 1
        verdict_counts[row.verdict or "N/A"] = verdict_counts.get(row.verdict or "N/A", 0) + 1
        extraction_counts[row.extraction_status or "N/A"] = extraction_counts.get(row.extraction_status or "N/A", 0) + 1

    generated_at = datetime.now(timezone.utc).isoformat()

    report = [
        "# Runtime Benchmark Report",
        "",
        "## Environment",
        f"- Generated at (UTC): `{generated_at}`",
        f"- Python: `{sys.version.split()[0]}`",
        f"- Platform: `{platform.platform()}`",
        f"- Runs per case: `{repeats}`",
        "",
        "## Performance Summary",
        f"- Total scans executed: `{len(rows)}`",
        f"- Validation-pass scans: `{sum(1 for r in rows if r.validation_ok)}`",
        f"- Avg total scan time (all): `{_format_float(statistics.mean(total_times) if total_times else None)}s`",
        f"- Median total scan time (all): `{_format_float(statistics.median(total_times) if total_times else None)}s`",
        f"- P95 total scan time (all): `{_format_float(_to_percentile(total_times, 95))}s`",
        f"- Avg total scan time (validation-pass only): `{_format_float(statistics.mean(valid_times) if valid_times else None)}s`",
        f"- Max total scan time: `{_format_float(max(total_times) if total_times else None)}s`",
        f"- Min total scan time: `{_format_float(min(total_times) if total_times else None)}s`",
        "",
        "## State Distribution",
        f"- Reachability: `{json.dumps(reachability_counts, sort_keys=True)}`",
        f"- Extraction status: `{json.dumps(extraction_counts, sort_keys=True)}`",
        f"- Verdicts: `{json.dumps(verdict_counts, sort_keys=True)}`",
        "",
        "## Case Results",
        _to_markdown_table(rows),
        "",
        "## Notes",
        "- Timings include validation, redirect pre-check, DNS/WHOIS feature attempts, Selenium reachability/content extraction, and model inference.",
        "- Results vary by network quality, browser driver availability, and remote site response speed.",
        f"- Source: `{output_path.name}` generated by `benchmark_scans.py`.",
    ]
    return "\n".join(report).strip() + "\n"



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run runtime benchmarks for URL Threat Scanner")
    parser.add_argument("--repeats", type=int, default=1, help="Number of runs per case (default: 1)")
    parser.add_argument("--output", type=Path, default=Path("BENCHMARK_REPORT.md"), help="Markdown report output path")
    return parser.parse_args()



def main() -> int:
    args = parse_args()
    repeats = max(1, int(args.repeats))

    rows: list[BenchmarkRow] = []

    for _ in range(repeats):
        for case in DEFAULT_CASES:
            rows.append(run_case("runtime", case["name"], case["url"]))
        for case in VALIDATION_CASES:
            rows.append(run_case("validation", case["name"], case["url"]))

    report = build_report(rows, repeats=repeats, output_path=args.output)
    args.output.write_text(report, encoding="utf-8")
    print(f"Benchmark report written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
