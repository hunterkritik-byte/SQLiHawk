#!/usr/bin/env python3
"""SQLiHawk: conservative, authorization-gated SQL injection signal checks."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

VERSION = "0.1.0"
DB_ERROR_PATTERNS = [
    ("MySQL", re.compile(r"You have an error in your SQL syntax|mysql_fetch|mysqli?_", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string", re.I)),
    ("Microsoft SQL Server", re.compile(r"\bSQL Server\b.*\b(error|message)\b|Unclosed quotation mark", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|sqlite3?\.OperationalError|near \"[^\"]+\": syntax error", re.I)),
    ("Oracle", re.compile(r"ORA-\d{4,5}", re.I)),
]


@dataclass
class Signal:
    parameter: str
    signal_type: str
    confidence: str
    detail: str


@dataclass
class ParameterResult:
    parameter: str
    status: str
    signals: list[dict[str, str]]
    baseline_status: int | None
    tested_requests: int
    note: str


def replace_query(url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, doseq=True), parts.fragment))


def detect_db_error(body: str) -> tuple[str, str] | None:
    for database, pattern in DB_ERROR_PATTERNS:
        match = pattern.search(body[:500_000])
        if match:
            return database, match.group(0)[:180]
    return None


def response_signature(response: requests.Response) -> tuple[int, int, str]:
    body = response.text[:500_000]
    # Keep a compact signature; exact body hashes are intentionally not used as a finding by themselves.
    normalized = re.sub(r"\s+", " ", body).strip()
    return response.status_code, len(body), normalized[:1000]


def run_scan(
    url: str,
    timeout: float = 8.0,
    delay: float = 0.25,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError("URL must be an absolute http:// or https:// URL.")
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not query_pairs:
        raise ValueError("URL must contain at least one query parameter to test.")

    client = session or requests.Session()
    headers = {"User-Agent": f"SQLiHawk/{VERSION} (authorized security testing)"}
    started = datetime.now(timezone.utc).isoformat()
    results: list[dict[str, Any]] = []

    # Baseline is fetched once. Requests only change an existing query parameter.
    baseline = client.get(url, timeout=timeout, headers=headers, allow_redirects=True)
    baseline_body = baseline.text[:500_000]
    baseline_sig = response_signature(baseline)
    tested_total = 1

    for index, (name, value) in enumerate(query_pairs):
        signals: list[Signal] = []
        tested = 0
        # A quote perturbation is a low-impact syntax signal; boolean pair checks for stable differences.
        payloads = [
            ("quote_error", value + "'"),
            ("boolean_true", value + "' AND '1'='1"),
            ("boolean_false", value + "' AND '1'='2"),
        ]
        for signal_type, payload in payloads:
            mutated = list(query_pairs)
            mutated[index] = (name, payload)
            try:
                if delay:
                    time.sleep(delay)
                response = client.get(
                    replace_query(url, mutated),
                    timeout=timeout,
                    headers=headers,
                    allow_redirects=True,
                )
                tested += 1
                tested_total += 1
                body = response.text[:500_000]
                db_error = detect_db_error(body)
                if db_error and not detect_db_error(baseline_body):
                    signals.append(Signal(
                        parameter=name,
                        signal_type="database_error",
                        confidence="medium",
                        detail=f"{db_error[0]}-style error appeared only after a parameter perturbation: {db_error[1]}",
                    ))
                if signal_type == "quote_error" and response.status_code >= 500 and baseline.status_code < 500:
                    signals.append(Signal(
                        parameter=name,
                        signal_type="server_error_change",
                        confidence="low",
                        detail=f"HTTP {response.status_code} after quote perturbation; baseline was HTTP {baseline.status_code}.",
                    ))
            except requests.RequestException as exc:
                results.append(asdict(ParameterResult(
                    parameter=name,
                    status="error",
                    signals=[asdict(s) for s in signals],
                    baseline_status=baseline.status_code,
                    tested_requests=tested,
                    note=f"Request failed: {type(exc).__name__}.",
                )))
                break

        if tested == len(payloads):
            try:
                true_pairs = list(query_pairs)
                false_pairs = list(query_pairs)
                true_pairs[index] = (name, value + "' AND '1'='1")
                false_pairs[index] = (name, value + "' AND '1'='2")
                # Re-use the two response bodies is avoided for clarity; these requests are explicit and bounded.
                true_response = client.get(replace_query(url, true_pairs), timeout=timeout, headers=headers, allow_redirects=True)
                false_response = client.get(replace_query(url, false_pairs), timeout=timeout, headers=headers, allow_redirects=True)
                tested += 2
                tested_total += 2
                true_sig = response_signature(true_response)
                false_sig = response_signature(false_response)
                if true_sig[0] != false_sig[0] or abs(true_sig[1] - false_sig[1]) > max(80, int(0.15 * max(true_sig[1], false_sig[1], 1))):
                    signals.append(Signal(
                        parameter=name,
                        signal_type="boolean_response_difference",
                        confidence="low",
                        detail="True/false boolean-style probes produced different status codes or materially different body lengths; dynamic content can cause false positives.",
                    ))
            except requests.RequestException:
                pass

        # Deduplicate identical signal types for a parameter.
        unique: dict[tuple[str, str], Signal] = {}
        for signal in signals:
            unique[(signal.signal_type, signal.detail)] = signal
        final_signals = [asdict(s) for s in unique.values()]
        results.append(asdict(ParameterResult(
            parameter=name,
            status="possible" if final_signals else "no_signal",
            signals=final_signals,
            baseline_status=baseline.status_code,
            tested_requests=tested,
            note="Heuristic only; manually validate in an authorized test environment." if final_signals else "No implemented signal observed; this does not prove the parameter is safe.",
        )))

    return {
        "tool": "SQLiHawk",
        "version": VERSION,
        "started_at": started,
        "target": urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")),
        "mode": "query-parameter signal checks",
        "authorization_acknowledged": True,
        "baseline": {"status_code": baseline.status_code, "body_length": len(baseline_body)},
        "tested_requests": tested_total,
        "results": results,
        "limitations": [
            "Signals are heuristic and can be false positives.",
            "A clean run does not prove absence of SQL injection.",
            "Only existing URL query parameters are tested; no crawling or form submission.",
            "No data extraction, schema enumeration, authentication bypass, or destructive payloads.",
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sqlihawk",
        description="Conservative SQL injection signal checks for authorized testing only.",
    )
    parser.add_argument("--url", required=True, help="Absolute HTTP(S) URL containing query parameters.")
    parser.add_argument("--i-have-permission", action="store_true", help="Acknowledge that you own the target or have explicit authorization.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds (default: 8).")
    parser.add_argument("--delay", type=float, default=0.25, help="Delay between primary probes in seconds (default: 0.25; use 0 for no delay).")
    parser.add_argument("--output", help="Write JSON report to this path instead of stdout.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args(argv)
    if not args.i_have_permission:
        parser.error("authorization acknowledgement required: add --i-have-permission only for an authorized target")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.delay < 0 or args.delay > 10:
        parser.error("--delay must be between 0 and 10 seconds")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run_scan(args.url, timeout=args.timeout, delay=args.delay)
    except (ValueError, requests.RequestException) as exc:
        print(f"SQLiHawk: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
        print(f"Report written to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
