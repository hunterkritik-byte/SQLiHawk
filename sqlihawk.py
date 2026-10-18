#!/usr/bin/env python3
"""SQLiHawk: bounded differential SQL injection signal checks."""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

VERSION = "0.2.0"
MAX_BODY_CHARS = 500_000
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


def replace_query(url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, doseq=True), ""))


def detect_db_error(body: str) -> tuple[str, str] | None:
    for database, pattern in DB_ERROR_PATTERNS:
        match = pattern.search(body[:MAX_BODY_CHARS])
        if match:
            return database, match.group(0)[:180]
    return None


def response_signature(response: requests.Response) -> tuple[int, int, str]:
    body = response.text[:MAX_BODY_CHARS]
    normalized = re.sub(r"\s+", " ", body).strip()
    return response.status_code, len(body), normalized


def materially_different(left: requests.Response, right: requests.Response) -> bool:
    left_status, left_len, left_body = response_signature(left)
    right_status, right_len, right_body = response_signature(right)
    if left_status != right_status:
        return True
    if abs(left_len - right_len) > max(100, int(0.20 * max(left_len, right_len, 1))):
        return True
    # Ignore tiny responses: small dynamic fragments can dominate their content.
    if min(len(left_body), len(right_body)) < 120:
        return False
    similarity = difflib.SequenceMatcher(None, left_body[:4000], right_body[:4000], autojunk=False).ratio()
    return similarity < 0.70


def _request(client: requests.Session, url: str, timeout: float, headers: dict[str, str]) -> requests.Response:
    # Redirects are disabled so a test cannot silently continue onto another host.
    return client.get(url, timeout=timeout, headers=headers, allow_redirects=False)


def run_scan(
    url: str,
    timeout: float = 8.0,
    delay: float = 0.4,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("URL must be an absolute http:// or https:// URL.")
    if parts.username or parts.password:
        raise ValueError("Do not put credentials in the URL.")
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not query_pairs:
        raise ValueError("URL must contain at least one query parameter to test.")
    if len(query_pairs) > 20:
        raise ValueError("Maximum 20 query parameters per scan; narrow the URL first.")

    client = session or requests.Session()
    headers = {"User-Agent": f"SQLiHawk/{VERSION} (authorized security testing)", "Accept": "text/html,application/json,*/*"}
    started = datetime.now(timezone.utc).isoformat()
    baseline = _request(client, url, timeout, headers)
    baseline_body = baseline.text[:MAX_BODY_CHARS]
    baseline_error = detect_db_error(baseline_body)
    results: list[dict[str, Any]] = []
    total_requests = 1

    for index, (name, value) in enumerate(query_pairs):
        signals: list[Signal] = []
        tested = 0
        # Include string-context and numeric-context boolean pairs, bounded to four probes per parameter.
        probes = [
            ("quote", value + "'"),
            ("string_true", value + "' AND '1'='1"),
            ("string_false", value + "' AND '1'='2"),
        ]
        if re.fullmatch(r"-?\d{1,12}", value.strip()):
            probes.extend([
                ("numeric_true", value + " AND 1=1"),
                ("numeric_false", value + " AND 1=2"),
            ])

        responses: dict[str, requests.Response] = {}
        request_error = None
        for probe_name, payload in probes:
            mutated = list(query_pairs)
            mutated[index] = (name, payload)
            try:
                if delay:
                    time.sleep(delay)
                response = _request(client, replace_query(url, mutated), timeout, headers)
                responses[probe_name] = response
                tested += 1
                total_requests += 1
                body = response.text[:MAX_BODY_CHARS]
                db_error = detect_db_error(body)
                if db_error and not baseline_error:
                    signals.append(Signal(
                        parameter=name,
                        signal_type="database_error",
                        confidence="high",
                        detail=f"{db_error[0]}-style database error appeared only after a parameter perturbation: {db_error[1]}",
                    ))
                if probe_name == "quote" and response.status_code >= 500 and baseline.status_code < 500:
                    signals.append(Signal(
                        parameter=name,
                        signal_type="server_error_change",
                        confidence="low",
                        detail=f"Quote probe returned HTTP {response.status_code}; baseline returned HTTP {baseline.status_code}. This alone is not proof of SQL injection.",
                    ))
            except requests.RequestException as exc:
                request_error = type(exc).__name__
                break

        pair_names = [("string_true", "string_false")]
        if "numeric_true" in responses and "numeric_false" in responses:
            pair_names.append(("numeric_true", "numeric_false"))
        for true_name, false_name in pair_names:
            if true_name in responses and false_name in responses:
                if materially_different(responses[true_name], responses[false_name]):
                    signals.append(Signal(
                        parameter=name,
                        signal_type="boolean_response_difference",
                        confidence="medium",
                        detail=f"{true_name} and {false_name} probes produced materially different responses. Repeat in a stable test environment to rule out dynamic content and WAF behavior.",
                    ))

        unique: dict[tuple[str, str], Signal] = {}
        for signal in signals:
            unique[(signal.signal_type, signal.detail)] = signal
        final_signals = [asdict(signal) for signal in unique.values()]
        if request_error:
            status = "error"
            note = f"Request failed ({request_error}); partial results only."
        elif final_signals:
            status = "possible"
            note = "Potential SQLi signal; manually reproduce and validate before reporting."
        else:
            status = "no_signal"
            note = "No implemented signal observed. This does not prove the parameter is safe."
        results.append({
            "parameter": name,
            "status": status,
            "signals": final_signals,
            "baseline_status": baseline.status_code,
            "tested_requests": tested,
            "note": note,
        })

    return {
        "tool": "SQLiHawk",
        "version": VERSION,
        "started_at": started,
        "target": urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")),
        "mode": "bounded query-parameter differential checks",
        "authorization_acknowledged": True,
        "redirects_followed": False,
        "baseline": {
            "status_code": baseline.status_code,
            "body_length": len(baseline_body),
            "database_error_present": baseline_error is not None,
        },
        "tested_requests": total_requests,
        "results": results,
        "limitations": [
            "This is a heuristic detector, not proof; false positives and false negatives are possible.",
            "Only parameters already present in the URL are tested; no crawling, forms, or authentication flows.",
            "Redirects are not followed to avoid silently testing another host.",
            "No data extraction, schema enumeration, authentication bypass, or destructive queries.",
            "Use only on systems you own or have explicit authorization to test.",
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SQL injection signal checks for authorized testing only.")
    parser.add_argument("--url", required=True, help="Absolute HTTP(S) URL containing query parameters.")
    parser.add_argument("--i-have-permission", action="store_true", help="Acknowledge authorization to test this target.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.4, help="Delay between probes in seconds (0 to 10).")
    parser.add_argument("--output", help="Write JSON report to this path.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args(argv)
    if not args.i_have_permission:
        parser.error("authorization acknowledgement required: add --i-have-permission only for an authorized target")
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("--timeout must be greater than 0 and at most 60 seconds")
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
