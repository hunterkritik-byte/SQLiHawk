# SQLiHawk 🦅

A lightweight, permission-first SQL injection signal detector for security testing. SQLiHawk checks URL query parameters for response differences that *may* indicate SQL injection. It is a triage aid, not proof of a vulnerability.

## Features

- Query-parameter testing only; does not crawl or submit forms.
- Explicit authorization acknowledgement required before requests are sent.
- Low-impact boolean-difference checks and common database-error indicators.
- Per-request timeout, configurable delay, and a clear request limit.
- JSON report with tested URL, parameter, evidence, and confidence notes.
- Unit tests that use mocked HTTP responses (no live target needed).
- GitHub Actions test workflow.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\\Scripts\\activate`.

## Usage

Only test systems you own or have explicit written permission to assess.

```bash
python sqlihawk.py --url "https://example.test/products?id=1" --i-have-permission
```

Write the report to a file:

```bash
python sqlihawk.py --url "https://example.test/products?id=1" --i-have-permission --output report.json
```

Tune request timeout and pace:

```bash
python sqlihawk.py --url "https://example.test/products?id=1" --i-have-permission --timeout 8 --delay 0.5 --output report.json
```

SQLiHawk only tests parameters already present in the supplied URL. Use a dedicated test environment whenever possible. The tool does not dump records, enumerate schemas, bypass authentication, or attempt stacked/destructive queries.

## Interpreting results

- `possible`: a response difference or database-style error was observed; manually validate safely.
- `no_signal`: this run did not find the implemented signals. This does **not** prove the parameter is safe.
- `error`: the request failed or could not be evaluated reliably.

Response changes can be caused by WAFs, caching, unstable pages, application errors, or normal dynamic content. Review the evidence and reproduce manually before reporting a finding.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Scope and safety

Use only with authorization. You are responsible for complying with applicable law, program scope, and rate limits. Stop immediately if testing causes instability. SQLiHawk is intentionally a conservative signal detector, not an exploitation framework.

## License

MIT. See [LICENSE](LICENSE).
