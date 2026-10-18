# SQLiHawk 🦅

SQLiHawk is a real HTTP-based, permission-first SQL injection signal detector. It sends a small, bounded set of query-parameter perturbations and compares the server responses. It is designed for authorized testing and triage—not exploitation.

## What it does

- Sends real HTTP requests to the supplied URL.
- Checks existing query parameters using quote and boolean-style differential probes; numeric-looking values also receive numeric boolean probes.
- Detects common database error messages that appear only after a parameter is changed.
- Compares status codes and response bodies for true/false probe differences.
- Does not follow redirects, reducing the chance of silently testing a different host.
- Writes structured JSON evidence.
- Requires an explicit authorization acknowledgement and limits URL parameters, timeout, and delay.

## Install

Python 3.10+ is required.

\`\`\`bash
git clone https://github.com/hunterkritik-byte/SQLiHawk.git
cd SQLiHawk
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
\`\`\`

On Windows, activate with \`.venv\\\\Scripts\\\\activate\`.

## Run

Only run against systems you own or have explicit written permission to test.

\`\`\`bash
python sqlihawk.py --url "https://your-authorized-test-host.example/item?id=1" --i-have-permission --output report.json
\`\`\`

Tune request pacing:

\`\`\`bash
python sqlihawk.py --url "https://your-authorized-test-host.example/item?id=1" --i-have-permission --timeout 8 --delay 0.5 --output report.json
\`\`\`

The URL must already contain query parameters. SQLiHawk does not crawl, submit forms, log in, or discover hidden parameters. Redirects are not followed. Keep tests within the target's written scope and rate limits.

## Results

- \`possible\`: one or more signals appeared. Reproduce safely and manually validate before reporting.
- \`no_signal\`: these checks found no signal; the parameter may still be vulnerable.
- \`error\`: the request failed or results are partial.

Database error evidence is stronger than a response difference alone. A difference between boolean probes can still be caused by dynamic content, caching, a WAF, or application logic. Treat results as leads, not confirmed findings.

## Tests

\`\`\`bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
\`\`\`

## Scope and safety

SQLiHawk intentionally avoids data extraction, schema enumeration, authentication bypass, and destructive queries. It is a heuristic tool, so both false positives and false negatives are possible. No scanner can guarantee discovery of every SQL injection vulnerability.

## License

MIT. See [LICENSE](LICENSE).
