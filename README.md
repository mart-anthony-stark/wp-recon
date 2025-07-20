# WPRecon

## WordPress Passive Security Posture Scanner

This tool performs **PASSIVE** and low‑impact HTTP checks against a WordPress site
that you are explicitly authorized to assess. It is NOT an exploitation or brute
force tool. It avoids intrusive behavior (no fuzzing, no credential guessing,
no concurrent high‑volume requests). Always obtain _written_ permission before
scanning a target you do not own.

## Features (passive checks):

• Resolves base URL, enforces https scheme if provided.
• Retrieves home page & parses: - WordPress version from meta generator tag (if exposed) - Theme name & version (from style.css headers if discoverable) - Plugin names passively referenced in HTML asset paths
• Checks presence / accessibility of common sensitive files:
readme.html, license.txt, wp-config-sample.php, xmlrpc.php
• Checks if xmlrpc.php responds (potential attack surface if enabled)
• Detects directory indexing on /wp-content/uploads/
• Basic user enumeration exposure via ?author=1 redirect pattern
• Security header assessment (missing / weak):
Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy
• REST API index exposure (/wp-json/)
• TLS certificate expiry (if HTTPS) using ssl + socket (no external libs)

## How to use

### Prerequisites

- Python 3.x.x ([Download here](https://www.python.org/downloads/))

1. Clone repository to your local machine.

```
git clone https://github.com/mart-anthony-stark/wp-recon.git
```

2. Pull the latest commit in main branch

```
git checkout main
git pull
```

3. Install python libraries

```
pip install -r requirements.txt
```

4. Run the main script

```
python main.py [url]
```

## Output:

Summarized JSON report + human readable table.

## Extensibility:

Add new passive checks in the "checks" list or extend parse_homepage().

## Safeguards:

Rate limiting between requests.

> DISCLAIMER:
> This code is for defensive security assessment & educational purposes.
> Do not use it for unauthorized testing. You are responsible for complying
> with all applicable laws & terms of service.

Made with ❤️ by Mart Salazar
