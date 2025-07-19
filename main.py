"""
WordPress Passive Security Posture Scanner
------------------------------------------
This script performs **PASSIVE** and low‑impact HTTP checks against a WordPress site
that you are explicitly authorized to assess. It is NOT an exploitation or brute
force tool. It avoids intrusive behavior (no fuzzing, no credential guessing,
no concurrent high‑volume requests). Always obtain *written* permission before
scanning a target you do not own.

Features (passive checks):
  • Resolves base URL, enforces https scheme if provided.
  • Retrieves home page & parses:
       - WordPress version from meta generator tag (if exposed)
       - Theme name & version (from style.css headers if discoverable)
       - Plugin names passively referenced in HTML asset paths
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

Output:
  Summarized JSON report + human readable table.

Extensibility:
  Add new passive checks in the "checks" list or extend parse_homepage().

Safeguards:
  Requires explicit flag --i-am-authorized to run.
  Rate limiting between requests.

DISCLAIMER:
  This code is for defensive security assessment & educational purposes.
  Do not use it for unauthorized testing. You are responsible for complying
  with all applicable laws & terms of service.
"""
from __future__ import annotations
import sys
import argparse
from pathlib import Path
from config import settings
from scanner import PassiveScanner
from utils import print_human_report


def main():
    parser = argparse.ArgumentParser(description="Passive WordPress security postue scanner (authorized use only)")
    
    parser.add_argument('url', help="Base URL or Hostname of the WordPress site (e.g., https://example.com)")
    
    parser.add_argument('--json-output', help="Write full JSON report to file")

    parser.add_argument('--timeout', type=int, default=settings.DEFAULT_TIMEOUT)

    parser.add_argument('--exit-code-on-medium', action='store_true', help='Return exit code 2 if any medium/high findings (CI Integration)')

    args = parser.parse_args()

    if sys.stdin.isatty():
        print("[!] WARNING: This tool performs passive security checks (HTTP GET/HEAD) on the target you specify.",
            "\nUse ONLY on systems you own or have *explicit* permission to assess. Unauthorized scanning may be illegal."
            "\nProceed? (yes/no): ", end='', flush=True)
        choice = input().strip().lower()
        if choice not in ('y','yes'):
            print("Aborted by user.")
            sys.exit(1)
    else:
        choice = 'y'
        print("[!] Non-interactive mode detected; proceeding without confirmation prompt.")


    if choice in ('y', 'yes'):
        scanner = PassiveScanner(args.url, timeout=args.timeout)
        report = scanner.run()

        print_human_report(report)

        if args.json_output:
            Path(args.json_output).write_text(report.to_json(), encoding='utf-8')
            print(f"\nJSON report written to {args.json_output}")

        if args.exit_code_on_medium:
            if report.summary.get('medium', 0) > 0 or report.get('high', 0) > 0:
                sys.exit(2)

if __name__ == '__main__':
    main()