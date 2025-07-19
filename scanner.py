import re
import ssl
import time
import socket
from config import settings
from utils import print_logo
from typing import List, Dict
from urllib.parse import urlparse
from models import Optional, Finding, Report
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from knowledge import MITIGATION_DATA

# external libs
import requests
from bs4 import BeautifulSoup

class PassiveScanner:
    def __init__(self, base_url: str, timeout: int = settings.DEFAULT_TIMEOUT):
        self.base_url = self._normalize_base(base_url)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": settings.USER_AGENT})
        self.timeout = timeout
        self.findings: List[Finding] = []
        self.meta: Dict[str, Optional[str]] = {
            "wordpress_version": None,
            "theme": None,
            "theme_version": None,
            "detected_plugins": None,
            "tls_expires": None
        }

    @staticmethod
    def _normalize_base(url: str) -> str:
        if not re.match(r"^https?://", url):
            url = "https://" + url.strip('/')

        # strip path to root
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}/"
        
    def _get(self, path: str, allow_redirects: bool = True) -> Optional[requests.Response]:
        url = urljoin(self.base_url, path)
        try:
            time.sleep(settings.RATE_LIMIT_SECONDS)
            response = self.session.get(url,
                                    timeout=self.timeout,
                                    allow_redirects=allow_redirects)
            return response
        except requests.RequestException as e:
            # self._add_finding("network",)
            pass

    def _head(self, path: str) -> Optional[requests.Response]:
        url = urljoin(self.base_url, path)
        try:
            time.sleep(settings.RATE_LIMIT_SECONDS)
            resp = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            return resp
        except requests.RequestException:
            return None

    def _add_finding(self, category: str, name: str, severity: str,
                    description: str, evidence: Optional[str] = None):
        data = MITIGATION_DATA.get(name, {})
        mitigation = data.get("mitigation")
        references = data.get("references", [])
        self.findings.append(
            Finding(category, name, severity, description,
                    evidence=evidence,
                    mitigation=mitigation,
                    references=references)
        )

     # --- Checks / Scans for vulnerabilities ---
    def parse_homepage(self):
        resp = self._get('/')
        if not resp:
            return
        soup = BeautifulSoup(resp.text, 'html.parser')
        # WordPress version
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen and gen.get('content') and 'WordPress' in gen['content']:
            version = gen['content'].split('WordPress')[-1].strip()
            self.meta['wordpress_version'] = version
            self._add_finding(
                'information_disclosure',
                'WordPress version exposed',
                'low',
                'The meta generator tag reveals the WordPress core version. Consider removing for minimal fingerprint reduction.',
                evidence=version
            )
        # Passive plugin detection (asset paths)
        plugin_pattern = re.compile(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/")
        plugins = sorted(set(plugin_pattern.findall(resp.text)))
        if plugins:
            self.meta['detected_plugins'] = ', '.join(plugins)
            self._add_finding(
                'enumeration',
                'Plugin names discoverable in HTML',
                'info',
                'Plugin directories referenced by asset URLs. Keep plugins updated and remove inactive ones.',
                evidence=','.join(plugins)
            )
        # Theme detection
        theme_pattern = re.compile(r"/wp-content/themes/([a-zA-Z0-9_-]+)/")
        themes = theme_pattern.findall(resp.text)
        if themes:
            theme = themes[0]
            self.meta['theme'] = theme
            # Try to fetch style.css for version header
            style_resp = self._get(f"/wp-content/themes/{theme}/style.css")
            if style_resp and style_resp.status_code == 200 and 'Version:' in style_resp.text[:1000]:
                m = re.search(r"Version:\s*([0-9A-Za-z._-]+)", style_resp.text)
                if m:
                    self.meta['theme_version'] = m.group(1)
                    self._add_finding('information_disclosure', 'Theme version obtainable', 'info', 'Theme version found in style.css header.', evidence=m.group(1))

    def check_sensitive_files(self):
        paths = [
            'readme.html', 'license.txt', 'wp-config-sample.php'
        ]
        for p in paths:
            resp = self._head(p)
            if resp and resp.status_code == 200:
                self._add_finding('hardening', f"File present: {p}", 'info', f"Publicly accessible {p} can reveal version/licensing info. Consider removing or restricting.")

    def check_xmlrpc(self):
        resp = self._head('xmlrpc.php')
        if resp and resp.status_code in (200, 405):
            self._add_finding('surface', 'xmlrpc.php enabled', 'low', 'xmlrpc.php responds. If not needed, disable it to reduce attack surface.', evidence=str(resp.status_code))

    def check_rest_api(self):
        resp = self._get('wp-json/')
        if resp and resp.status_code == 200 and 'application/json' in resp.headers.get('Content-Type',''):
            # Presence is normal for modern WP but note exposure
            self._add_finding('surface', 'REST API index accessible', 'info', 'WordPress REST API index is publicly accessible (normal). Ensure only needed routes are enabled.')

    def check_directory_indexing(self):
        resp = self._get('wp-content/uploads/')
        if resp and resp.status_code == 200 and re.search(r"<title>Index of /wp-content/uploads/?</title>", resp.text, re.I):
            self._add_finding('hardening', 'Directory indexing enabled (uploads)', 'low', 'Directory listing can reveal media filenames & structure. Disable autoindex in web server config.')

    def check_security_headers(self):
        resp = self._get('/')
        if not resp:
            return
        headers = {k.lower(): v for k,v in resp.headers.items()}
        needed = {
            'strict-transport-security': 'Adds protection against protocol downgrade & cookie hijacking. Enable with a long max-age after validation.',
            'content-security-policy': 'Mitigates XSS & data injection. Define trusted sources.',
            'x-frame-options': 'Helps prevent clickjacking (SAMEORIGIN or DENY).',
            'x-content-type-options': 'Prevents MIME sniffing (nosniff).',
            'referrer-policy': 'Controls referrer leakage (e.g., no-referrer-when-downgrade, strict-origin-when-cross-origin).',
            'permissions-policy': 'Restricts powerful browser features (camera, geolocation, etc.).'
        }
        for h, rationale in needed.items():
            if h not in headers:
                self._add_finding('headers', f'Missing security header: {h}', 'medium', rationale)
            else:
                if h == 'strict-transport-security' and 'max-age=' not in headers[h].lower():
                    self._add_finding('headers', 'Weak HSTS header', 'low', 'HSTS present but lacks max-age directive.')

    def check_author_enumeration(self):
        # Passive check: request ?author=1 and see if it redirects to /author/username/
        parsed = urlparse(self.base_url)
        path = '?author=1'
        try:
            time.sleep(settings.RATE_LIMIT_SECONDS)
            resp = self.session.get(self.base_url + path, timeout=self.timeout, allow_redirects=True)
            if resp.history:
                final = resp.url
                m = re.search(r"/author/([a-zA-Z0-9_-]+)/?", final)
                if m:
                    self._add_finding('enumeration', 'Author username exposure', 'low', 'Numeric author ID enumeration reveals a login name. Consider blocking author archive scans.', evidence=m.group(1))
        except requests.RequestException:
            pass

    def check_tls_expiry(self):
        parsed = urlparse(self.base_url)
        if parsed.scheme != 'https':
            return
        host = parsed.hostname
        port = 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            not_after = cert.get('notAfter')
            if not_after:
                expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                # Make expires timezone-aware (UTC)
                expires = expires.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days = (expires - now).days
                self.meta['tls_expires'] = expires.isoformat()
                if days < 0:
                    self._add_finding('tls', 'Expired TLS certificate', 'high', 'The TLS certificate is expired. Renew immediately.', evidence=str(days))
                elif days < 15:
                    self._add_finding('tls', 'Impending TLS certificate expiry', 'medium', f'Certificate expires in {days} days. Renew soon.', evidence=str(days))
        except Exception as e:
            self._add_finding('tls', 'TLS check failed', 'info', f'Could not evaluate certificate: {e}')

    
    def run(self):
        print(f"Scanning {self.base_url} for vulnerabilities...")

        self.parse_homepage()
        self.check_sensitive_files()
        self.check_xmlrpc()
        self.check_rest_api()
        self.check_directory_indexing()
        self.check_security_headers()
        self.check_author_enumeration()
        self.check_tls_expiry()
        return self.build_report()
    
    def build_report(self) -> Report:
        severity_count = {s:0 for s in ['info','low','medium','high']}
        for f in self.findings:
            severity_count[f.severity] = severity_count.get(f.severity,0)+1
        return Report(
            target=self.base_url,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            findings=self.findings,
            summary=severity_count,
            metadata=self.meta
        )

    def print_human_report(report: Report):
        from textwrap import shorten
        print_logo()
        print(f"Target: {report.target}")
        print(f"Timestamp (UTC): {report.timestamp_utc}")
        print("\nMetadata:")
        for k,v in report.metadata.items():
            print(f"  - {k}: {v}")
        print("\nFindings (grouped by severity):")
        order = ['high','medium','low','info']
        for sev in order:
            items = [f for f in report.findings if f.severity == sev]
            if not items:
                continue
            print(f"\n  {sev.upper()} ({len(items)}):")
            for f in items:
                desc = shorten(f.description, width=100, placeholder='…')
                ev = f" [evidence: {f.evidence}]" if f.evidence else ''
                print(f"    - {f.category}: {f.name} :: {desc}{ev}")
        print("\nSummary counts:")
        for sev,count in report.summary.items():
            print(f"  {sev}: {count}")