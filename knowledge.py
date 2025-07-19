from typing import Dict

MITIGATION_DATA: Dict[str, Dict[str, object]] = {
    "WordPress version exposed": {
        "mitigation": (
            "Remove or filter the generator meta tag (e.g., add "
            "remove_action('wp_head', 'wp_generator'); in a must‑use plugin or theme functions.php). "
            "Keep core auto‑updates enabled so even if disclosed it is patched."
        ),
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Software_and_Data_Integrity_Failures_Cheat_Sheet.html"
        ]
    },
    "Plugin names discoverable in HTML": {
        "mitigation": (
            "Limit inactive/unused plugins; keep all active plugins updated (consider auto‑updates). "
            "Use build/optimization tools (caching, bundling) to reduce direct plugin path exposure; "
            "periodically review installed plugins for abandonment."
        ),
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Component_Security_Cheat_Sheet.html"
        ]
    },
    "Theme version obtainable": {
        "mitigation": (
            "Restrict direct access to theme headers; keep theme updated; remove unused themes. "
            "Consider build pipelines to strip version comments or serve minimized assets."
        ),
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
        ]
    },
    "File present: readme.html": {
        "mitigation": (
            "Delete or restrict public access to readme.html, license.txt, and wp-config-sample.php. "
            "They are not required in production and can aid reconnaissance."
        ),
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "File present: license.txt": {
        "mitigation": "Remove or block public access to license.txt to reduce version reconnaissance.",
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "File present: wp-config-sample.php": {
        "mitigation": (
            "Remove wp-config-sample.php from production. Ensure wp-config.php permissions are restrictive "
            "(e.g., 400/440 depending on user/group)."
        ),
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "xmlrpc.php enabled": {
        "mitigation": (
            "If unused (no Jetpack/mobile integrations), disable via add_filter('xmlrpc_enabled','__return_false'); "
            "or block at the web server. If needed, apply rate limiting and monitor auth attempts."
        ),
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        ]
    },
    "REST API index accessible": {
        "mitigation": (
            "Default exposure is normal. To limit enumeration, authenticate sensitive routes, unregister unused "
            "endpoints via the 'rest_endpoints' filter, or apply a security plugin / WAF rules."
        ),
        "references": [
            "https://developer.wordpress.org/rest-api/",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "Directory indexing enabled (uploads)": {
        "mitigation": (
            "Disable autoindex (Apache: 'Options -Indexes'; Nginx: 'autoindex off;') and/or place an empty index.php "
            "in /wp-content/uploads/. Limit direct listing to reduce reconnaissance."
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://wordpress.org/documentation/article/hardening-wordpress/"
        ]
    },
    "Missing security header: strict-transport-security": {
        "mitigation": (
            "After confirming HTTPS everywhere, add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload "
            "(phase in with smaller max-age first)."
        ),
        "references": [
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        ]
    },
    "Weak HSTS header": {
        "mitigation": "Increase max-age (e.g., 31536000) and add includeSubDomains; preload after testing.",
        "references": [
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        ]
    },
    "Missing security header: content-security-policy": {
        "mitigation": (
            "Design a CSP (start in report-only) enumerating required sources. Use nonces or hashes; avoid 'unsafe-inline'. "
            "Iteratively tighten."
        ),
        "references": [
            "https://developer.mozilla.org/docs/Web/HTTP/CSP",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
        ]
    },
    "Missing security header: x-frame-options": {
        "mitigation": "Add X-Frame-Options: SAMEORIGIN (or use CSP frame-ancestors) to mitigate clickjacking.",
        "references": [
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
        ]
    },
    "Missing security header: x-content-type-options": {
        "mitigation": "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
        "references": [
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "Missing security header: referrer-policy": {
        "mitigation": "Adopt Referrer-Policy: strict-origin-when-cross-origin (or stricter per privacy goals).",
        "references": [
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
        ]
        # (Referrer policy ties loosely to privacy & data leakage; logging/monitoring tie-in depends on org policy.)
    },
    "Missing security header: permissions-policy": {
        "mitigation": (
            "Add Permissions-Policy (formerly Feature-Policy) to explicitly disallow unneeded features, "
            "e.g., Permissions-Policy: camera=(), microphone=(), geolocation=()."
        ),
        "references": [
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "Author username exposure": {
        "mitigation": (
            "Block enumeration: deny /?author= pattern or redirect to a generic page; ensure 'display_name' differs "
            "from 'user_login'; employ a WAF rule or plugin to throttle enumeration."
        ),
        "references": [
            "https://wordpress.org/documentation/article/hardening-wordpress/",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "Expired TLS certificate": {
        "mitigation": "Renew immediately (use automated renewal + monitoring, e.g., certbot renew + cron/systemd).",
        "references": [
            "https://letsencrypt.org/docs/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
            "https://ssl-config.mozilla.org/"
        ]
    },
    "Impending TLS certificate expiry": {
        "mitigation": "Schedule/automate renewal; add alerting when <30 days remain.",
        "references": [
            "https://letsencrypt.org/docs/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        ]
    },
    "TLS check failed": {
        "mitigation": "Verify chain, hostname, protocol versions; test with external SSL scanners, then correct config.",
        "references": [
            "https://ssl-config.mozilla.org/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        ]
    }
}