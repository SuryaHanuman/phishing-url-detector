class RiskEngine:
    """
    Combines results from all analyzers and calculates a phishing risk score.

    Risk score:
        0-9   : SAFE
        10-24 : LOW
        25-49 : MEDIUM
        50-74 : HIGH
        75-100: CRITICAL
    """

    def __init__(
        self,
        url_result,
        dns_result,
        http_result,
        ssl_result,
        whois_result,
        html_result
    ):
        self.url_result = url_result or {}
        self.dns_result = dns_result or {}
        self.http_result = http_result or {}
        self.ssl_result = ssl_result or {}
        self.whois_result = whois_result or {}
        self.html_result = html_result or {}

        self.score = 0
        self.findings = []

    # =========================================================
    # ADD RISK
    # =========================================================

    def add_risk(self, points, level, message):

        self.score += points

        self.findings.append({
            "points": points,
            "level": level,
            "message": message
        })

    # =========================================================
    # URL ANALYSIS
    # =========================================================

    def analyze_url_risk(self):

        is_ip_address = self.url_result.get(
            "is_ip_address",
            False
        )

        # -----------------------------------------------------
        # IP address
        # -----------------------------------------------------

        if is_ip_address:

            self.add_risk(
                12,
                "HIGH",
                "The URL uses an IP address instead of a normal domain name."
            )

        # -----------------------------------------------------
        # URL length
        # -----------------------------------------------------

        url_length = self.url_result.get(
            "url_length",
            0
        )

        if url_length >= 150:

            self.add_risk(
                8,
                "MEDIUM",
                "The URL is unusually long."
            )

        elif url_length >= 100:

            self.add_risk(
                4,
                "LOW",
                "The URL is relatively long."
            )

        # -----------------------------------------------------
        # Domain length
        # -----------------------------------------------------

        domain_length = self.url_result.get(
            "domain_length",
            0
        )

        if domain_length >= 50:

            self.add_risk(
                5,
                "MEDIUM",
                "The domain name is unusually long."
            )

        # -----------------------------------------------------
        # @ symbol
        # -----------------------------------------------------

        if self.url_result.get("has_at_symbol"):

            self.add_risk(
                12,
                "HIGH",
                "The URL contains an '@' symbol, which can hide the real destination."
            )

        # -----------------------------------------------------
        # Percent encoding
        # -----------------------------------------------------

        if self.url_result.get("has_percent_encoding"):

            self.add_risk(
                3,
                "LOW",
                "The URL contains percent-encoded characters."
            )

        # -----------------------------------------------------
        # Base64
        # -----------------------------------------------------

        if self.url_result.get("base64_like"):

            self.add_risk(
                6,
                "MEDIUM",
                "The URL contains Base64-like encoded data."
            )

        # -----------------------------------------------------
        # URL shortener
        # -----------------------------------------------------

        if self.url_result.get("is_shortened"):

            self.add_risk(
                7,
                "MEDIUM",
                "A URL shortening service is being used."
            )

        # -----------------------------------------------------
        # Suspicious TLD
        # -----------------------------------------------------

        if self.url_result.get("suspicious_tld"):

            self.add_risk(
                5,
                "MEDIUM",
                "The domain uses a TLD commonly associated with suspicious URLs."
            )

        # -----------------------------------------------------
        # Subdomains
        # -----------------------------------------------------

        subdomain_count = self.url_result.get(
            "subdomain_count",
            0
        )

        if subdomain_count >= 4:

            self.add_risk(
                6,
                "MEDIUM",
                "The hostname contains an unusually large number of subdomains."
            )

        elif subdomain_count >= 3:

            self.add_risk(
                3,
                "LOW",
                "The hostname contains several subdomains."
            )

        # -----------------------------------------------------
        # Multiple hyphens
        # -----------------------------------------------------

        if self.url_result.get("multiple_hyphens"):

            self.add_risk(
                3,
                "LOW",
                "The hostname contains multiple hyphens."
            )

        # -----------------------------------------------------
        # Multiple dots
        # -----------------------------------------------------
        #
        # IP addresses naturally contain three dots.
        # Therefore this check is only meaningful for domains.
        #

        if (
            not is_ip_address
            and self.url_result.get("multiple_dots")
        ):

            self.add_risk(
                2,
                "LOW",
                "The hostname contains an unusually complex dot structure."
            )

        # -----------------------------------------------------
        # Entropy
        # -----------------------------------------------------

        if self.url_result.get("high_entropy"):

            self.add_risk(
                2,
                "LOW",
                "The hostname contains a relatively high-entropy string."
            )

        # -----------------------------------------------------
        # Suspicious keywords
        # -----------------------------------------------------

        keywords = self.url_result.get(
            "suspicious_keywords",
            []
        )

        if keywords:

            points = min(
                2 + len(keywords),
                6
            )

            keyword_text = ", ".join(
                keywords
            )

            self.add_risk(
                points,
                "MEDIUM",
                f"Potentially phishing-related URL keywords were found: {keyword_text}"
            )

        # -----------------------------------------------------
        # Brand impersonation
        # -----------------------------------------------------

        brand_impersonation = self.url_result.get(
            "brand_impersonation_detected",
            []
        )

        if brand_impersonation:

            brand_text = ", ".join(
                brand_impersonation
            )

            self.add_risk(
                10,
                "HIGH",
                f"Possible brand impersonation was detected in the hostname: {brand_text}"
            )

        # -----------------------------------------------------
        # Suspicious URL patterns
        # -----------------------------------------------------
        #
        # Do NOT score patterns that already have dedicated
        # checks above.
        #
        # This prevents double counting.
        #

        patterns = self.url_result.get(
            "suspicious_patterns",
            []
        )

        ignored_patterns = {
            "multiple_hyphens_in_hostname",
            "ip_address",
            "at_symbol",
            "very_long_url",
            "percent_encoding"
        }

        independent_patterns = [
            pattern
            for pattern in patterns
            if pattern not in ignored_patterns
        ]

        if independent_patterns:

            points = min(
                len(independent_patterns) * 3,
                9
            )

            pattern_text = ", ".join(
                independent_patterns
            )

            self.add_risk(
                points,
                "MEDIUM",
                f"Suspicious URL patterns were detected: {pattern_text}"
            )

    # =========================================================
    # DNS ANALYSIS
    # =========================================================

    def analyze_dns_risk(self):

        resolution_failed = self.dns_result.get(
            "resolution_failed",
            False
        )

        if resolution_failed:

            self.add_risk(
                12,
                "HIGH",
                "DNS resolution failed for the hostname."
            )

            # Prevent a second finding for the same failure.
            return

        ip_addresses = self.dns_result.get(
            "ip_addresses",
            []
        )

        if not ip_addresses:

            self.add_risk(
                8,
                "MEDIUM",
                "The hostname did not resolve to an IP address."
            )

        elif len(ip_addresses) >= 8:

            self.add_risk(
                2,
                "LOW",
                "The hostname resolves to an unusually large number of IP addresses."
            )

    # =========================================================
    # HTTP ANALYSIS
    # =========================================================

    def analyze_http_risk(self):

        uses_http = self.http_result.get(
            "uses_http",
            False
        )

        uses_https = self.http_result.get(
            "uses_https",
            False
        )

        request_successful = self.http_result.get(
            "request_successful",
            False
        )

        status_code = self.http_result.get(
            "status_code"
        )

        # -----------------------------------------------------
        # HTTP
        # -----------------------------------------------------

        if uses_http and not uses_https:

            self.add_risk(
                10,
                "HIGH",
                "The URL uses unencrypted HTTP."
            )

        # -----------------------------------------------------
        # Request failure
        # -----------------------------------------------------
        #
        # Do not count this if DNS already failed because the
        # HTTP failure is probably a consequence of DNS failure.
        #

        elif (
            not request_successful
            and not self.dns_result.get(
                "resolution_failed",
                False
            )
        ):

            self.add_risk(
                3,
                "LOW",
                "The HTTP request could not be completed successfully."
            )

        # -----------------------------------------------------
        # Cross-domain redirect
        # -----------------------------------------------------

        if self.http_result.get(
            "cross_domain_redirect"
        ):

            self.add_risk(
                10,
                "HIGH",
                "The URL redirects to a different registered domain."
            )

        # -----------------------------------------------------
        # Redirect count
        # -----------------------------------------------------

        redirect_count = self.http_result.get(
            "redirect_count",
            0
        )

        if redirect_count >= 4:

            self.add_risk(
                3,
                "LOW",
                "The URL uses an unusually long redirect chain."
            )

        # -----------------------------------------------------
        # HTTP status
        # -----------------------------------------------------

        if isinstance(
            status_code,
            int
        ):

            if 500 <= status_code <= 599:

                self.add_risk(
                    2,
                    "LOW",
                    "The server returned a 5xx error."
                )

            elif status_code in (
                401,
                403
            ):

                self.add_risk(
                    1,
                    "LOW",
                    f"The server returned HTTP status {status_code}."
                )

        # -----------------------------------------------------
        # Security headers
        # -----------------------------------------------------

        missing_headers = self.http_result.get(
            "missing_security_headers",
            []
        )

        header_count = len(
            missing_headers
        )

        if header_count >= 6:

            self.add_risk(
                3,
                "LOW",
                "Many recommended security headers are missing."
            )

        elif header_count >= 4:

            self.add_risk(
                2,
                "LOW",
                "Several recommended security headers are missing."
            )

        elif header_count >= 2:

            self.add_risk(
                1,
                "LOW",
                "Some recommended security headers are missing."
            )

    # =========================================================
    # SSL ANALYSIS
    # =========================================================

    def analyze_ssl_risk(self):

        uses_http = self.http_result.get(
            "uses_http",
            False
        )

        uses_https = self.http_result.get(
            "uses_https",
            False
        )

        # SSL/TLS is relevant only for HTTPS.
        if uses_http and not uses_https:
            return

        if not uses_https:
            return

        ssl_available = self.ssl_result.get(
            "ssl_available",
            False
        )

        ssl_error = self.ssl_result.get(
            "ssl_error"
        )

        certificate_valid = self.ssl_result.get(
            "certificate_valid",
            False
        )

        certificate_expired = self.ssl_result.get(
            "certificate_expired",
            False
        )

        hostname_mismatch = self.ssl_result.get(
            "hostname_mismatch",
            False
        )

        weak_tls = self.ssl_result.get(
            "weak_tls_version",
            False
        )

        expires_soon = self.ssl_result.get(
            "expires_soon",
            False
        )

        # -----------------------------------------------------
        # SSL unavailable
        # -----------------------------------------------------

        if not ssl_available:

            self.add_risk(
                8,
                "MEDIUM",
                "HTTPS was requested but a valid TLS connection could not be established."
            )

            return

        # -----------------------------------------------------
        # SSL error
        # -----------------------------------------------------

        if ssl_error:

            self.add_risk(
                6,
                "MEDIUM",
                f"An SSL/TLS error occurred: {ssl_error}"
            )

        # -----------------------------------------------------
        # Certificate
        # -----------------------------------------------------

        if not certificate_valid:

            self.add_risk(
                10,
                "HIGH",
                "The SSL/TLS certificate is not currently valid."
            )

        if certificate_expired:

            self.add_risk(
                12,
                "HIGH",
                "The SSL/TLS certificate has expired."
            )

        # -----------------------------------------------------
        # Hostname mismatch
        # -----------------------------------------------------

        if hostname_mismatch:

            self.add_risk(
                12,
                "HIGH",
                "The SSL/TLS certificate hostname does not match the requested hostname."
            )

        # -----------------------------------------------------
        # Weak TLS
        # -----------------------------------------------------

        if weak_tls:

            self.add_risk(
                6,
                "MEDIUM",
                "The server is using a weak TLS version."
            )

        # -----------------------------------------------------
        # Certificate expiration
        # -----------------------------------------------------

        if expires_soon:

            self.add_risk(
                1,
                "LOW",
                "The SSL/TLS certificate expires soon."
            )

    # =========================================================
    # WHOIS ANALYSIS
    # =========================================================

    def analyze_whois_risk(self):

        whois_available = self.whois_result.get(
            "whois_available",
            False
        )

        if not whois_available:

            self.add_risk(
                1,
                "LOW",
                "WHOIS information could not be obtained."
            )

            return

        # -----------------------------------------------------
        # Newly registered
        # -----------------------------------------------------

        if self.whois_result.get(
            "newly_registered"
        ):

            self.add_risk(
                10,
                "HIGH",
                "The domain appears to have been registered recently."
            )

            return

        age_days = self.whois_result.get(
            "domain_age_days"
        )

        if isinstance(
            age_days,
            (int, float)
        ):

            if 31 <= age_days <= 90:

                self.add_risk(
                    5,
                    "MEDIUM",
                    "The domain is relatively new."
                )

            elif 91 <= age_days <= 180:

                self.add_risk(
                    2,
                    "LOW",
                    "The domain was registered fairly recently."
                )

    # =========================================================
    # HTML ANALYSIS
    # =========================================================

    def analyze_html_risk(self):

        # -----------------------------------------------------
        # Login form
        # -----------------------------------------------------

        if self.html_result.get(
            "login_form"
        ):

            self.add_risk(
                4,
                "LOW",
                "The webpage contains a possible login form."
            )

        # -----------------------------------------------------
        # Password fields
        # -----------------------------------------------------

        password_fields = self.html_result.get(
            "password_fields",
            0
        )

        if password_fields > 0:

            self.add_risk(
                4,
                "LOW",
                "The webpage contains password input fields."
            )

        # -----------------------------------------------------
        # External form actions
        # -----------------------------------------------------

        external_form_actions = self.html_result.get(
            "external_form_actions",
            []
        )

        if external_form_actions:

            self.add_risk(
                12,
                "HIGH",
                "A form submits data to an external domain."
            )

        # -----------------------------------------------------
        # Suspicious form actions
        # -----------------------------------------------------

        suspicious_form_actions = self.html_result.get(
            "suspicious_form_actions",
            []
        )

        if suspicious_form_actions:

            self.add_risk(
                10,
                "HIGH",
                "A form appears to submit sensitive information to a suspicious destination."
            )

        # -----------------------------------------------------
        # External iframes
        # -----------------------------------------------------

        external_iframes = self.html_result.get(
            "external_iframes",
            []
        )

        if external_iframes:

            self.add_risk(
                4,
                "LOW",
                "The webpage contains an iframe loaded from an external domain."
            )

        # -----------------------------------------------------
        # JavaScript redirects
        # -----------------------------------------------------

        javascript_redirects = self.html_result.get(
            "javascript_redirects",
            []
        )

        external_js_redirects = [
            redirect
            for redirect in javascript_redirects
            if redirect.get("external")
        ]

        if external_js_redirects:

            self.add_risk(
                6,
                "MEDIUM",
                "The webpage contains JavaScript redirects to external destinations."
            )

        # -----------------------------------------------------
        # Meta refresh
        # -----------------------------------------------------

        meta_refresh = self.html_result.get(
            "meta_refresh",
            []
        )

        if meta_refresh:

            self.add_risk(
                4,
                "LOW",
                "The webpage uses a meta-refresh redirect."
            )

        # -----------------------------------------------------
        # Phishing keywords
        # -----------------------------------------------------

        phishing_keywords = self.html_result.get(
            "phishing_keywords",
            []
        )

        weak_keywords = {
            "sign in",
            "login",
            "log in",
            "account"
        }

        meaningful_keywords = [
            keyword
            for keyword in phishing_keywords
            if keyword.lower() not in weak_keywords
        ]

        if meaningful_keywords:

            points = min(
                len(meaningful_keywords),
                4
            )

            keyword_text = ", ".join(
                meaningful_keywords
            )

            self.add_risk(
                points,
                "LOW",
                f"Potentially phishing-related webpage keywords were found: {keyword_text}"
            )

    # =========================================================
    # CALCULATE SCORE
    # =========================================================

    def calculate_score(self):

        self.score = 0
        self.findings = []

        self.analyze_url_risk()
        self.analyze_dns_risk()
        self.analyze_http_risk()
        self.analyze_ssl_risk()
        self.analyze_whois_risk()
        self.analyze_html_risk()

        self.score = max(
            0,
            min(
                self.score,
                100
            )
        )

        return self.score

    # =========================================================
    # RISK LEVEL
    # =========================================================

    def get_risk_level(self):

        if self.score >= 75:
            return "CRITICAL"

        if self.score >= 50:
            return "HIGH"

        if self.score >= 25:
            return "MEDIUM"

        if self.score >= 10:
            return "LOW"

        return "SAFE"

    # =========================================================
    # SUMMARY
    # =========================================================

    def get_summary(self):

        level = self.get_risk_level()

        if level == "SAFE":

            return (
                "The URL appears to be low risk based on "
                "the available analysis."
            )

        if level == "LOW":

            return (
                "The URL contains some potentially suspicious "
                "characteristics, but the evidence is limited."
            )

        if level == "MEDIUM":

            return (
                "The URL contains multiple suspicious "
                "characteristics that warrant caution."
            )

        if level == "HIGH":

            return (
                "The URL contains several strong indicators "
                "associated with phishing or malicious activity."
            )

        return (
            "The URL contains multiple strong indicators and "
            "should be treated as potentially malicious."
        )

    # =========================================================
    # FINAL RESULT
    # =========================================================

    def get_result(self):

        self.calculate_score()

        return {
            "risk_score": self.score,
            "risk_level": self.get_risk_level(),
            "summary": self.get_summary(),
            "findings": self.findings
        }


# =============================================================
# HELPER FUNCTION
# =============================================================

def calculate_risk(
    url_result,
    dns_result,
    http_result,
    ssl_result,
    whois_result,
    html_result
):

    engine = RiskEngine(
        url_result=url_result,
        dns_result=dns_result,
        http_result=http_result,
        ssl_result=ssl_result,
        whois_result=whois_result,
        html_result=html_result
    )

    return engine.get_result()


# =============================================================
# STANDALONE TEST
# =============================================================

if __name__ == "__main__":

    test_url = {
        "is_ip_address": False,
        "url_length": 60,
        "domain_length": 30,
        "has_at_symbol": False,
        "has_percent_encoding": False,
        "base64_like": False,
        "is_shortened": False,
        "suspicious_tld": False,
        "subdomain_count": 1,
        "multiple_hyphens": False,
        "multiple_dots": False,
        "high_entropy": False,
        "suspicious_keywords": [],
        "brand_impersonation_detected": [],
        "suspicious_patterns": []
    }

    test_dns = {
        "resolution_failed": False,
        "ip_addresses": [
            "142.250.72.14"
        ]
    }

    test_http = {
        "uses_http": False,
        "uses_https": True,
        "request_successful": True,
        "status_code": 200,
        "cross_domain_redirect": False,
        "redirect_count": 1,
        "missing_security_headers": []
    }

    test_ssl = {
        "ssl_available": True,
        "ssl_error": None,
        "certificate_valid": True,
        "certificate_expired": False,
        "hostname_mismatch": False,
        "weak_tls_version": False,
        "expires_soon": False
    }

    test_whois = {
        "whois_available": True,
        "newly_registered": False,
        "domain_age_days": 5000
    }

    test_html = {
        "login_form": False,
        "password_fields": 0,
        "external_form_actions": [],
        "suspicious_form_actions": [],
        "external_iframes": [],
        "javascript_redirects": [],
        "meta_refresh": [],
        "phishing_keywords": []
    }

    result = calculate_risk(
        test_url,
        test_dns,
        test_http,
        test_ssl,
        test_whois,
        test_html
    )

    print(
        "Risk Score :",
        result["risk_score"]
    )

    print(
        "Risk Level :",
        result["risk_level"]
    )

    print(
        "Summary    :",
        result["summary"]
    )

    print("\nFindings:")

    for finding in result["findings"]:

        print(
            f"[+{finding['points']}] "
            f"[{finding['level']}] "
            f"{finding['message']}"
        )