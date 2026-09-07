import re
import base64
import ipaddress
import math

from urllib.parse import (
    urlparse,
    unquote
)


class URLAnalyzer:
    """
    Performs static analysis of a URL.

    This analyzer does not make network requests.
    It extracts lexical and structural characteristics
    that can be used by the risk engine.
    """

    # ---------------------------------------------------------
    # Generic suspicious keywords
    # ---------------------------------------------------------

    SUSPICIOUS_KEYWORDS = [
        "login",
        "signin",
        "verify",
        "account",
        "password",
        "bank",
        "secure",
        "update",
        "confirm",
        "wallet",
        "payment",
        "billing",
        "invoice",
        "recover",
        "suspend",
        "unlock",
        "authorize",
        "authentication"
    ]

    # ---------------------------------------------------------
    # Brands
    # ---------------------------------------------------------

    BRANDS = {
        "paypal": [
            "paypal.com"
        ],
        "microsoft": [
            "microsoft.com",
            "live.com",
            "outlook.com"
        ],
        "google": [
            "google.com"
        ],
        "apple": [
            "apple.com"
        ],
        "amazon": [
            "amazon.com"
        ],
        "facebook": [
            "facebook.com"
        ],
        "instagram": [
            "instagram.com"
        ],
        "netflix": [
            "netflix.com"
        ]
    }

    # ---------------------------------------------------------
    # Suspicious TLDs
    # ---------------------------------------------------------

    SUSPICIOUS_TLDS = {
        "zip",
        "mov",
        "click",
        "top",
        "xyz",
        "work",
        "country",
        "gq",
        "tk",
        "ml",
        "ga",
        "cf"
    }

    # ---------------------------------------------------------
    # URL shortening services
    # ---------------------------------------------------------

    SHORTENING_SERVICES = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "buff.ly",
        "ow.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at"
    }

    # ---------------------------------------------------------
    # Constructor
    # ---------------------------------------------------------

    def __init__(self, url):

        self.original_url = url.strip()

        self.normalized_url = self.normalize_url()

        self.parsed_url = urlparse(
            self.normalized_url
        )

        self.scheme = self.parsed_url.scheme.lower()

        self.hostname = (
            self.parsed_url.hostname or ""
        ).lower()

        self.path = (
            self.parsed_url.path or ""
        )

        self.query = (
            self.parsed_url.query or ""
        )

        self.fragment = (
            self.parsed_url.fragment or ""
        )

    # =========================================================
    # URL NORMALIZATION
    # =========================================================

    def normalize_url(self):

        url = self.original_url.strip()

        # Add scheme when user enters a bare domain.
        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            url
        ):
            url = "http://" + url

        return url

    # =========================================================
    # IP ADDRESS DETECTION
    # =========================================================

    def is_ip_address(self):

        if not self.hostname:
            return False

        try:

            ipaddress.ip_address(
                self.hostname
            )

            return True

        except ValueError:

            return False

    # =========================================================
    # DOMAIN INFORMATION
    # =========================================================

    def get_domain_length(self):

        return len(self.hostname)

    def get_subdomain_count(self):

        if not self.hostname:
            return 0

        # An IP address should not be interpreted as a
        # multi-level domain.
        if self.is_ip_address():
            return 0

        parts = self.hostname.split(".")

        if len(parts) <= 2:
            return 0

        return len(parts) - 2

    def get_dot_count(self):

        return self.hostname.count(".")

    def get_hyphen_count(self):

        return self.hostname.count("-")

    def get_digit_count(self):

        return sum(
            character.isdigit()
            for character in self.hostname
        )

    # =========================================================
    # SPECIAL CHARACTER RATIO
    # =========================================================

    def get_special_character_ratio(self):

        if not self.normalized_url:
            return 0.0

        special_characters = sum(
            1
            for character in self.normalized_url
            if not character.isalnum()
        )

        return round(
            special_characters /
            len(self.normalized_url),
            4
        )

    # =========================================================
    # URL PARAMETERS
    # =========================================================

    def get_parameter_count(self):

        if not self.query:
            return 0

        return self.query.count("&") + 1

    # =========================================================
    # ENTROPY
    # =========================================================

    def calculate_entropy(self, value):

        if not value:
            return 0.0

        frequencies = {}

        for character in value:

            frequencies[character] = (
                frequencies.get(character, 0) + 1
            )

        length = len(value)

        entropy = 0.0

        for count in frequencies.values():

            probability = count / length

            entropy -= (
                probability *
                math.log2(probability)
            )

        return round(
            entropy,
            4
        )

    def get_domain_entropy(self):

        return self.calculate_entropy(
            self.hostname
        )

    # =========================================================
    # ENCODING DETECTION
    # =========================================================

    def has_percent_encoding(self):

        return bool(
            re.search(
                r"%[0-9a-fA-F]{2}",
                self.normalized_url
            )
        )

    def is_base64_like(self):

        decoded_part = unquote(
            self.normalized_url
        )

        candidates = re.findall(
            r"[A-Za-z0-9+/]{16,}={0,2}",
            decoded_part
        )

        for candidate in candidates:

            # Base64 length should normally be divisible
            # by four after padding.
            padding = len(candidate) % 4

            if padding:
                candidate += "=" * (
                    4 - padding
                )

            try:

                decoded = base64.b64decode(
                    candidate,
                    validate=True
                )

                if decoded:

                    return True

            except Exception:

                continue

        return False

    # =========================================================
    # URL SHORTENER
    # =========================================================

    def is_shortened_url(self):

        hostname = self.hostname.lower()

        # Remove www. for comparison.
        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname in self.SHORTENING_SERVICES

    # =========================================================
    # SUSPICIOUS TLD
    # =========================================================

    def has_suspicious_tld(self):

        if self.is_ip_address():
            return False

        parts = self.hostname.split(".")

        if len(parts) < 2:
            return False

        tld = parts[-1].lower()

        return tld in self.SUSPICIOUS_TLDS

    # =========================================================
    # SUSPICIOUS KEYWORDS
    # =========================================================

    def detect_suspicious_keywords(self):

        decoded_url = unquote(
            self.normalized_url
        ).lower()

        detected = []

        for keyword in self.SUSPICIOUS_KEYWORDS:

            if keyword in decoded_url:

                detected.append(
                    keyword
                )

        return detected

    # =========================================================
    # BRAND DETECTION
    # =========================================================

    def detect_brand_names(self):

        hostname = self.hostname.lower()

        detected = []

        for brand in self.BRANDS:

            if brand in hostname:

                detected.append(
                    brand
                )

        return detected

    # =========================================================
    # REGISTERED DOMAIN
    # =========================================================

    def get_registered_domain(self, hostname=None):

        if hostname is None:
            hostname = self.hostname

        hostname = hostname.lower().strip(".")

        if not hostname:
            return ""

        # IP addresses do not have a registered domain.
        try:

            ipaddress.ip_address(
                hostname
            )

            return hostname

        except ValueError:

            pass

        parts = hostname.split(".")

        if len(parts) <= 2:
            return hostname

        # Common second-level public suffixes.
        #
        # This is intentionally lightweight. A full Public
        # Suffix List implementation can be added later.
        second_level_suffixes = {
            "co.uk",
            "org.uk",
            "ac.uk",
            "gov.uk",
            "com.au",
            "net.au",
            "org.au",
            "co.in",
            "firm.in",
            "net.in",
            "org.in",
            "gen.in",
            "ind.in",
            "com.br",
            "com.cn",
            "com.sg",
            "com.my",
            "co.jp",
            "co.nz"
        }

        last_two = ".".join(
            parts[-2:]
        )

        if last_two in second_level_suffixes:

            if len(parts) >= 3:

                return ".".join(
                    parts[-3:]
                )

            return hostname

        return ".".join(
            parts[-2:]
        )

    # =========================================================
    # BRAND IMPERSONATION
    # =========================================================

    def detect_brand_impersonation(self):

        hostname = self.hostname.lower()

        if not hostname:
            return []

        registered_domain = (
            self.get_registered_domain(
                hostname
            )
        )

        detected = []

        for brand, legitimate_domains in self.BRANDS.items():

            # Brand isn't present in hostname.
            if brand not in hostname:
                continue

            # -------------------------------------------------
            # Legitimate domain check
            # -------------------------------------------------
            #
            # Example:
            #
            # accounts.google.com
            #
            # registered domain = google.com
            #
            # Therefore Google is legitimate.
            #

            legitimate = False

            for legitimate_domain in legitimate_domains:

                legitimate_domain = (
                    legitimate_domain.lower()
                )

                legitimate_registered_domain = (
                    self.get_registered_domain(
                        legitimate_domain
                    )
                )

                if registered_domain == (
                    legitimate_registered_domain
                ):

                    legitimate = True
                    break

            if legitimate:
                continue

            # -------------------------------------------------
            # Brand is present but registered domain belongs
            # to somebody else.
            # -------------------------------------------------

            detected.append(
                brand
            )

        return detected

    # =========================================================
    # SUSPICIOUS URL PATTERNS
    # =========================================================

    def detect_suspicious_patterns(self):

        patterns = []

        hostname = self.hostname.lower()

        # Multiple hyphens
        if hostname.count("-") >= 2:

            patterns.append(
                "multiple_hyphens_in_hostname"
            )

        # Excessive subdomains
        if self.get_subdomain_count() >= 4:

            patterns.append(
                "excessive_subdomains"
            )

        # @ symbol
        if "@" in self.normalized_url:

            patterns.append(
                "at_symbol"
            )

        # Very long URL
        if len(self.normalized_url) >= 150:

            patterns.append(
                "very_long_url"
            )

        # Encoded URL
        if self.has_percent_encoding():

            patterns.append(
                "percent_encoding"
            )

        # IP address
        if self.is_ip_address():

            patterns.append(
                "ip_address"
            )

        return patterns

    # =========================================================
    # COMPLETE ANALYSIS
    # =========================================================

    def analyze(self):

        is_ip = self.is_ip_address()

        return {
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,

            "scheme": self.scheme,
            "hostname": self.hostname,

            "url_length": len(
                self.normalized_url
            ),

            "domain_length": self.get_domain_length(),

            "subdomain_count": self.get_subdomain_count(),

            "dot_count": self.get_dot_count(),

            "hyphen_count": self.get_hyphen_count(),

            "digit_count": self.get_digit_count(),

            "special_character_ratio":
                self.get_special_character_ratio(),

            "parameter_count":
                self.get_parameter_count(),

            "domain_entropy":
                self.get_domain_entropy(),

            # IMPORTANT:
            # Always return a boolean.
            "is_ip_address": is_ip,

            "is_shortened":
                self.is_shortened_url(),

            "suspicious_tld":
                self.has_suspicious_tld(),

            "has_percent_encoding":
                self.has_percent_encoding(),

            "base64_like":
                self.is_base64_like(),

            "suspicious_keywords":
                self.detect_suspicious_keywords(),

            "brand_names_detected":
                self.detect_brand_names(),

            "brand_impersonation_detected":
                self.detect_brand_impersonation(),

            "multiple_hyphens":
                self.get_hyphen_count() >= 2,

            "multiple_dots":
                self.get_dot_count() >= 3,

            "high_entropy":
                self.get_domain_entropy() >= 3.8,

            "suspicious_patterns":
                self.detect_suspicious_patterns()
        }


# =============================================================
# STANDALONE TEST
# =============================================================

if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://accounts.google.com",
        "http://192.0.2.10/login/verify",
        "http://paypal-login-security.example.com/verify/account"
    ]

    for test_url in test_urls:

        print("\n" + "=" * 70)
        print("Testing:", test_url)
        print("=" * 70)

        analyzer = URLAnalyzer(
            test_url
        )

        result = analyzer.analyze()

        print(
            "Hostname:",
            result["hostname"]
        )

        print(
            "Uses IP Address:",
            result["is_ip_address"]
        )

        print(
            "Brand Names:",
            result["brand_names_detected"]
        )

        print(
            "Brand Impersonation:",
            result["brand_impersonation_detected"]
        )

        print(
            "Suspicious Keywords:",
            result["suspicious_keywords"]
        )

        print(
            "Suspicious Patterns:",
            result["suspicious_patterns"]
        )