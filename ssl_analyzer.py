import ssl
import socket
from datetime import datetime, timezone


# ============================================================
# SSL / TLS ANALYZER
# ============================================================

class SSLAnalyzer:

    def __init__(
        self,
        hostname,
        port=443,
        timeout=10
    ):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.result = {
            "hostname": hostname,
            "port": port,

            "ssl_available": False,

            "tls_version": None,
            "cipher": None,

            "certificate_valid": False,
            "certificate_expired": False,

            "hostname_match": False,
            "hostname_mismatch": False,

            "valid_from": None,
            "valid_until": None,

            "days_remaining": None,
            "expires_soon": None,

            "weak_tls_version": False,

            "ssl_error": None
        }

    # ========================================================
    # HOSTNAME MATCHING
    # ========================================================

    @staticmethod
    def check_hostname_match(
        hostname,
        certificate
    ):
        """
        Check whether the hostname matches the certificate
        Subject Alternative Name (SAN) or Common Name (CN).
        """

        if not hostname or not certificate:
            return False

        hostname = hostname.lower().rstrip(".")

        # ----------------------------------------------------
        # Subject Alternative Name
        # ----------------------------------------------------

        san_entries = []

        for entry in certificate.get(
            "subjectAltName",
            []
        ):

            if len(entry) == 2:

                name_type, value = entry

                if name_type == "DNS":
                    san_entries.append(
                        value.lower().rstrip(".")
                    )

        # ----------------------------------------------------
        # Use SAN when available
        # ----------------------------------------------------

        if san_entries:

            for pattern in san_entries:

                if SSLAnalyzer.hostname_matches_pattern(
                    hostname,
                    pattern
                ):
                    return True

            return False

        # ----------------------------------------------------
        # Fall back to Common Name
        # ----------------------------------------------------

        common_names = []

        for subject_part in certificate.get(
            "subject",
            []
        ):

            for key, value in subject_part:

                if key == "commonName":

                    common_names.append(
                        value.lower().rstrip(".")
                    )

        for pattern in common_names:

            if SSLAnalyzer.hostname_matches_pattern(
                hostname,
                pattern
            ):
                return True

        return False

    # ========================================================
    # WILDCARD HOSTNAME MATCHING
    # ========================================================

    @staticmethod
    def hostname_matches_pattern(
        hostname,
        pattern
    ):
        """
        Safely match a hostname against a certificate DNS name.

        Supports certificates such as:

            *.google.com

        but does not allow a wildcard to match multiple
        hostname levels.
        """

        hostname = hostname.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")

        # Exact match
        if hostname == pattern:
            return True

        # Wildcard match
        if pattern.startswith("*."):

            suffix = pattern[1:]

            if not hostname.endswith(
                suffix
            ):
                return False

            hostname_labels = hostname.split(".")
            suffix_labels = suffix.lstrip(".").split(".")

            # Wildcard must represent exactly one label.
            if len(hostname_labels) != (
                len(suffix_labels) + 1
            ):
                return False

            return True

        return False

    # ========================================================
    # CERTIFICATE DATE PARSING
    # ========================================================

    @staticmethod
    def parse_certificate_date(
        date_string
    ):
        """
        Convert OpenSSL certificate date format into
        an aware datetime object.
        """

        if not date_string:
            return None

        try:

            # Example:
            # Aug 10 08:37:35 2026 GMT

            parsed = datetime.strptime(
                date_string,
                "%b %d %H:%M:%S %Y %Z"
            )

            return parsed.replace(
                tzinfo=timezone.utc
            )

        except ValueError:

            try:

                parsed = datetime.strptime(
                    date_string,
                    "%b %d %H:%M:%S %Y GMT"
                )

                return parsed.replace(
                    tzinfo=timezone.utc
                )

            except ValueError:

                return None

    # ========================================================
    # CERTIFICATE DATE ANALYSIS
    # ========================================================

    def analyze_certificate_dates(
        self,
        certificate
    ):
        """
        Calculate certificate validity and remaining lifetime.
        """

        valid_from_string = certificate.get(
            "notBefore"
        )

        valid_until_string = certificate.get(
            "notAfter"
        )

        valid_from = self.parse_certificate_date(
            valid_from_string
        )

        valid_until = self.parse_certificate_date(
            valid_until_string
        )

        self.result[
            "valid_from"
        ] = (
            valid_from.isoformat()
            if valid_from
            else None
        )

        self.result[
            "valid_until"
        ] = (
            valid_until.isoformat()
            if valid_until
            else None
        )

        now = datetime.now(
            timezone.utc
        )

        # ----------------------------------------------------
        # If we cannot parse the certificate dates
        # ----------------------------------------------------

        if not valid_from or not valid_until:

            self.result[
                "certificate_valid"
            ] = False

            self.result[
                "certificate_expired"
            ] = False

            self.result[
                "days_remaining"
            ] = None

            self.result[
                "expires_soon"
            ] = None

            return

        # ----------------------------------------------------
        # Certificate validity
        # ----------------------------------------------------

        self.result[
            "certificate_valid"
        ] = (
            valid_from <= now <= valid_until
        )

        # ----------------------------------------------------
        # Expiration
        # ----------------------------------------------------

        self.result[
            "certificate_expired"
        ] = (
            now > valid_until
        )

        # ----------------------------------------------------
        # Remaining lifetime
        # ----------------------------------------------------

        remaining_seconds = (
            valid_until - now
        ).total_seconds()

        days_remaining = max(
            0,
            int(
                remaining_seconds // 86400
            )
        )

        self.result[
            "days_remaining"
        ] = days_remaining

        # ----------------------------------------------------
        # Expiring within 30 days
        # ----------------------------------------------------

        self.result[
            "expires_soon"
        ] = (
            0 < days_remaining <= 30
        )

    # ========================================================
    # TLS SECURITY
    # ========================================================

    def analyze_tls_security(
        self,
        tls_version
    ):
        """
        Detect outdated TLS versions.
        """

        if not tls_version:
            self.result[
                "weak_tls_version"
            ] = False

            return

        weak_versions = {
            "SSLv2",
            "SSLv3",
            "TLSv1",
            "TLSv1.0",
            "TLSv1.1"
        }

        self.result[
            "weak_tls_version"
        ] = (
            tls_version in weak_versions
        )

    # ========================================================
    # SSL CONNECTION
    # ========================================================

    def analyze(self):

        context = ssl.create_default_context()

        # Explicitly enable hostname verification.
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:

            with socket.create_connection(
                (
                    self.hostname,
                    self.port
                ),
                timeout=self.timeout
            ) as raw_socket:

                with context.wrap_socket(
                    raw_socket,
                    server_hostname=self.hostname
                ) as ssl_socket:

                    self.result[
                        "ssl_available"
                    ] = True

                    # ------------------------------------------------
                    # TLS version
                    # ------------------------------------------------

                    self.result[
                        "tls_version"
                    ] = ssl_socket.version()

                    # ------------------------------------------------
                    # Cipher
                    # ------------------------------------------------

                    self.result[
                        "cipher"
                    ] = ssl_socket.cipher()

                    # ------------------------------------------------
                    # Certificate
                    # ------------------------------------------------

                    certificate = (
                        ssl_socket.getpeercert()
                    )

                    # ------------------------------------------------
                    # Hostname verification
                    #
                    # The TLS context has already performed
                    # hostname verification. We also inspect
                    # the certificate explicitly for reporting.
                    # ------------------------------------------------

                    hostname_match = (
                        self.check_hostname_match(
                            self.hostname,
                            certificate
                        )
                    )

                    self.result[
                        "hostname_match"
                    ] = hostname_match

                    self.result[
                        "hostname_mismatch"
                    ] = not hostname_match

                    # ------------------------------------------------
                    # Certificate dates
                    # ------------------------------------------------

                    self.analyze_certificate_dates(
                        certificate
                    )

                    # ------------------------------------------------
                    # TLS security
                    # ------------------------------------------------

                    self.analyze_tls_security(
                        self.result[
                            "tls_version"
                        ]
                    )

                    return self.result

        except ssl.SSLCertVerificationError as error:

            self.result[
                "ssl_available"
            ] = False

            self.result[
                "certificate_valid"
            ] = False

            self.result[
                "ssl_error"
            ] = (
                "Certificate verification failed: "
                + str(error)
            )

            return self.result

        except ssl.SSLError as error:

            self.result[
                "ssl_available"
            ] = False

            self.result[
                "ssl_error"
            ] = (
                "SSL/TLS error: "
                + str(error)
            )

            return self.result

        except socket.timeout:

            self.result[
                "ssl_available"
            ] = False

            self.result[
                "ssl_error"
            ] = (
                "SSL/TLS connection timed out."
            )

            return self.result

        except socket.gaierror as error:

            self.result[
                "ssl_available"
            ] = False

            self.result[
                "ssl_error"
            ] = (
                "Hostname resolution failed: "
                + str(error)
            )

            return self.result

        except ConnectionRefusedError:

            self.result[
                "ssl_available"
            ] = False

            self.result[
                "ssl_error"
            ] = (
                "Connection to the SSL/TLS port "
                "was refused."
            )

            return self.result

        except Exception as error:

            self.result[
                "ssl_available"
            ] = False

            self.result[
                "ssl_error"
            ] = (
                "Unexpected SSL/TLS error: "
                + str(error)
            )

            return self.result


# ============================================================
# HELPER FUNCTION
# ============================================================

def analyze_ssl(
    hostname,
    port=443,
    timeout=10
):
    """
    Convenience function used by main.py.
    """

    analyzer = SSLAnalyzer(
        hostname,
        port=port,
        timeout=timeout
    )

    return analyzer.analyze()


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_hostname = "google.com"

    print("=" * 70)
    print("SSL / TLS ANALYZER TEST")
    print("=" * 70)

    result = analyze_ssl(
        test_hostname
    )

    for key, value in result.items():

        print(
            f"{key:35}: {value}"
        )