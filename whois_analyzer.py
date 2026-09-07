import datetime
import whois


class WHOISAnalyzer:
    """
    Analyzes WHOIS information for a domain.

    Extracts:
    - Registrar
    - Creation date
    - Expiration date
    - Updated date
    - Domain age
    - Registration period
    - WHOIS availability/errors
    """

    def __init__(self, domain):
        self.domain = domain.strip().lower().rstrip(".")

        self.result = {
            "domain": self.domain,
            "whois_available": False,

            "registrar": None,

            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,

            "domain_age_days": None,
            "domain_age_years": None,

            "registration_period_days": None,

            "newly_registered": False,
            "expires_soon": False,

            "whois_error": None
        }

    # =========================================================
    # DATE HANDLING
    # =========================================================

    def normalize_date(self, value):
        """
        WHOIS libraries may return either a datetime object
        or a list of datetime objects.
        """

        if value is None:
            return None

        if isinstance(value, list):

            if not value:
                return None

            dates = [
                item for item in value
                if isinstance(item, datetime.datetime)
            ]

            if not dates:
                return None

            return min(dates)

        if isinstance(value, datetime.datetime):
            return value

        return None

    # =========================================================
    # WHOIS LOOKUP
    # =========================================================

    def lookup(self):
        """
        Perform the WHOIS lookup.
        """

        try:

            data = whois.whois(self.domain)

            if not data:
                return None

            self.result["whois_available"] = True

            # -------------------------------------------------
            # Registrar
            # -------------------------------------------------

            self.result["registrar"] = data.registrar

            # -------------------------------------------------
            # Dates
            # -------------------------------------------------

            creation_date = self.normalize_date(
                data.creation_date
            )

            expiration_date = self.normalize_date(
                data.expiration_date
            )

            updated_date = self.normalize_date(
                data.updated_date
            )

            self.result["creation_date"] = (
                creation_date.isoformat()
                if creation_date
                else None
            )

            self.result["expiration_date"] = (
                expiration_date.isoformat()
                if expiration_date
                else None
            )

            self.result["updated_date"] = (
                updated_date.isoformat()
                if updated_date
                else None
            )

            # -------------------------------------------------
            # Domain Age
            # -------------------------------------------------

            if creation_date:

                # Remove timezone information to avoid
                # timezone comparison problems.
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(
                        tzinfo=None
                    )

                now = datetime.datetime.now()

                age = now - creation_date

                self.result["domain_age_days"] = age.days

                self.result["domain_age_years"] = round(
                    age.days / 365.25,
                    2
                )

                # Domains younger than 30 days
                # receive a weak risk indicator.
                if 0 <= age.days <= 30:
                    self.result["newly_registered"] = True

            # -------------------------------------------------
            # Registration Period
            # -------------------------------------------------

            if creation_date and expiration_date:

                if expiration_date.tzinfo is not None:
                    expiration_date = expiration_date.replace(
                        tzinfo=None
                    )

                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(
                        tzinfo=None
                    )

                registration_period = (
                    expiration_date - creation_date
                )

                self.result[
                    "registration_period_days"
                ] = registration_period.days

            # -------------------------------------------------
            # Expiration
            # -------------------------------------------------

            if expiration_date:

                if expiration_date.tzinfo is not None:
                    expiration_date = expiration_date.replace(
                        tzinfo=None
                    )

                now = datetime.datetime.now()

                days_until_expiration = (
                    expiration_date - now
                ).days

                # Certificate/domain expiration within
                # 30 days is recorded as an informational
                # indicator.
                if 0 <= days_until_expiration <= 30:
                    self.result["expires_soon"] = True

            return data

        except Exception as error:

            self.result["whois_error"] = str(error)

            return None

    # =========================================================
    # ANALYSIS
    # =========================================================

    def analyze(self):
        """
        Run the complete WHOIS analysis.
        """

        if not self.domain:
            raise ValueError(
                "Domain cannot be empty."
            )

        self.lookup()

        return self.result


# =============================================================
# HELPER FUNCTION
# =============================================================

def analyze_whois(domain):
    """
    Convenience function for WHOIS analysis.
    """

    analyzer = WHOISAnalyzer(domain)

    return analyzer.analyze()


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    test_domain = "example.com"

    result = analyze_whois(test_domain)

    print("\n" + "=" * 60)
    print("WHOIS DOMAIN ANALYSIS")
    print("=" * 60)

    for key, value in result.items():
        print(f"{key:30}: {value}")

    print("=" * 60)