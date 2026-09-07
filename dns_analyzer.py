import socket
import dns.resolver
import dns.exception


class DNSAnalyzer:
    """
    Performs DNS analysis on a domain.

    The analyzer collects:
    - IPv4 (A) records
    - IPv6 (AAAA) records
    - MX records
    - NS records
    - TXT records
    - CNAME records
    - Canonical hostname
    - DNS resolution status
    """

    def __init__(self, hostname):
        self.hostname = hostname.strip().lower()

        # Remove trailing dot if present
        self.hostname = self.hostname.rstrip(".")

        self.result = {
            "hostname": self.hostname,

            "resolution_failed": False,

            "ip_addresses": [],
            "ipv4_addresses": [],
            "ipv6_addresses": [],

            "canonical_hostname": None,
            "aliases": [],

            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],

            "no_a_record": False,
            "no_aaaa_record": False,
            "no_mx_record": False,
            "no_ns_record": False,

            "dns_errors": []
        }

    # =========================================================
    # BASIC SOCKET DNS RESOLUTION
    # =========================================================

    def resolve_hostname(self):
        """
        Resolve the hostname using Python's socket library.

        This provides a simple first-level DNS resolution.
        """

        try:
            hostname_info = socket.gethostbyname_ex(
                self.hostname
            )

            canonical_name = hostname_info[0]
            aliases = hostname_info[1]
            addresses = hostname_info[2]

            self.result["canonical_hostname"] = canonical_name
            self.result["aliases"] = aliases
            self.result["ip_addresses"] = addresses

            self.result["ipv4_addresses"] = addresses

            return addresses

        except socket.gaierror as error:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                f"Hostname resolution failed: {error}"
            )

            return []

        except Exception as error:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                f"Unexpected DNS resolution error: {error}"
            )

            return []

    # =========================================================
    # A RECORD
    # =========================================================

    def get_a_records(self):
        """
        Retrieve IPv4 A records.
        """

        records = []

        try:
            answers = dns.resolver.resolve(
                self.hostname,
                "A"
            )

            for answer in answers:
                records.append(answer.to_text())

        except dns.resolver.NoAnswer:

            self.result["no_a_record"] = True

        except dns.resolver.NXDOMAIN:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                "The domain does not exist (NXDOMAIN)."
            )

        except dns.exception.DNSException as error:

            self.result["dns_errors"].append(
                f"A record lookup failed: {error}"
            )

        self.result["a_records"] = records

        return records

    # =========================================================
    # AAAA RECORD
    # =========================================================

    def get_aaaa_records(self):
        """
        Retrieve IPv6 AAAA records.
        """

        records = []

        try:
            answers = dns.resolver.resolve(
                self.hostname,
                "AAAA"
            )

            for answer in answers:
                records.append(answer.to_text())

        except dns.resolver.NoAnswer:

            self.result["no_aaaa_record"] = True

        except dns.resolver.NXDOMAIN:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                "The domain does not exist (NXDOMAIN)."
            )

        except dns.exception.DNSException as error:

            self.result["dns_errors"].append(
                f"AAAA record lookup failed: {error}"
            )

        self.result["aaaa_records"] = records

        return records

    # =========================================================
    # MX RECORD
    # =========================================================

    def get_mx_records(self):
        """
        Retrieve mail exchange records.

        MX records indicate which mail servers handle
        email for the domain.
        """

        records = []

        try:
            answers = dns.resolver.resolve(
                self.hostname,
                "MX"
            )

            for answer in answers:

                exchange = str(answer.exchange).rstrip(".")

                records.append({
                    "preference": answer.preference,
                    "exchange": exchange
                })

        except dns.resolver.NoAnswer:

            self.result["no_mx_record"] = True

        except dns.resolver.NXDOMAIN:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                "The domain does not exist (NXDOMAIN)."
            )

        except dns.exception.DNSException as error:

            self.result["dns_errors"].append(
                f"MX record lookup failed: {error}"
            )

        self.result["mx_records"] = records

        return records

    # =========================================================
    # NS RECORD
    # =========================================================

    def get_ns_records(self):
        """
        Retrieve authoritative name servers.
        """

        records = []

        try:
            answers = dns.resolver.resolve(
                self.hostname,
                "NS"
            )

            for answer in answers:

                records.append(
                    str(answer.target).rstrip(".")
                )

        except dns.resolver.NoAnswer:

            self.result["no_ns_record"] = True

        except dns.resolver.NXDOMAIN:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                "The domain does not exist (NXDOMAIN)."
            )

        except dns.exception.DNSException as error:

            self.result["dns_errors"].append(
                f"NS record lookup failed: {error}"
            )

        self.result["ns_records"] = records

        return records

    # =========================================================
    # TXT RECORD
    # =========================================================

    def get_txt_records(self):
        """
        Retrieve TXT records.

        TXT records can contain information such as:
        - SPF
        - domain verification
        - other DNS metadata
        """

        records = []

        try:
            answers = dns.resolver.resolve(
                self.hostname,
                "TXT"
            )

            for answer in answers:

                record = "".join(
                    part.decode("utf-8", errors="replace")
                    if isinstance(part, bytes)
                    else str(part)
                    for part in answer.strings
                )

                records.append(record)

        except dns.resolver.NoAnswer:
            pass

        except dns.resolver.NXDOMAIN:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                "The domain does not exist (NXDOMAIN)."
            )

        except dns.exception.DNSException as error:

            self.result["dns_errors"].append(
                f"TXT record lookup failed: {error}"
            )

        self.result["txt_records"] = records

        return records

    # =========================================================
    # CNAME RECORD
    # =========================================================

    def get_cname_records(self):
        """
        Retrieve canonical name records.
        """

        records = []

        try:
            answers = dns.resolver.resolve(
                self.hostname,
                "CNAME"
            )

            for answer in answers:

                records.append(
                    str(answer.target).rstrip(".")
                )

        except dns.resolver.NoAnswer:
            pass

        except dns.resolver.NXDOMAIN:

            self.result["resolution_failed"] = True

            self.result["dns_errors"].append(
                "The domain does not exist (NXDOMAIN)."
            )

        except dns.exception.DNSException as error:

            self.result["dns_errors"].append(
                f"CNAME record lookup failed: {error}"
            )

        self.result["cname_records"] = records

        return records

    # =========================================================
    # IPv6 SOCKET RESOLUTION
    # =========================================================

    def get_ipv6_addresses(self):
        """
        Retrieve IPv6 addresses using socket resolution.
        """

        ipv6_addresses = []

        try:

            results = socket.getaddrinfo(
                self.hostname,
                None,
                socket.AF_INET6
            )

            for result in results:

                address = result[4][0]

                if address not in ipv6_addresses:
                    ipv6_addresses.append(address)

        except socket.gaierror:
            pass

        except Exception as error:

            self.result["dns_errors"].append(
                f"IPv6 resolution failed: {error}"
            )

        self.result["ipv6_addresses"] = ipv6_addresses

        self.result["aaaa_records"] = list(
            set(
                self.result["aaaa_records"]
                + ipv6_addresses
            )
        )

        return ipv6_addresses

    # =========================================================
    # COMBINE IP ADDRESSES
    # =========================================================

    def combine_ip_addresses(self):
        """
        Combine IPv4 and IPv6 addresses into one list.
        """

        addresses = []

        for address in (
            self.result["ipv4_addresses"]
            + self.result["ipv6_addresses"]
        ):

            if address not in addresses:
                addresses.append(address)

        self.result["ip_addresses"] = addresses

        return addresses

    # =========================================================
    # DNS SERVER INFORMATION
    # =========================================================

    def get_resolver_nameservers(self):
        """
        Return the DNS resolver nameservers being used
        by dnspython.
        """

        try:

            resolver = dns.resolver.Resolver()

            return resolver.nameservers

        except Exception:

            return []

    # =========================================================
    # DNS ANALYSIS
    # =========================================================

    def analyze(self):
        """
        Run the complete DNS analysis.
        """

        if not self.hostname:
            raise ValueError(
                "Hostname cannot be empty."
            )

        # Basic hostname resolution
        self.resolve_hostname()

        # DNS record analysis
        self.get_a_records()
        self.get_aaaa_records()
        self.get_mx_records()
        self.get_ns_records()
        self.get_txt_records()
        self.get_cname_records()

        # IPv6 resolution
        self.get_ipv6_addresses()

        # Combine addresses
        self.combine_ip_addresses()

        # Resolver information
        self.result["resolver_nameservers"] = (
            self.get_resolver_nameservers()
        )

        return self.result


# =============================================================
# HELPER FUNCTION
# =============================================================

def analyze_dns(hostname):
    """
    Convenience function for DNS analysis.
    """

    analyzer = DNSAnalyzer(hostname)

    return analyzer.analyze()


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    test_domain = "example.com"

    result = analyze_dns(test_domain)

    print("\n" + "=" * 60)
    print("DNS SECURITY ANALYSIS")
    print("=" * 60)

    for key, value in result.items():
        print(f"{key:30}: {value}")

    print("=" * 60)