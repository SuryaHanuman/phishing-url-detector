import urllib.request
import urllib.error
from urllib.parse import urlparse


# ============================================================
# REDIRECT COUNTER
# ============================================================

class RedirectCounter(urllib.request.HTTPRedirectHandler):
    """
    Records every HTTP redirect encountered during a request.
    """

    def __init__(self):
        super().__init__()
        self.redirects = []

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl
    ):
        self.redirects.append({
            "status_code": code,
            "from_url": req.full_url,
            "to_url": newurl
        })

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl
        )


# ============================================================
# HTTP ANALYZER
# ============================================================

class HTTPAnalyzer:

    def __init__(
        self,
        url,
        timeout=10,
        max_redirects=5
    ):
        self.url = url
        self.timeout = timeout
        self.max_redirects = max_redirects

        self.result = {
            "url": url,
            "request_successful": False,
            "status_code": None,
            "reason": None,
            "final_url": None,

            "uses_http": False,
            "uses_https": False,

            "redirected": False,
            "redirect_count": 0,
            "redirects": [],

            "hostname_changed": False,
            "same_registered_domain": None,
            "cross_domain_redirect": False,

            "final_hostname": None,
            "redirect_domain_changes": [],

            "content_type": None,
            "content_length": None,
            "server": None,

            "security_headers": {},
            "missing_security_headers": [],

            "html_available": False,
            "html_content": "",
            "response_size": 0,

            "error": None
        }

    # ========================================================
    # HOSTNAME NORMALIZATION
    # ========================================================

    @staticmethod
    def normalize_hostname(hostname):
        """
        Normalize a hostname for comparison.
        """

        if not hostname:
            return ""

        hostname = hostname.lower().strip()

        if hostname.endswith("."):
            hostname = hostname[:-1]

        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname

    # ========================================================
    # REGISTERED DOMAIN
    # ========================================================

    @staticmethod
    def get_base_domain(hostname):
        """
        Approximate registered-domain extraction.

        This is a heuristic implementation and does not use
        the Public Suffix List.
        """

        hostname = HTTPAnalyzer.normalize_hostname(
            hostname
        )

        if not hostname:
            return ""

        parts = hostname.split(".")

        if len(parts) <= 2:
            return hostname

        # Common second-level public suffixes.
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
            "co.jp",
            "ne.jp",
            "or.jp",
            "com.br",
            "com.cn",
            "com.sg",
            "com.my",
            "co.nz"
        }

        last_two = ".".join(parts[-2:])

        if last_two in second_level_suffixes:

            if len(parts) >= 3:
                return ".".join(parts[-3:])

            return hostname

        return ".".join(parts[-2:])

    # ========================================================
    # REDIRECT ANALYSIS
    # ========================================================

    def analyze_redirects(self):

        redirects = self.result.get(
            "redirects",
            []
        )

        self.result["redirect_count"] = len(
            redirects
        )

        self.result["redirected"] = bool(
            redirects
        )

        if not redirects:
            return

        original_hostname = self.normalize_hostname(
            urlparse(
                self.url
            ).hostname
        )

        final_url = self.result.get(
            "final_url"
        )

        final_hostname = self.normalize_hostname(
            urlparse(
                final_url or self.url
            ).hostname
        )

        self.result["final_hostname"] = (
            final_hostname
        )

        original_base = self.get_base_domain(
            original_hostname
        )

        final_base = self.get_base_domain(
            final_hostname
        )

        self.result["same_registered_domain"] = (
            original_base == final_base
        )

        self.result["cross_domain_redirect"] = (
            original_base != final_base
        )

        self.result["hostname_changed"] = (
            original_hostname != final_hostname
        )

        domain_changes = []

        previous_url = self.url

        for redirect in redirects:

            from_url = redirect.get(
                "from_url",
                previous_url
            )

            to_url = redirect.get(
                "to_url"
            )

            from_hostname = self.normalize_hostname(
                urlparse(
                    from_url
                ).hostname
            )

            to_hostname = self.normalize_hostname(
                urlparse(
                    to_url
                ).hostname
            )

            if from_hostname != to_hostname:

                domain_changes.append({
                    "from_hostname": from_hostname,
                    "to_hostname": to_hostname,
                    "same_registered_domain": (
                        self.get_base_domain(
                            from_hostname
                        )
                        ==
                        self.get_base_domain(
                            to_hostname
                        )
                    )
                })

            previous_url = to_url

        self.result[
            "redirect_domain_changes"
        ] = domain_changes

    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    def analyze_security_headers(self, headers):

        security_headers = {
            "Strict-Transport-Security":
                headers.get(
                    "Strict-Transport-Security"
                ),

            "Content-Security-Policy":
                headers.get(
                    "Content-Security-Policy"
                ),

            "X-Frame-Options":
                headers.get(
                    "X-Frame-Options"
                ),

            "X-Content-Type-Options":
                headers.get(
                    "X-Content-Type-Options"
                ),

            "Referrer-Policy":
                headers.get(
                    "Referrer-Policy"
                ),

            "Permissions-Policy":
                headers.get(
                    "Permissions-Policy"
                )
        }

        self.result[
            "security_headers"
        ] = security_headers

        missing_headers = []

        for name, value in security_headers.items():

            if not value:
                missing_headers.append(
                    name
                )

        self.result[
            "missing_security_headers"
        ] = missing_headers

    # ========================================================
    # HTML EXTRACTION
    # ========================================================

    def extract_html(
        self,
        response
    ):

        content_type = (
            response.headers.get(
                "Content-Type",
                ""
            )
            or ""
        ).lower()

        # Only treat HTML/XHTML responses as webpage content.
        is_html = (
            "text/html" in content_type
            or
            "application/xhtml+xml"
            in content_type
        )

        if not is_html:
            self.result[
                "html_available"
            ] = False

            self.result[
                "html_content"
            ] = ""

            return

        try:

            # Limit the amount of HTML stored in memory.
            max_html_size = 2 * 1024 * 1024

            raw_data = response.read(
                max_html_size
            )

            self.result[
                "response_size"
            ] = len(raw_data)

            encoding = response.headers.get_content_charset()

            if not encoding:
                encoding = "utf-8"

            try:
                html_content = raw_data.decode(
                    encoding,
                    errors="replace"
                )

            except LookupError:

                html_content = raw_data.decode(
                    "utf-8",
                    errors="replace"
                )

            self.result[
                "html_content"
            ] = html_content

            self.result[
                "html_available"
            ] = bool(html_content)

            # Keep this alias for compatibility with
            # older versions of the project.
            self.result[
                "html"
            ] = html_content

            self.result[
                "content_length"
            ] = len(raw_data)

        except Exception as error:

            self.result[
                "html_available"
            ] = False

            self.result[
                "html_content"
            ] = ""

            self.result[
                "html_error"
            ] = str(error)

    # ========================================================
    # ANALYZE
    # ========================================================

    def analyze(self):

        parsed = urlparse(
            self.url
        )

        self.result[
            "uses_http"
        ] = parsed.scheme.lower() == "http"

        self.result[
            "uses_https"
        ] = parsed.scheme.lower() == "https"

        # ----------------------------------------------------
        # Redirect handler
        # ----------------------------------------------------

        redirect_handler = RedirectCounter()

        opener = urllib.request.build_opener(
            redirect_handler
        )

        # ----------------------------------------------------
        # Request headers
        # ----------------------------------------------------

        request = urllib.request.Request(
            self.url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/131.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,"
                    "application/xhtml+xml,"
                    "application/xml;q=0.9,"
                    "*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.9"
            },
            method="GET"
        )

        # ----------------------------------------------------
        # Perform request
        # ----------------------------------------------------

        try:

            response = opener.open(
                request,
                timeout=self.timeout
            )

            self.result[
                "request_successful"
            ] = True

            self.result[
                "status_code"
            ] = response.getcode()

            self.result[
                "reason"
            ] = getattr(
                response,
                "reason",
                None
            )

            self.result[
                "final_url"
            ] = response.geturl()

            self.result[
                "redirects"
            ] = redirect_handler.redirects

            self.result[
                "redirect_count"
            ] = len(
                redirect_handler.redirects
            )

            self.result[
                "redirected"
            ] = bool(
                redirect_handler.redirects
            )

            self.result[
                "content_type"
            ] = response.headers.get(
                "Content-Type"
            )

            self.result[
                "server"
            ] = response.headers.get(
                "Server"
            )

            # ------------------------------------------------
            # Content-Length
            # ------------------------------------------------

            content_length_header = (
                response.headers.get(
                    "Content-Length"
                )
            )

            if content_length_header:

                try:

                    self.result[
                        "content_length"
                    ] = int(
                        content_length_header
                    )

                except ValueError:

                    self.result[
                        "content_length"
                    ] = None

            # ------------------------------------------------
            # Security headers
            # ------------------------------------------------

            self.analyze_security_headers(
                response.headers
            )

            # ------------------------------------------------
            # HTML
            # ------------------------------------------------

            self.extract_html(
                response
            )

            response.close()

            # ------------------------------------------------
            # Redirect analysis
            # ------------------------------------------------

            self.analyze_redirects()

            return self.result

        except urllib.error.HTTPError as error:

            self.result[
                "request_successful"
            ] = False

            self.result[
                "status_code"
            ] = error.code

            self.result[
                "reason"
            ] = error.reason

            self.result[
                "final_url"
            ] = error.geturl()

            self.result[
                "error"
            ] = (
                f"HTTP Error {error.code}: "
                f"{error.reason}"
            )

            self.result[
                "redirects"
            ] = redirect_handler.redirects

            self.result[
                "redirect_count"
            ] = len(
                redirect_handler.redirects
            )

            self.analyze_redirects()

            return self.result

        except urllib.error.URLError as error:

            self.result[
                "request_successful"
            ] = False

            self.result[
                "error"
            ] = str(
                error.reason
            )

            self.result[
                "redirects"
            ] = redirect_handler.redirects

            self.result[
                "redirect_count"
            ] = len(
                redirect_handler.redirects
            )

            self.analyze_redirects()

            return self.result

        except Exception as error:

            self.result[
                "request_successful"
            ] = False

            self.result[
                "error"
            ] = str(error)

            self.result[
                "redirects"
            ] = redirect_handler.redirects

            self.result[
                "redirect_count"
            ] = len(
                redirect_handler.redirects
            )

            self.analyze_redirects()

            return self.result


# ============================================================
# HELPER FUNCTION
# ============================================================

def analyze_http(
    url,
    timeout=10,
    max_redirects=5
):
    """
    Convenience function used by main.py.
    """

    analyzer = HTTPAnalyzer(
        url,
        timeout=timeout,
        max_redirects=max_redirects
    )

    return analyzer.analyze()


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://google.com"

    print("=" * 70)
    print("HTTP ANALYZER TEST")
    print("=" * 70)

    result = analyze_http(
        test_url
    )

    for key, value in result.items():
        print(
            f"{key:35}: {value}"
        )