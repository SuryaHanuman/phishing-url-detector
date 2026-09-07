from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup


class HTMLAnalyzer:
    """
    Analyzes HTML content for indicators that may be relevant
    to phishing detection.

    This analyzer does NOT execute JavaScript.
    It only performs static inspection of HTML and script text.
    """

    PHISHING_KEYWORDS = {
        "verify your account",
        "verify account",
        "confirm your account",
        "confirm account",
        "login",
        "log in",
        "sign in",
        "password",
        "credential",
        "security alert",
        "account suspended",
        "account locked",
        "unlock your account",
        "update your payment",
        "payment verification",
        "billing information",
        "bank account",
        "credit card",
        "social security"
    }

    JS_REDIRECT_PATTERNS = [
        "window.location",
        "window.location.href",
        "window.location.replace",
        "window.location.assign",
        "location.href",
        "location.replace",
        "location.assign"
    ]

    def __init__(self, html, page_url):
        self.html = html or ""
        self.page_url = page_url

        self.parsed_page_url = urlparse(
            page_url
        )

        self.page_hostname = (
            self.parsed_page_url.hostname or ""
        ).lower()

        self.soup = BeautifulSoup(
            self.html,
            "html.parser"
        )

    # =========================================================
    # BASIC PAGE INFORMATION
    # =========================================================

    def get_html_length(self):
        return len(self.html)

    def get_page_title(self):
        title = self.soup.find("title")

        if not title:
            return None

        return title.get_text(
            strip=True
        )

    # =========================================================
    # FORMS
    # =========================================================

    def get_forms(self):
        return self.soup.find_all("form")

    def get_form_count(self):
        return len(
            self.get_forms()
        )

    def get_password_fields(self):
        return self.soup.find_all(
            "input",
            {
                "type": lambda value:
                value and value.lower() == "password"
            }
        )

    def get_password_field_count(self):
        return len(
            self.get_password_fields()
        )

    def detect_login_form(self):
        """
        Detect whether the page appears to contain a login form.

        This is intentionally conservative. A form is not considered
        a login form merely because the word 'login' appears somewhere
        on the page.
        """

        forms = self.get_forms()

        for form in forms:

            password_fields = form.find_all(
                "input",
                {
                    "type": lambda value:
                    value and value.lower() == "password"
                }
            )

            if password_fields:
                return True

            form_text = form.get_text(
                " ",
                strip=True
            ).lower()

            login_terms = [
                "login",
                "log in",
                "sign in",
                "password"
            ]

            if any(
                term in form_text
                for term in login_terms
            ):
                return True

        return False

    # =========================================================
    # FORM ACTIONS
    # =========================================================

    def get_form_actions(self):
        actions = []

        for form in self.get_forms():

            action = form.get(
                "action"
            )

            if not action:
                action = self.page_url

            absolute_action = urljoin(
                self.page_url,
                action
            )

            actions.append(
                absolute_action
            )

        return actions

    def is_external_url(self, target_url):
        """
        Determine whether a URL points to a different hostname.
        """

        try:
            parsed = urlparse(
                target_url
            )

            hostname = (
                parsed.hostname or ""
            ).lower()

            if not hostname:
                return False

            return hostname != self.page_hostname

        except Exception:
            return False

    def get_external_form_actions(self):
        external_actions = []

        for action in self.get_form_actions():

            if self.is_external_url(action):
                external_actions.append(
                    action
                )

        return external_actions

    def get_suspicious_form_actions(self):
        """
        Look for form actions containing terms commonly associated
        with credential collection or suspicious destinations.
        """

        suspicious_actions = []

        suspicious_terms = {
            "login",
            "signin",
            "verify",
            "account",
            "password",
            "credential",
            "payment",
            "billing",
            "wallet",
            "bank"
        }

        for action in self.get_form_actions():

            action_lower = action.lower()

            matched_terms = [
                term
                for term in suspicious_terms
                if term in action_lower
            ]

            if matched_terms:
                suspicious_actions.append({
                    "action": action,
                    "matched_terms": matched_terms
                })

        return suspicious_actions

    # =========================================================
    # LINKS
    # =========================================================

    def get_links(self):
        return self.soup.find_all(
            "a",
            href=True
        )

    def get_external_links(self):
        external_links = []

        for link in self.get_links():

            href = link.get(
                "href"
            )

            if not href:
                continue

            absolute_url = urljoin(
                self.page_url,
                href
            )

            if self.is_external_url(
                absolute_url
            ):
                external_links.append(
                    absolute_url
                )

        return external_links

    # =========================================================
    # IFRAMES
    # =========================================================

    def get_iframes(self):
        return self.soup.find_all(
            "iframe"
        )

    def get_external_iframes(self):
        external_iframes = []

        for iframe in self.get_iframes():

            source = iframe.get(
                "src"
            )

            if not source:
                continue

            absolute_url = urljoin(
                self.page_url,
                source
            )

            if self.is_external_url(
                absolute_url
            ):
                external_iframes.append(
                    absolute_url
                )

        return external_iframes

    # =========================================================
    # JAVASCRIPT ANALYSIS
    # =========================================================

    def get_script_tags(self):
        return self.soup.find_all(
            "script"
        )

    def get_inline_scripts(self):
        scripts = []

        for script in self.get_script_tags():

            # External scripts have a src attribute.
            # We are interested here in inline JavaScript.
            if script.get("src"):
                continue

            script_text = script.get_text(
                " ",
                strip=True
            )

            if script_text:
                scripts.append(
                    script_text
                )

        return scripts

    def get_javascript_redirects(self):
        """
        Detect actual JavaScript redirect assignments rather than
        simply searching for the words 'window.location'.

        Examples that can be detected:

            window.location.href = "https://example.com"

            location.href = '/login'

            window.location.replace("https://example.com")

        The JavaScript is NOT executed.
        """

        redirects = []

        # Matches assignments such as:
        #
        # window.location = "..."
        # window.location.href = "..."
        # location.href = "..."
        #
        assignment_pattern = (
            r"""
            (?:
                window\s*\.\s*location
                |
                location
            )
            \s*
            (?:
                \.\s*
                (?:
                    href
                    |
                    replace
                    |
                    assign
                )
            )?
            \s*
            =
            \s*
            (?:
                ["']
                ([^"']+)
                ["']
            )
            """
        )

        # Matches:
        #
        # window.location.replace("...")
        # location.replace("...")
        #
        function_pattern = (
            r"""
            (?:
                window\s*\.\s*location
                |
                location
            )
            \s*
            \.\s*
            (?:
                replace
                |
                assign
            )
            \s*
            \(
            \s*
            ["']
            ([^"']+)
            ["']
            \s*
            \)
            """
        )

        import re

        for script in self.get_inline_scripts():

            for match in re.finditer(
                assignment_pattern,
                script,
                re.IGNORECASE | re.VERBOSE
            ):

                destination = match.group(
                    1
                )

                if destination:

                    absolute_destination = urljoin(
                        self.page_url,
                        destination
                    )

                    redirects.append({
                        "type": "assignment",
                        "destination": absolute_destination,
                        "external": self.is_external_url(
                            absolute_destination
                        )
                    })

            for match in re.finditer(
                function_pattern,
                script,
                re.IGNORECASE | re.VERBOSE
            ):

                destination = match.group(
                    1
                )

                if destination:

                    absolute_destination = urljoin(
                        self.page_url,
                        destination
                    )

                    redirects.append({
                        "type": "function",
                        "destination": absolute_destination,
                        "external": self.is_external_url(
                            absolute_destination
                        )
                    })

        # Remove duplicates while preserving order.
        unique_redirects = []

        seen = set()

        for redirect in redirects:

            key = (
                redirect["type"],
                redirect["destination"]
            )

            if key not in seen:

                seen.add(key)

                unique_redirects.append(
                    redirect
                )

        return unique_redirects

    # =========================================================
    # META REFRESH
    # =========================================================

    def get_meta_refresh(self):
        refresh_entries = []

        meta_tags = self.soup.find_all(
            "meta"
        )

        for meta in meta_tags:

            http_equiv = meta.get(
                "http-equiv",
                ""
            ).lower()

            if http_equiv != "refresh":
                continue

            content = meta.get(
                "content",
                ""
            )

            refresh_entries.append(
                content
            )

        return refresh_entries

    # =========================================================
    # HIDDEN INPUTS
    # =========================================================

    def get_hidden_inputs(self):
        return self.soup.find_all(
            "input",
            {
                "type": lambda value:
                value and value.lower() == "hidden"
            }
        )

    def get_hidden_input_count(self):
        return len(
            self.get_hidden_inputs()
        )

    # =========================================================
    # LOGIN FORM HTTPS STATUS
    # =========================================================

    def check_login_form_https(self):
        """
        Determine whether login forms submit over HTTPS.

        Returns:
            True  -> all external login form actions use HTTPS
            False -> at least one login form action is HTTP
            None  -> no login form was detected
        """

        forms = self.get_forms()

        login_forms = []

        for form in forms:

            password_fields = form.find_all(
                "input",
                {
                    "type": lambda value:
                    value and value.lower() == "password"
                }
            )

            if password_fields:
                login_forms.append(
                    form
                )

        if not login_forms:
            return None

        for form in login_forms:

            action = form.get(
                "action"
            )

            if not action:
                action = self.page_url

            absolute_action = urljoin(
                self.page_url,
                action
            )

            parsed = urlparse(
                absolute_action
            )

            if parsed.scheme.lower() == "http":
                return False

        return True

    # =========================================================
    # PAGE TEXT
    # =========================================================

    def get_visible_text(self):
        """
        Extract visible text while removing script/style content.
        """

        for element in self.soup(
            ["script", "style", "noscript"]
        ):
            element.decompose()

        return self.soup.get_text(
            " ",
            strip=True
        )

    def find_phishing_keywords(self):
        """
        Search visible page text for stronger phishing-related
        phrases.

        Matching is case-insensitive.
        """

        text = self.get_visible_text().lower()

        found = []

        for keyword in self.PHISHING_KEYWORDS:

            if keyword in text:
                found.append(
                    keyword
                )

        return sorted(
            found
        )

    # =========================================================
    # COMPLETE ANALYSIS
    # =========================================================

    def analyze(self):

        forms = self.get_forms()

        password_fields = (
            self.get_password_fields()
        )

        external_form_actions = (
            self.get_external_form_actions()
        )

        external_links = (
            self.get_external_links()
        )

        iframes = (
            self.get_iframes()
        )

        external_iframes = (
            self.get_external_iframes()
        )

        javascript_redirects = (
            self.get_javascript_redirects()
        )

        meta_refresh = (
            self.get_meta_refresh()
        )

        hidden_inputs = (
            self.get_hidden_inputs()
        )

        login_form = (
            self.detect_login_form()
        )

        login_form_https = (
            self.check_login_form_https()
        )

        phishing_keywords = (
            self.find_phishing_keywords()
        )

        suspicious_form_actions = (
            self.get_suspicious_form_actions()
        )

        return {
            "html_length": self.get_html_length(),

            "page_title": self.get_page_title(),

            "form_count": len(forms),

            "login_form": login_form,

            "password_fields": len(
                password_fields
            ),

            "external_form_actions": (
                external_form_actions
            ),

            "suspicious_form_actions": (
                suspicious_form_actions
            ),

            "external_links": external_links,

            "iframes": len(iframes),

            "external_iframes": external_iframes,

            "javascript_redirects": (
                javascript_redirects
            ),

            "meta_refresh": meta_refresh,

            "hidden_inputs": len(
                hidden_inputs
            ),

            "login_form_https": (
                login_form_https
            ),

            "phishing_keywords": (
                phishing_keywords
            )
        }


def analyze_html(
    html,
    page_url
):
    """
    Helper function used by main.py.
    """

    analyzer = HTMLAnalyzer(
        html=html,
        page_url=page_url
    )

    return analyzer.analyze()


if __name__ == "__main__":

    test_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Login Page</title>
    </head>
    <body>

        <form action="/login" method="post">
            <input type="text" name="username">
            <input type="password" name="password">
            <button type="submit">Sign In</button>
        </form>

        <form action="https://example-attacker.com/collect">
            <input type="password" name="password">
        </form>

        <script>
            window.location.href = "https://example.com/login";
        </script>

        <iframe src="https://example.com/frame"></iframe>

    </body>
    </html>
    """

    test_url = (
        "https://example.com"
    )

    print("=" * 70)
    print("HTML ANALYZER TEST")
    print("=" * 70)

    result = analyze_html(
        test_html,
        test_url
    )

    for key, value in result.items():
        print(
            f"{key:35}: {value}"
        )