import json

from url_analyzer import URLAnalyzer
from dns_analyzer import DNSAnalyzer
from http_analyzer import HTTPAnalyzer
from ssl_analyzer import SSLAnalyzer
from whois_analyzer import analyze_whois
from html_analyzer import HTMLAnalyzer
from risk_engine import RiskEngine


# ============================================================
# DISPLAY HELPERS
# ============================================================

def print_header(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_result(label, value):
    print(f"{label:<35}: {value}")


def print_list(label, values):
    if values is None:
        values = []

    if isinstance(values, list):
        print_result(label, values)
    else:
        print_result(label, values)


# ============================================================
# URL ANALYSIS DISPLAY
# ============================================================

def display_url_result(result):

    print_header("URL ANALYSIS")

    print_result(
        "Original URL",
        result.get("original_url")
    )

    print_result(
        "Normalized URL",
        result.get("normalized_url")
    )

    print_result(
        "Scheme",
        result.get("scheme")
    )

    print_result(
        "Hostname",
        result.get("hostname")
    )

    print_result(
        "URL Length",
        result.get("url_length")
    )

    print_result(
        "Domain Length",
        result.get("domain_length")
    )

    print_result(
        "Subdomain Count",
        result.get("subdomain_count")
    )

    print_result(
        "Dot Count",
        result.get("dot_count")
    )

    print_result(
        "Hyphen Count",
        result.get("hyphen_count")
    )

    print_result(
        "Digit Count",
        result.get("digit_count")
    )

    print_result(
        "Special Character Ratio",
        result.get("special_character_ratio")
    )

    print_result(
        "Parameter Count",
        result.get("parameter_count")
    )

    print_result(
        "Domain Entropy",
        result.get("domain_entropy")
    )

    print_result(
        "Uses IP Address",
        result.get("is_ip_address")
    )

    print_result(
        "URL Shortener",
        result.get("is_shortened")
    )

    print_result(
        "Suspicious TLD",
        result.get("suspicious_tld")
    )

    print_result(
        "Base64 Detected",
        result.get("base64_like")
    )

    print_list(
        "Suspicious Keywords",
        result.get("suspicious_keywords", [])
    )

    print_list(
        "Brand Names Detected",
        result.get("brand_names_detected", [])
    )

    print_list(
        "Brand Impersonation",
        result.get("brand_impersonation_detected", [])
    )

    print_list(
        "Suspicious Patterns",
        result.get("suspicious_patterns", [])
    )


# ============================================================
# DNS ANALYSIS DISPLAY
# ============================================================

def display_dns_result(result):

    print_header("DNS ANALYSIS")

    print_result(
        "Hostname",
        result.get("hostname")
    )

    print_result(
        "Resolution Failed",
        result.get("resolution_failed")
    )

    print_result(
        "IPv4 Addresses",
        result.get("ipv4_addresses", [])
    )

    print_result(
        "IPv6 Addresses",
        result.get("ipv6_addresses", [])
    )

    print_result(
        "Canonical Hostname",
        result.get("canonical_hostname")
    )

    print_result(
        "Aliases",
        result.get("aliases", [])
    )

    print_result(
        "A Records",
        result.get("a_records", [])
    )

    print_result(
        "AAAA Records",
        result.get("aaaa_records", [])
    )

    print_result(
        "MX Records",
        result.get("mx_records", [])
    )

    print_result(
        "NS Records",
        result.get("ns_records", [])
    )

    print_result(
        "CNAME Records",
        result.get("cname_records", [])
    )

    print_result(
        "No MX Record",
        result.get("no_mx_record")
    )


# ============================================================
# HTTP ANALYSIS DISPLAY
# ============================================================

def display_http_result(result):

    print_header("HTTP / HTTPS ANALYSIS")

    print_result(
        "Request Successful",
        result.get("request_successful")
    )

    print_result(
        "Status Code",
        result.get("status_code")
    )

    print_result(
        "Reason",
        result.get("reason")
    )

    print_result(
        "Final URL",
        result.get("final_url")
    )

    print_result(
        "Uses HTTP",
        result.get("uses_http")
    )

    print_result(
        "Uses HTTPS",
        result.get("uses_https")
    )

    print_result(
        "Redirected",
        result.get("redirected")
    )

    print_result(
        "Redirect Count",
        result.get("redirect_count")
    )

    print_result(
        "Hostname Changed",
        result.get("hostname_changed")
    )

    print_result(
        "Same Registered Domain",
        result.get("same_registered_domain")
    )

    print_result(
        "Cross Domain Redirect",
        result.get("cross_domain_redirect")
    )

    print_result(
        "Content Type",
        result.get("content_type")
    )

    print_result(
        "Server",
        result.get("server")
    )

    print_result(
        "Missing Security Headers",
        result.get("missing_security_headers", [])
    )

    print_result(
        "HTML Available",
        result.get("html_available")
    )

    print_result(
        "Response Size",
        result.get("response_size")
    )

    print_result(
        "Redirect Chain",
        result.get("redirects", [])
    )


# ============================================================
# SSL ANALYSIS DISPLAY
# ============================================================

def display_ssl_result(result):

    print_header("SSL / TLS ANALYSIS")

    print_result(
        "SSL Available",
        result.get("ssl_available")
    )

    print_result(
        "TLS Version",
        result.get("tls_version")
    )

    print_result(
        "Cipher",
        result.get("cipher")
    )

    print_result(
        "Certificate Valid",
        result.get("certificate_valid")
    )

    print_result(
        "Certificate Expired",
        result.get("certificate_expired")
    )

    print_result(
        "Hostname Match",
        result.get("hostname_match")
    )

    print_result(
        "Hostname Mismatch",
        result.get("hostname_mismatch")
    )

    print_result(
        "Valid From",
        result.get("valid_from")
    )

    print_result(
        "Valid Until",
        result.get("valid_until")
    )

    print_result(
        "Days Remaining",
        result.get("days_remaining")
    )

    print_result(
        "Expires Soon",
        result.get("expires_soon")
    )

    print_result(
        "Weak TLS Version",
        result.get("weak_tls_version")
    )

    print_result(
        "SSL Error",
        result.get("ssl_error")
    )


# ============================================================
# WHOIS ANALYSIS DISPLAY
# ============================================================

def display_whois_result(result):

    print_header("WHOIS / DOMAIN INFORMATION")

    print_result(
        "Domain",
        result.get("domain")
    )

    print_result(
        "WHOIS Available",
        result.get("whois_available")
    )

    print_result(
        "Registrar",
        result.get("registrar")
    )

    print_result(
        "Creation Date",
        result.get("creation_date")
    )

    print_result(
        "Expiration Date",
        result.get("expiration_date")
    )

    print_result(
        "Updated Date",
        result.get("updated_date")
    )

    print_result(
        "Domain Age (Days)",
        result.get("domain_age_days")
    )

    print_result(
        "Domain Age (Years)",
        result.get("domain_age_years")
    )

    print_result(
        "Registration Period",
        result.get("registration_period_days")
    )

    print_result(
        "Newly Registered",
        result.get("newly_registered")
    )

    print_result(
        "Expires Soon",
        result.get("expires_soon")
    )

    print_result(
        "WHOIS Error",
        result.get("whois_error")
    )


# ============================================================
# HTML ANALYSIS DISPLAY
# ============================================================

def display_html_result(result):

    print_header("HTML / CONTENT ANALYSIS")

    print_result(
        "HTML Length",
        result.get("html_length")
    )

    print_result(
        "Page Title",
        result.get("page_title")
    )

    print_result(
        "Form Count",
        result.get("form_count")
    )

    print_result(
        "Login Form",
        result.get("login_form")
    )

    print_result(
        "Password Fields",
        result.get("password_fields")
    )

    print_result(
        "External Form Actions",
        result.get("external_form_actions", [])
    )

    print_result(
        "External Links",
        result.get("external_links", [])
    )

    print_result(
        "Iframes",
        result.get("iframes")
    )

    print_result(
        "External Iframes",
        result.get("external_iframes", [])
    )

    print_result(
        "JavaScript Redirects",
        result.get("javascript_redirects", [])
    )

    print_result(
        "Meta Refresh",
        result.get("meta_refresh", [])
    )

    print_result(
        "Hidden Inputs",
        result.get("hidden_inputs")
    )

    print_result(
        "Phishing Keywords",
        result.get("phishing_keywords", [])
    )


# ============================================================
# RISK DISPLAY
# ============================================================

def display_risk_result(result):

    print_header("FINAL RISK ASSESSMENT")

    score = result.get(
        "risk_score",
        0
    )

    risk_level = result.get(
        "risk_level",
        "SAFE"
    )

    findings = result.get(
        "findings",
        []
    )

    print_result(
        "Risk Score",
        f"{score}/100"
    )

    print_result(
        "Risk Level",
        risk_level
    )

    print_result(
        "Finding Count",
        len(findings)
    )

    print("\nSummary:")
    print(
        result.get(
            "summary",
            "No summary available."
        )
    )

    print("\nFindings:")

    if not findings:
        print("No suspicious findings detected.")

    else:

        for finding in findings:

            points = finding.get(
                "points",
                0
            )

            # The risk engine uses "level".
            # This fallback also supports older reports that
            # may have used "severity".
            level = finding.get(
                "level",
                finding.get(
                    "severity",
                    "UNKNOWN"
                )
            )

            message = finding.get(
                "message",
                finding.get(
                    "finding",
                    "Unknown finding"
                )
            )

            print(
                f"[+{points}] "
                f"[{level}] "
                f"{message}"
            )


# ============================================================
# SAVE JSON REPORT
# ============================================================

def save_json_report(
    url,
    url_result,
    dns_result,
    http_result,
    ssl_result,
    whois_result,
    html_result,
    risk_result
):

    report = {
        "target_url": url,
        "url_analysis": url_result,
        "dns_analysis": dns_result,
        "http_analysis": http_result,
        "ssl_analysis": ssl_result,
        "whois_analysis": whois_result,
        "html_analysis": html_result,
        "risk_assessment": risk_result
    }

    try:

        with open(
            "scan_report.json",
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                default=str
            )

        print(
            "\nJSON report saved as: scan_report.json"
        )

    except Exception as error:

        print(
            f"\nCould not save JSON report: {error}"
        )


# ============================================================
# MAIN SCAN FUNCTION
# ============================================================

def scan_url(url):

    print_header(
        "PHISHING URL SECURITY SCANNER"
    )

    print_result(
        "Target URL",
        url
    )

    # --------------------------------------------------------
    # 1. URL
    # --------------------------------------------------------

    print("\n[1/6] Analyzing URL...")

    url_analyzer = URLAnalyzer(url)
    url_result = url_analyzer.analyze()

    display_url_result(
        url_result
    )

    # --------------------------------------------------------
    # 2. DNS
    # --------------------------------------------------------

    print("\n[2/6] Analyzing DNS...")

    hostname = url_result.get(
        "hostname"
    )

    dns_analyzer = DNSAnalyzer(hostname)
    dns_result = dns_analyzer.analyze()

    display_dns_result(
        dns_result
    )

    # --------------------------------------------------------
    # 3. HTTP
    # --------------------------------------------------------

    print("\n[3/6] Analyzing HTTP/HTTPS...")

    http_analyzer = HTTPAnalyzer(url)
    http_result = http_analyzer.analyze()

    display_http_result(
        http_result
    )

    # --------------------------------------------------------
    # 4. SSL/TLS
    # --------------------------------------------------------

    print("\n[4/6] Analyzing SSL/TLS...")

    ssl_analyzer = SSLAnalyzer(
        hostname
    )

    ssl_result = ssl_analyzer.analyze()

    display_ssl_result(
        ssl_result
    )

    # --------------------------------------------------------
    # 5. WHOIS
    # --------------------------------------------------------

    print("\n[5/6] Analyzing WHOIS...")

    whois_result = analyze_whois(
        hostname
    )

    display_whois_result(
        whois_result
    )

    # --------------------------------------------------------
    # 6. HTML
    # --------------------------------------------------------

    print("\n[6/6] Analyzing webpage content...")

    html_content = http_result.get(
        "html_content"
    )

    if html_content:

        page_url = http_result.get(
            "final_url"
        ) or url

        html_analyzer = HTMLAnalyzer(
            html_content,
            page_url
        )

        html_result = html_analyzer.analyze()

    else:

        html_result = {
            "html_length": 0,
            "page_title": None,
            "form_count": 0,
            "login_form": False,
            "password_fields": 0,
            "external_form_actions": [],
            "suspicious_form_actions": [],
            "external_links": [],
            "iframes": 0,
            "external_iframes": [],
            "javascript_redirects": [],
            "meta_refresh": [],
            "hidden_inputs": 0,
            "login_form_https": None,
            "phishing_keywords": []
        }

    display_html_result(
        html_result
    )

    # --------------------------------------------------------
    # Risk engine
    # --------------------------------------------------------

    print("\nCalculating overall risk...")

    risk_engine = RiskEngine(
        url_result=url_result,
        dns_result=dns_result,
        http_result=http_result,
        ssl_result=ssl_result,
        whois_result=whois_result,
        html_result=html_result
    )

    risk_result = risk_engine.get_result()

    display_risk_result(
        risk_result
    )

    # --------------------------------------------------------
    # Save report
    # --------------------------------------------------------

    save_json_report(
        url=url,
        url_result=url_result,
        dns_result=dns_result,
        http_result=http_result,
        ssl_result=ssl_result,
        whois_result=whois_result,
        html_result=html_result,
        risk_result=risk_result
    )

    return {
        "target_url": url,
        "url_analysis": url_result,
        "dns_analysis": dns_result,
        "http_analysis": http_result,
        "ssl_analysis": ssl_result,
        "whois_analysis": whois_result,
        "html_analysis": html_result,
        "risk_assessment": risk_result
    }


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

def main():

    print("=" * 70)
    print(
        "        PHISHING URL DETECTION SYSTEM"
    )
    print("=" * 70)

    url = input(
        "\nEnter URL to analyze: "
    ).strip()

    if not url:

        print(
            "\nError: URL cannot be empty."
        )

        return

    try:

        scan_url(url)

    except KeyboardInterrupt:

        print(
            "\n\nScan cancelled by user."
        )

    except Exception as error:

        print(
            "\nAn unexpected error occurred:"
        )

        print(
            error
        )


if __name__ == "__main__":
    main()