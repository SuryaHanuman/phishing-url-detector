"""
Unit Tests for URLAnalyzer
Directly tests Surya's real URLAnalyzer class from url_analyzer.py.
Validates lexical analysis, IP detection, brand impersonation, and Shannon entropy.
"""

import sys
from pathlib import Path

# Add project root to sys.path so tests can import url_analyzer
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from url_analyzer import URLAnalyzer


def test_ip_based_url_detection():
    """Verifies detection of raw IPv4 addresses vs domain names."""
    analyzer_ip = URLAnalyzer("http://192.168.1.1/login")
    assert analyzer_ip.is_ip_address() is True

    analyzer_domain = URLAnalyzer("https://www.google.com")
    assert analyzer_domain.is_ip_address() is False


def test_domain_entropy_calculation():
    """Verifies Shannon entropy calculation on normal vs high-entropy randomized domains."""
    analyzer_normal = URLAnalyzer("https://google.com")
    analyzer_random = URLAnalyzer("https://xq79bz12mpk90w.xyz")

    normal_entropy = analyzer_normal.get_domain_entropy()
    random_entropy = analyzer_random.get_domain_entropy()

    assert random_entropy > normal_entropy
    assert normal_entropy > 0.0


def test_brand_impersonation_detection():
    """Tests brand impersonation detection (e.g. PayPal impersonated on an attacker domain)."""
    # Legitimate brand domain
    analyzer_legit = URLAnalyzer("https://www.paypal.com/signin")
    assert analyzer_legit.detect_brand_impersonation() == []

    # Impersonation attack domain
    analyzer_phish = URLAnalyzer("http://paypal-security-update.attacker.com/login")
    impersonations = analyzer_phish.detect_brand_impersonation()
    assert "paypal" in impersonations


def test_suspicious_keywords_detection():
    """Tests lexical extraction of sensitive phishing keywords."""
    analyzer = URLAnalyzer("https://example.com/login/verify/update-password")
    keywords = analyzer.detect_suspicious_keywords()

    assert "login" in keywords
    assert "verify" in keywords
    assert "password" in keywords
    assert "update" in keywords


def test_suspicious_tld_detection():
    """Tests detection of high-risk top-level domains."""
    analyzer_tld = URLAnalyzer("http://free-crypto.xyz")
    assert analyzer_tld.has_suspicious_tld() is True

    analyzer_standard = URLAnalyzer("https://example.org")
    assert analyzer_standard.has_suspicious_tld() is False


def test_subdomain_count():
    """Verifies subdomain counting logic."""
    analyzer_single = URLAnalyzer("https://example.com")
    assert analyzer_single.get_subdomain_count() == 0

    analyzer_sub = URLAnalyzer("https://login.secure.example.com")
    assert analyzer_sub.get_subdomain_count() == 2


def test_complete_analysis_schema():
    """Verifies that analyze() returns a complete dictionary with expected keys."""
    analyzer = URLAnalyzer("https://google.com")
    result = analyzer.analyze()

    assert isinstance(result, dict)
    assert "hostname" in result
    assert "is_ip_address" in result
    assert "domain_entropy" in result
    assert "suspicious_patterns" in result
    assert result["is_ip_address"] is False
