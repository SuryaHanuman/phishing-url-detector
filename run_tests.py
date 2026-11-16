"""
Automated Test Runner & URL Analyzer Verification Script
Executes all unit tests and demonstrates real URL detection on sample domains.
Works using standard library so it runs in any Python 3 environment.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from url_analyzer import URLAnalyzer
import tests.test_url_analyzer as tests_mod


def run_unit_tests():
    print("=" * 70)
    print("  PHISHING URL DETECTOR - AUTOMATED UNIT TEST SUITE")
    print("=" * 70)

    test_functions = [
        getattr(tests_mod, name)
        for name in dir(tests_mod)
        if name.startswith("test_") and callable(getattr(tests_mod, name))
    ]

    passed = 0
    failed = 0

    for func in test_functions:
        test_name = func.__name__
        try:
            func()
            print(f"  [PASS] {test_name}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {test_name}: Assertion Failed ({e})")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] {test_name}: {type(e).__name__} ({e})")
            failed += 1

    print("-" * 70)
    print(f"  RESULTS: {passed} PASSED, {failed} FAILED across {len(test_functions)} tests.")
    print("=" * 70)
    return failed == 0


def demonstrate_live_scans():
    print("\n" + "=" * 70)
    print("  LIVE URL ANALYSIS DEMONSTRATION")
    print("=" * 70)

    sample_urls = [
        ("https://www.google.com", "Legitimate Global Search Engine"),
        ("http://192.168.1.1/login/verify.php", "Raw IP with Sensitive Phishing Keywords"),
        ("http://paypal-security-update.attacker.com/account", "Brand Impersonation & Typosquatting"),
        ("https://xq79bz12mpk90w.xyz", "High-Entropy Randomized DGA Domain + Suspicious TLD"),
    ]

    for url, description in sample_urls:
        print(f"\n[+] Target URL : {url}")
        print(f"    Scenario   : {description}")
        analyzer = URLAnalyzer(url)
        res = analyzer.analyze()

        print(f"    Hostname   : {res['hostname']}")
        print(f"    Raw IP     : {res['is_ip_address']}")
        print(f"    Entropy    : {res['domain_entropy']} (Shannon entropy)")
        print(f"    Brand Spoof: {res['brand_impersonation_detected'] or 'None'}")
        print(f"    Keywords   : {res['suspicious_keywords'] or 'None'}")
        print(f"    Bad TLD    : {res['suspicious_tld']}")
        print(f"    Patterns   : {res['suspicious_patterns'] or 'None'}")

    print("\n" + "=" * 70)
    print("  DEMONSTRATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    success = run_unit_tests()
    demonstrate_live_scans()
    sys.exit(0 if success else 1)
