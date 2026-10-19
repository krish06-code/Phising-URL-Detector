"""
feature_extractor.py
====================
Extracts URL-based features from a raw URL string.

These features EXACTLY match the PhiUSIIL dataset computation:
- URLLength: length of URL EXCLUDING scheme (e.g., 'https://')
- NoOfSubDomain: number of dots in hostname (www.google.com = 1 dot, so 1 subdomain)
- NoOfLettersInURL: letters ONLY in the domain+path portion (after scheme is removed)
- LetterRatioInURL: NoOfLettersInURL / URLLength
- SpacialCharRatioInURL: non-alphanumeric chars / URLLength (in domain+path portion)
- NoOfOtherSpecialCharsInURL: special chars excluding dots and slashes

Why URL-only features?
  Phishing sites change fast. We can detect suspicious URLs from
  their structure alone, without fetching the page. This also means
  we never make network requests to potentially dangerous URLs.
"""

import re
import urllib.parse


# -----------------------------------------------------------------------
# This list defines the canonical feature order.
# The model expects exactly these columns, in this exact order.
# DO NOT reorder or rename without retraining the model.
# -----------------------------------------------------------------------
FEATURE_NAMES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]


def extract_features(url: str) -> dict:
    """
    Given a raw URL string, return a dictionary of features.

    The dictionary keys match FEATURE_NAMES exactly.
    Feature computation matches the PhiUSIIL dataset exactly:
      - URLLength uses URL WITHOUT the scheme (e.g., strips 'https://')
      - Letter/digit counts are over the scheme-stripped URL
      - NoOfSubDomain = number of dots in hostname

    Returns all zeros if the URL cannot be parsed.
    """
    # Use Python's urllib to safely parse the URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {name: 0 for name in FEATURE_NAMES}

    # --- Scheme ---
    is_https = 1 if parsed.scheme == "https" else 0

    # --- Strip the scheme (https:// or http://) from URL ---
    # The dataset's URLLength, letter counts, etc. are computed WITHOUT the scheme.
    # Example: "https://www.google.com" -> stripped = "www.google.com"
    scheme_prefix = parsed.scheme + "://" if parsed.scheme else ""
    url_no_scheme = url[len(scheme_prefix):] if url.startswith(scheme_prefix) else url

    # Remove trailing slash to match dataset computation
    url_no_scheme = url_no_scheme.rstrip("/")

    url_str = url_no_scheme
    url_len = len(url_str)

    # --- Hostname / Domain ---
    hostname = parsed.hostname or ""  # e.g. "www.evil.xyz"
    domain_len = len(hostname)

    # Check if the hostname is an IP address (a sign of phishing)
    is_ip = 1 if _is_ip_address(hostname) else 0

    # --- TLD (top-level domain) ---
    tld = hostname.split(".")[-1] if "." in hostname else ""
    tld_len = len(tld)

    # --- Subdomains ---
    # Dataset computation: NoOfSubDomain = number of dots in the hostname
    # e.g. "www.google.com" has 2 dots → NoOfSubDomain = 2? No...
    # From label_check.txt: "www.google.com" → dataset shows 1
    # So it's: number of hostname_parts - 2 (subtract domain + TLD, min 0)
    # But wait: www.google.com = ["www", "google", "com"] → 3 parts → 3-2=1 ✓
    # www.voicefmradio.co.uk = ["www", "voicefmradio", "co", "uk"] → 4-2=2 ✓
    hostname_parts = hostname.split(".")
    no_of_subdomain = max(0, len(hostname_parts) - 2)  # matches dataset

    # --- Obfuscation ---
    obfuscated_chars = re.findall(r"%[0-9A-Fa-f]{2}", url_str)
    no_obfuscated = len(obfuscated_chars)
    has_obfuscation = 1 if no_obfuscated > 0 else 0
    obfuscation_ratio = no_obfuscated / url_len if url_len > 0 else 0.0

    # --- Letter and digit counts (over scheme-stripped URL) ---
    letters = [c for c in url_str if c.isalpha()]
    digits = [c for c in url_str if c.isdigit()]
    no_letters = len(letters)
    letter_ratio = no_letters / url_len if url_len > 0 else 0.0
    no_digits = len(digits)
    digit_ratio = no_digits / url_len if url_len > 0 else 0.0

    # --- Special characters ---
    no_equals = url_str.count("=")
    no_qmark = url_str.count("?")
    no_ampersand = url_str.count("&")

    # "Other special chars" = non-alphanumeric chars that are NOT:
    # dot (.), slash (/), hyphen (-), underscore (_)
    # This matches what the dataset counts as "special" beyond structural chars
    structural_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/")
    other_special = sum(1 for c in url_str if c not in structural_chars)

    # "Special char ratio" = ratio of non-alphanumeric chars (dots, slashes, etc.)
    non_alpha_num = sum(1 for c in url_str if not c.isalnum())
    special_ratio = non_alpha_num / url_len if url_len > 0 else 0.0

    return {
        "URLLength": url_len,
        "DomainLength": domain_len,
        "IsDomainIP": is_ip,
        "TLDLength": tld_len,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_obfuscated,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_equals,
        "NoOfQMarkInURL": no_qmark,
        "NoOfAmpersandInURL": no_ampersand,
        "NoOfOtherSpecialCharsInURL": other_special,
        "SpacialCharRatioInURL": special_ratio,
        "IsHTTPS": is_https,
    }


def extract_features_as_list(url: str) -> list:
    """
    Returns features as a plain Python list, in the order defined by FEATURE_NAMES.
    This is what you pass to model.predict() or model.predict_proba().
    """
    feature_dict = extract_features(url)
    return [feature_dict[name] for name in FEATURE_NAMES]


def _is_ip_address(hostname: str) -> bool:
    """
    Returns True if the hostname looks like an IPv4 address (e.g., "192.168.1.1").
    Phishing sites sometimes use raw IP addresses to hide their real identity.
    """
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ipv4_pattern, hostname):
        parts = hostname.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False


# -----------------------------------------------------------------------
# Quick sanity check — run this file directly to see feature output
# -----------------------------------------------------------------------
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login?user=admin&pass=1234",
        "https://paypal-security-update.evil.com/verify%20account",
        "http://bit.ly/2xQtR3p",
    ]
    for u in test_urls:
        print(f"\nURL: {u}")
        features = extract_features(u)
        for k, v in features.items():
            print(f"  {k}: {v}")
