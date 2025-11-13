import re
import tldextract
import validators
from urllib.parse import urlparse

SUSPICIOUS_TOKENS = [
    'login','account','update','verify','bank','secure','ebay',
    'paypal','signin','confirm'
]

def has_ip(url):
    return 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url or "") else 0

def url_length(url):
    return len(url or "")

def count_dots(url):
    return (url or "").count('.')

def has_https(url):
    return 1 if (url or "").lower().startswith('https') else 0

def count_special_chars(url):
    return sum((url or "").count(c) for c in ['@','-','?','=','_','&','%','$','/'])

def suspicious_token_count(url):
    u = (url or "").lower()
    return sum(1 for t in SUSPICIOUS_TOKENS if t in u)

def ext_domain_parts(url):
    ext = tldextract.extract(url or "")
    return len(ext.subdomain.split('.')) if ext.subdomain else 0

def is_valid_url(url):
    return 1 if validators.url(url or "") else 0

def combine_features(url, html_features=None, whois_info=None, tls_info=None):
    url_feats = [
        has_ip(url),
        url_length(url),
        count_dots(url),
        has_https(url),
        count_special_chars(url),
        suspicious_token_count(url),
        ext_domain_parts(url),
        is_valid_url(url)
    ]

    html_feats = [
        html_features.get("has_html",0),
        html_features.get("forms",0),
        html_features.get("password_fields",0),
        html_features.get("num_links",0),
        html_features.get("num_external_links",0),
        html_features.get("num_scripts",0)
    ] if html_features else [0,0,0,0,0,0]

    who_tls = [
        1 if whois_info and whois_info.get("whois_success") else 0,
        1 if tls_info and tls_info.get("tls_present") else 0
    ]

    return url_feats + html_feats + who_tls


FEATURE_NAMES = [
    "has_ip","url_length","count_dots","has_https","count_special_chars",
    "suspicious_token_count","ext_domain_parts","is_valid_url",
    "has_html","forms","password_fields","num_links","num_external_links",
    "num_scripts","whois_success","tls_present"
]
