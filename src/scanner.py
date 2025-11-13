# src/scanner.py
import requests
from bs4 import BeautifulSoup
import socket, ssl
import whois
from urllib.parse import urlparse

REQUEST_TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (PhishDetect/1.0)"}

def fetch_html(url):
    """
    Fetch HTML safely. Returns (status_code, final_url, html_text) or (None,...)
    """
    try:
        r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
        return r.status_code, r.url, r.text
    except Exception as e:
        return None, url, None

def parse_html_features(html):
    """
    Basic content features: presence of forms, password fields, number of links, external resources
    """
    if not html:
        return {
            "has_html": 0,
            "forms": 0,
            "password_fields": 0,
            "num_links": 0,
            "num_external_links": 0,
            "num_scripts": 0
        }
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    num_forms = len(forms)
    pw = 0
    for f in forms:
        if f.find("input", {"type":"password"}):
            pw += 1
    links = soup.find_all("a", href=True)
    num_links = len(links)
    external = 0
    for a in links:
        href = a['href']
        if href.startswith("http") and urlparse(href).netloc:
            external += 1
    scripts = soup.find_all("script")
    return {
        "has_html": 1,
        "forms": num_forms,
        "password_fields": pw,
        "num_links": num_links,
        "num_external_links": external,
        "num_scripts": len(scripts)
    }

def get_tls_info(hostname):
    """
    Returns dict with certificate validity info (issuer, valid_from, valid_to, expired)
    """
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        # cert keys: subject, issuer, notAfter, notBefore
        not_after = cert.get('notAfter')
        not_before = cert.get('notBefore')
        issuer = dict(x[0] for x in cert.get('issuer', (('unknown',''),)))
        return {"tls_present":1, "issuer": issuer, "not_before": not_before, "not_after": not_after}
    except Exception:
        return {"tls_present":0, "issuer": None, "not_before": None, "not_after": None}

def get_whois(domain):
    try:
        w = whois.whois(domain)
        # w.creation_date can be list or datetime
        return {"whois_success":1, "creation_date": str(w.creation_date), "registrar": str(w.registrar)}
    except Exception:
        return {"whois_success":0, "creation_date": None, "registrar": None}
