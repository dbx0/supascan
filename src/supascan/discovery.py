from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

from .models import Credentials

_RE_PROJECT_REF = re.compile(r'https://([a-z0-9]{20})\.supabase\.co')
_RE_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
_RE_CREATE_CLIENT = re.compile(
    r'createClient\s*\(\s*[\'"]https://([a-z0-9]{20})\.supabase\.co[\'"]'
    r'\s*,\s*[\'"]([^\'"]+)[\'"]'
)
_RE_SUPABASE_KEY = re.compile(r'SUPABASE_(?:ANON_)?KEY\s*[=:]\s*[\'"]([^\'"]+)[\'"]')
_RE_ANON_KEY = re.compile(r'anon[_-]?key[\'"]?\s*[=:]\s*[\'"]([^\'"]+)[\'"]')
_RE_EDGE_FN = re.compile(r'functions\.invoke\s*\(\s*[\'"]([^\'"]+)[\'"]')
# Tuple format: ('https://ref.supabase.co', 'eyJ...')
_RE_TUPLE = re.compile(
    r'\(\s*[\'"]https://([a-z0-9]{20})\.supabase\.co[\'"]'
    r'\s*,\s*[\'"]([^\'"]+)[\'"]'
    r'\s*\)'
)
# Matches url+key as consecutive args without requiring closing paren —
# catches minified calls with a third options argument, e.g. Ps('url', 'key', {...})
_RE_URL_KEY_PAIR = re.compile(
    r'[\'"]https://([a-z0-9]{20})\.supabase\.co[\'"]'
    r'\s*,\s*[\'"]([^\'"]{50,})[\'"]',
    re.DOTALL,
)


def is_valid_supabase_anon_key(token: str) -> bool:
    try:
        import jwt
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("role") == "anon"
    except Exception:
        return False


def is_valid_supabase_key(token: str) -> bool:
    """Accept both anon and service_role Supabase JWTs."""
    try:
        import jwt
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("role") in ("anon", "service_role")
    except Exception:
        return False


def _extract_credentials(content: str, source: str) -> Optional[Credentials]:
    project_ref: Optional[str] = None
    anon_key: Optional[str] = None

    # createClient pattern gives both ref and key
    m = _RE_CREATE_CLIENT.search(content)
    if m:
        project_ref = m.group(1)
        anon_key = m.group(2)

    # Tuple format: ('https://ref.supabase.co', 'eyJ...')
    if not (project_ref and anon_key):
        m = _RE_TUPLE.search(content)
        if m:
            project_ref = m.group(1)
            anon_key = m.group(2)

    # Minified call with options arg: Ps('https://ref.supabase.co', 'eyJ...', {...})
    if not (project_ref and anon_key):
        m = _RE_URL_KEY_PAIR.search(content)
        if m:
            candidate = m.group(2)
            if _RE_JWT.match(candidate) and is_valid_supabase_key(candidate):
                project_ref = m.group(1)
                anon_key = candidate

    # Fall back to ref from URL
    if not project_ref:
        m = _RE_PROJECT_REF.search(content)
        if m:
            project_ref = m.group(1)

    # Key patterns
    if not anon_key:
        for pattern in (_RE_SUPABASE_KEY, _RE_ANON_KEY):
            m = pattern.search(content, re.IGNORECASE)
            if m:
                candidate = m.group(1)
                if _RE_JWT.match(candidate):
                    anon_key = candidate
                    break

    # Last resort: any JWT that looks like a Supabase key (anon or service_role)
    if not anon_key:
        for token in _RE_JWT.findall(content):
            if is_valid_supabase_key(token):
                anon_key = token
                break

    if project_ref and anon_key:
        return Credentials(project_ref=project_ref, anon_key=anon_key, source=source)
    return None


def find_edge_functions(content: str) -> list[str]:
    return list(dict.fromkeys(_RE_EDGE_FN.findall(content)))


_CRAWL_PATHS = [
    "/", "/login", "/signin", "/signup", "/auth", "/dashboard",
    "/app", "/admin", "/home", "/index",
]

_RE_JS_SRC = re.compile(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']')


def _collect_js_urls(html: str, base: str) -> list[str]:
    """Extract all JS URLs from HTML (script src tags and inline references)."""
    seen: set[str] = set()
    result: list[str] = []
    for src in _RE_JS_SRC.findall(html):
        if not src.startswith("http"):
            src = base + ("" if src.startswith("/") else "/") + src
        if src not in seen:
            seen.add(src)
            result.append(src)
    return result


def from_url(url: str) -> Optional[Credentials]:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    seen_js: set[str] = set()
    all_js: list[str] = []

    # Crawl the target URL plus common sub-paths to collect all JS chunk URLs
    crawl_targets = [url]
    # Add sub-paths only for root-level URLs (not deep links)
    if parsed.path in ("", "/"):
        crawl_targets += [base + p for p in _CRAWL_PATHS if base + p != url]

    for crawl_url in crawl_targets:
        try:
            resp = requests.get(crawl_url, timeout=10)
        except Exception as e:
            print(f"  [WARN] Failed to fetch {crawl_url}: {e}")
            continue

        # Check the HTML/page itself first
        creds = _extract_credentials(resp.text, source=crawl_url)
        if creds:
            return creds

        # Collect JS URLs from this page
        for js_url in _collect_js_urls(resp.text, base):
            if js_url not in seen_js:
                seen_js.add(js_url)
                all_js.append(js_url)

    # Scan all collected JS files
    for js_url in all_js:
        try:
            js_resp = requests.get(js_url, timeout=10)
            creds = _extract_credentials(js_resp.text, source=js_url)
            if creds:
                return creds
        except Exception:
            continue

    return None


def from_html_file(path: str) -> Optional[Credentials]:
    content = Path(path).read_text(errors="replace")
    return _extract_credentials(content, source=path)


def from_js_file(path: str) -> Optional[Credentials]:
    content = Path(path).read_text(errors="replace")
    return _extract_credentials(content, source=path)


def from_har_file(path: str) -> Optional[Credentials]:
    try:
        har = json.loads(Path(path).read_text())
    except Exception as e:
        print(f"  [WARN] Failed to parse HAR file: {e}")
        return None

    entries = har.get("log", {}).get("entries", [])
    for entry in entries:
        req = entry.get("request", {})
        # Check URL
        url_str = req.get("url", "")
        creds = _extract_credentials(url_str, source=path)
        if creds:
            return creds
        # Check request headers
        for header in req.get("headers", []):
            val = header.get("value", "")
            creds = _extract_credentials(val, source=path)
            if creds:
                return creds
        # Check post data
        post_data = req.get("postData", {}).get("text", "")
        if post_data:
            creds = _extract_credentials(post_data, source=path)
            if creds:
                return creds
        # Check response body
        resp_text = entry.get("response", {}).get("content", {}).get("text", "")
        if resp_text:
            creds = _extract_credentials(resp_text, source=path)
            if creds:
                return creds
    return None
