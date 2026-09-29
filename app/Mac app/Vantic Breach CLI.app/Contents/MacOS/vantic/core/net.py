"""
Net - shared HTTP/socket helpers for every web-speaking tool

Browser-realistic UA, thread-local keep-alive connections (~3-5x faster
than per-request urllib over TLS), retry with backoff, Retry-After
respect, per-host rate limiting, and redirect capture with loop/hop caps.
"""

import http.client
import json
import socket
import ssl
import threading
import time
import urllib.parse

USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")

_local = threading.local()
_rate_lock = threading.Lock()
_rate = {}  # host -> token bucket state (tokens, last_refill)


# ---------- rate limiting ----------

class RateLimiter:
    """Token bucket per host. `rate` = requests/second allowed."""

    def __init__(self, rate=None):
        self.rate = rate
        self.capacity = rate or 0

    def wait(self, host):
        if not self.rate:
            return
        with _rate_lock:
            now = time.monotonic()
            tokens, last = _rate.get(host, (float(self.capacity), now))
            elapsed = now - last
            tokens = min(self.capacity, tokens + elapsed * self.rate)
            if tokens < 1:
                need = (1 - tokens) / self.rate
                _rate[host] = (tokens + need * self.rate, now + need)
                sleep = need
            else:
                tokens -= 1
                _rate[host] = (tokens, now)
                sleep = 0
        if sleep:
            time.sleep(max(0, sleep))

    def delay(self, seconds, jitter=0.0):
        """Explicit inter-request sleep with optional +-jitter fraction."""
        import random
        if seconds <= 0:
            return
        base = seconds * (1 + random.uniform(-jitter, jitter))
        time.sleep(max(0, base))


limiter = RateLimiter()


def set_rate(rps):
    limiter.rate = rps
    limiter.capacity = rps or 0


# ---------- connections ----------

def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _conn_for(url, timeout):
    """Thread-local keep-alive connection keyed by (scheme, host, port)."""
    p = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    scheme = p.scheme or "http"
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    if not hasattr(_local, "conns"):
        _local.conns = {}
    key = (scheme, host, port)
    if key not in _local.conns:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_ctx())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        _local.conns[key] = conn
    return _local.conns[key], key


def close_connections():
    """Close every thread-local keep-alive connection."""
    for conn in getattr(_local, "conns", {}).values():
        try:
            conn.close()
        except Exception:
            pass
    _local.conns = {}


class Response:
    def __init__(self, status, headers, body, url, redirects=None):
        self.status = status
        self.headers = headers          # list[(name, value)]
        self.body = body
        self.url = url
        self.redirects = redirects or []

    def header(self, name, default=None):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return default

    def headers_dict(self):
        d = {}
        for k, v in self.headers:
            d.setdefault(k, v)
        return d

    def cookies(self):
        return [v for k, v in self.headers if k.lower() == "set-cookie"]

    def text(self, limit=None):
        if limit is not None:
            return self.body[:limit].decode("utf-8", errors="replace")
        return self.body.decode("utf-8", errors="replace")


def request(url, method="GET", data=None, headers=None, timeout=10,
            max_retries=2, follow_redirects=True, rate=None):
    """Perform one HTTP request with keep-alive, retries and redirect capture.

    Returns a Response. Raises URLError-ish exceptions after retries are
    exhausted; connection-level resets mid-keep-alive are retried once.
    """
    if rate:
        set_rate(rate)
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*",
            "Accept-Encoding": "identity", "Connection": "keep-alive"}
    if headers:
        hdrs.update({k: v for k, v in headers.items() if v is not None})
    body = data
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode()

    redirects = []
    current = url
    last_exc = None
    for _attempt in range(max_retries + 1):
        limiter.wait(urllib.parse.urlsplit(current).hostname or "")
        try:
            conn, key = _conn_for(current, timeout)
            path = urllib.parse.urlsplit(current)
            reqpath = path.path or "/"
            if path.query:
                reqpath += "?" + path.query
            conn.request(method, reqpath, body=body, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            headers_list = resp.getheaders()
            status = resp.status
            location = None
            for k, v in headers_list:
                if k.lower() == "location" and status in (301, 302, 303, 307, 308):
                    location = v
                    break
            if location and follow_redirects and len(redirects) < 10:
                redirects.append((current, status, location))
                current = urllib.parse.urljoin(current, location)
                if current in [r[0] for r in redirects]:
                    break  # redirect loop
                if method == "POST" and status == 303:
                    method = "GET"
                    body = None
                continue
            return Response(status, headers_list, raw, current, redirects)
        except (http.client.RemoteDisconnected, ConnectionResetError,
                socket.timeout, http.client.BadStatusLine) as e:
            last_exc = e
            # Server closed an idle keep-alive socket - drop and retry once
            conn, key = _conn_for(current, timeout)
            try:
                conn.close()
            except Exception:
                pass
            if hasattr(_local, "conns") and key in _local.conns:
                del _local.conns[key]
            time.sleep(0.3)
            continue
        except OSError as e:
            last_exc = e
            time.sleep(0.5)
            continue
    raise last_exc or OSError("request failed")


def retry_after(resp):
    """Parse Retry-After into seconds (None when absent/unparseable)."""
    v = resp.header("Retry-After")
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def get(url, **kw):
    return request(url, "GET", **kw)


def post(url, **kw):
    return request(url, "POST", **kw)


def fetch_json(url, timeout=15, **kw):
    resp = request(url, timeout=timeout, **kw)
    return json.loads(resp.body.decode("utf-8", errors="replace"))


# ---------- socket helpers ----------

def tcp_connect(host, port, timeout=5):
    """Open a TCP socket. Returns sock (caller closes)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def recv_all(sock, n=4096, timeout=3):
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except socket.timeout:
        return b""


def udp_exchange(host, port, payload, timeout=3, retries=2):
    """Send one UDP datagram, read one reply. Returns bytes or None."""
    for _ in range(retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(payload, (host, port))
                data, _addr = s.recvfrom(65535)
                return data
        except (socket.timeout, OSError):
            continue
    return None
