"""
Scope Guard - engagement scope enforcement

When an engagement is active and has scope entries, every tool run is
checked before execution. Semantics:

  explicit deny match  -> refuse (deny always wins)
  explicit allow match -> allow
  no match at all      -> refuse if any ALLOW entries exist (allow-list
                         mode), otherwise allow (deny-list mode)

Hostnames are verified by their RESOLVED A/AAAA records (not name
strings) so a subdomain CNAMEing outside the estate cannot be touched
by accident. Exit code 3 = scope refusal.
"""

import ipaddress
import socket

from vantic.core import store


class ScopeRefusal(Exception):
    """Raised when a target is outside the engagement scope."""

    EXIT_CODE = 3

    def __init__(self, target, reason):
        self.target = target
        self.reason = reason
        super().__init__(f"target '{target}' outside engagement scope: {reason}")


def _domain_match(name, pattern):
    """ '*.example.com' matches a.example.com (one level) and example.com. """
    name = name.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return name == base or (name.endswith("." + base) and "." not in name[:-len(base) - 1])
    return name == pattern or name.endswith("." + pattern)


def _ip_in_scope(ip, scope):
    """True/False on explicit match, None on no opinion."""
    for kind, value, allowed in scope:
        if kind == "cidr":
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False):
                    return allowed
            except ValueError:
                continue
        elif kind == "host":
            if ip == value:
                return allowed
    return None


def _host_allowed(host, scope):
    """True/False/None(no opinion) for an IP or hostname."""
    host = host.strip()
    # Literal IP?
    try:
        ipaddress.ip_address(host)
        return _ip_in_scope(host, scope)
    except ValueError:
        pass
    # Hostname: explicit domain rules first
    for kind, value, allowed in scope:
        if kind == "domain" and _domain_match(host, value):
            return allowed
    # Otherwise judge by resolved records
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = {info[4][0] for info in infos}
    except (socket.gaierror, OSError):
        return None  # unresolvable: no opinion
    if ips:
        votes = []
        for ip in ips:
            verdict = _ip_in_scope(ip, scope)
            votes.append(verdict)
        if any(v is False for v in votes):
            return False
        if votes and all(v is True for v in votes):
            return True
    return None


def _cidr_allowed(cidr, scope):
    """True/False/None. The whole CIDR must sit inside an allowed CIDR."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    for kind, value, allowed in scope:
        if kind != "cidr":
            continue
        try:
            allowed_net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if net.subnet_of(allowed_net):
            return allowed
    return None


def _url_allowed(url, scope):
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@", 1)[-1]
    if not host:
        return None
    for kind, value, allowed in scope:
        if kind == "url" and url.rstrip("/") == value.rstrip("/"):
            return allowed
    return _host_allowed(host, scope)


def _has_allows(scope):
    return any(allowed for _kind, _value, allowed in scope)


def _decide(verdict, has_allows, item, what):
    if verdict is False:
        raise ScopeRefusal(item, f"explicitly denied ({what})")
    if verdict is None and has_allows:
        raise ScopeRefusal(item, f"not matched by any allow entry ({what})")


def check(tool_meta, args):
    """Raise ScopeRefusal if any guarded target is out of scope.

    Guard mapping comes from META["guard"]: {"target": "host", "cidr": "cidr",
    "domain": "domain", "url": "url"} - dest names on the parsed args.
    """
    engagement = store.active_engagement()
    if not engagement:
        return  # no engagement: classic standalone mode

    scope = store.get_scope()
    if not scope:
        return  # engagement without declared scope: allow all (audit notes it)

    has_allows = _has_allows(scope)

    mapping = tool_meta.get("guard", {}) if tool_meta else {}
    for dest, kind in mapping.items():
        value = getattr(args, dest, None)
        if not value:
            continue
        for item in str(value).split(","):
            item = item.strip()
            if not item:
                continue
            if kind == "cidr":
                _decide(_cidr_allowed(item, scope), has_allows, item, "CIDR")
            elif kind == "domain":
                verdict = None
                for k, v, allowed in scope:
                    if k == "domain" and _domain_match(item, v):
                        verdict = allowed
                        break
                _decide(verdict, has_allows, item, "domain")
            elif kind == "url":
                _decide(_url_allowed(item, scope), has_allows, item, "URL host")
            else:  # host
                _decide(_host_allowed(item, scope), has_allows, item, "resolved host")
