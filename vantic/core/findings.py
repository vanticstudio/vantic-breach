"""
Findings model - severity bands, CVSS v3.1 base score, store integration

Every assessment tool reports through this so the engagement store,
report generator, and diff engine all speak one shape.
"""

import hashlib
import threading

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_COLORS = {
    "info": "DIM",
    "low": "CYAN",
    "medium": "BRIGHT_YELLOW",
    "high": "BRIGHT_RED",
    "critical": "BRIGHT_RED",
}

# CVSS v3.1 base metrics -> numeric weights (simplified weight tables)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_C_IA = {"H": 0.56, "L": 0.22, "N": 0.00}


def cvss_base(av="N", ac="L", pr="N", ui="N", c="L", i="L", a="L", scope="U"):
    """CVSS v3.1 base score from metric letters. Returns (score, vector)."""
    metrics = {
        "AV": str(av).upper(), "AC": str(ac).upper(), "PR": str(pr).upper(),
        "UI": str(ui).upper(), "C": str(c).upper(), "I": str(i).upper(),
        "A": str(a).upper(), "S": str(scope).upper(),
    }
    vector = "CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}".format(**metrics)
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        iss = 1 - (1 - _C_IA[metrics["C"]]) * (1 - _C_IA[metrics["I"]]) * (1 - _C_IA[metrics["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed \
            else 6.42 * iss
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
        if impact <= 0:
            return 0.0, vector
        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10)
        else:
            score = min(impact + exploitability, 10)
        # Roundup to one decimal (CVSS spec)
        import math
        score = math.ceil(score * 10) / 10
        return score, vector
    except (KeyError, TypeError):
        return 0.0, vector


def severity_from_score(score):
    """Shared severity bands: 0 info, 0.1-3.9 low, 4-6.9 medium, 7-8.9 high, 9-10 critical."""
    if score is None:
        return "info"
    if score <= 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


class Finding:
    """One assessment finding, in the shape the store + report expect."""

    def __init__(self, family, title, severity="info", target=None, port=None,
                 evidence="", remediation="", tool="vantic", cvss_score=None,
                 cvss_vector=None, status="open", instance_key=None):
        if severity not in SEVERITIES:
            severity = "info"
        self.family = family
        self.title = title
        self.severity = severity
        self.target = target
        self.port = port
        self.evidence = evidence or ""
        self.remediation = remediation or ""
        self.tool = tool
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        self.status = status
        if cvss_score is not None and not cvss_vector:
            self.severity = severity_from_score(cvss_score) if severity == "info" else severity
        key = instance_key or f"{title}|{evidence[:64]}"
        raw = f"{family}|{target}|{port}|{key}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self):
        return {
            "family": self.family, "title": self.title, "severity": self.severity,
            "target": self.target, "port": self.port, "evidence": self.evidence,
            "remediation": self.remediation, "tool": self.tool,
            "cvss_score": self.cvss_score, "cvss_vector": self.cvss_vector,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            family=d.get("family", "general"), title=d.get("title", "untitled"),
            severity=d.get("severity", "info"), target=d.get("target"),
            port=d.get("port"), evidence=d.get("evidence", ""),
            remediation=d.get("remediation", ""), tool=d.get("tool", "vantic"),
            cvss_score=d.get("cvss_score"), cvss_vector=d.get("cvss_vector"),
            status=d.get("status", "open"),
        )


# ---- module-level collection (works with or without an engagement) ----

_LOCAL = threading.local()


def _bucket():
    if not hasattr(_LOCAL, "findings"):
        _LOCAL.findings = []
    return _LOCAL.findings


def record(finding):
    """Record a finding: local thread bucket + engagement store if active."""
    _bucket().append(finding)
    from vantic.core import store
    if store.is_active():
        try:
            store.add_finding(finding)
        except Exception:
            pass
    return finding


def make(**kwargs):
    return record(Finding(**kwargs))


def drain():
    """Return + clear this thread's findings (used by --json emitters)."""
    out = list(_bucket())
    _bucket().clear()
    return out


def severity_badge(sev):
    from vantic.utils import Colors
    color = getattr(Colors, SEVERITY_COLORS.get(sev, "CYAN"))
    if sev == "critical":
        return f"{Colors.BOLD}{Colors.BG_RED}{color}{sev.upper()}{Colors.RESET}"
    return f"{Colors.BOLD}{color}{sev.upper():8}{Colors.RESET}"
