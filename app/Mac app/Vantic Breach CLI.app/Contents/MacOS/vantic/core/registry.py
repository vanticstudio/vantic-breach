"""
Tool Registry - plugin discovery + auto-registration

Every tool module in vantic/tools/ declares a META dict:

    META = {
        "name": "ctlog",                # subcommand; must == filename stem
        "title": "CT Log Lookup",
        "category": "RECONNAISSANCE",   # one of CATEGORY_ORDER
        "description": "one-line summary",
        "risk": "safe",                 # safe | intrusive | destructive
        "examples": ["vantic ctlog example.com"],
        "flow": [ ... ],                # optional: menu/GUI prompt spec
        "guard": {"target": "host"},    # optional: scope-guard arg mapping
        "gui_fields": ...               # optional: GUI override
    }

    def add_arguments(parser): ...       # argparse subparser
    def run(args): ...                  # execute

A failed import disables that one tool with a warning - it never breaks
startup. Users can drop extra plugins into ~/.vantic/plugins/.
"""

import importlib
import importlib.util
import os
import pkgutil
import sys

from vantic.utils import Colors, print_warning

# Category display order + colors (menu + help + GUI all derive from this)
CATEGORY_ORDER = [
    ("RECONNAISSANCE", Colors.BRIGHT_CYAN),
    ("DISCOVERY", Colors.BRIGHT_BLUE),
    ("INTERNAL / AD", Colors.BRIGHT_MAGENTA),
    ("SERVICES", Colors.BRIGHT_YELLOW),
    ("WEB ANALYSIS", Colors.BRIGHT_YELLOW),
    ("CREDENTIALS", Colors.BRIGHT_GREEN),
    ("GATEWAY / INFRA", Colors.BRIGHT_CYAN),
    ("VULNERABILITIES", Colors.BRIGHT_RED),
    ("EXPLOITATION", Colors.BRIGHT_RED),
    ("POST-EXPLOITATION", Colors.BRIGHT_MAGENTA),
    ("ANALYSIS & REPORTING", Colors.BRIGHT_WHITE),
]

# Names the registry may not claim (CLI-level commands)
RESERVED_NAMES = {"gui", "engage"}

_TOOLS = {}          # name -> module
_FAILED = []         # (module_name, error)
_LOADED = False


def _validate(mod, name):
    """A module is a tool iff it exposes META + add_arguments + run."""
    meta = getattr(mod, "META", None)
    if not isinstance(meta, dict):
        return False
    if not callable(getattr(mod, "add_arguments", None)):
        return False
    if not callable(getattr(mod, "run", None)):
        return False
    if name in RESERVED_NAMES:
        return False
    return True


def _register(mod, name, origin=""):
    if not _validate(mod, name):
        _FAILED.append((name, origin or "missing META/add_arguments/run"))
        return False
    meta = mod.META
    if meta.get("name") != name:
        _FAILED.append((name, f"META name {meta.get('name')!r} != filename {name!r}"))
        return False
    if meta.get("category") not in [c for c, _ in CATEGORY_ORDER]:
        _FAILED.append((name, f"unknown category {meta.get('category')!r}"))
        return False
    meta.setdefault("risk", "safe")
    meta.setdefault("examples", [])
    meta.setdefault("description", "")
    _TOOLS[name] = mod
    return True


def _load_package_tools():
    import vantic.tools as tools_pkg
    for importer, modname, ispkg in pkgutil.iter_modules(tools_pkg.__path__):
        if ispkg or modname.startswith('_'):
            continue
        try:
            mod = importlib.import_module(f"vantic.tools.{modname}")
        except Exception as e:
            _FAILED.append((modname, f"import failed: {e}"))
            continue
        _register(mod, modname)


def _load_user_plugins():
    plugdir = os.path.join(os.path.expanduser("~"), ".vantic", "plugins")
    if not os.path.isdir(plugdir):
        return
    for fname in sorted(os.listdir(plugdir)):
        if not fname.endswith(".py") or fname.startswith('_'):
            continue
        name = fname[:-3]
        if name in _TOOLS or name in RESERVED_NAMES:
            continue
        try:
            spec = importlib.util.spec_from_file_location(name, os.path.join(plugdir, fname))
            mod = importlib.util.module_from_spec(spec)
            # Plugins see the same package layout as built-ins
            sys.modules.setdefault(f"vantic.plugins.{name}", mod)
            spec.loader.exec_module(mod)
        except Exception as e:
            _FAILED.append((name, f"plugin import failed: {e}"))
            continue
        _register(mod, name, origin="plugin")


def load(force=False):
    """Discover all tools. Idempotent; safe to call repeatedly."""
    global _LOADED
    if _LOADED and not force:
        return
    _LOADED = True
    _TOOLS.clear()
    _FAILED.clear()
    _load_package_tools()
    _load_user_plugins()


def get(name):
    """Return a tool module by name, or None."""
    load()
    return _TOOLS.get(name)


def all_names():
    load()
    return sorted(_TOOLS.keys())


def tools():
    """List of tool modules, category-ordered then alphabetical."""
    load()
    order = {cat: i for i, (cat, _) in enumerate(CATEGORY_ORDER)}
    mods = list(_TOOLS.values())
    mods.sort(key=lambda m: (order[m.META["category"]], m.META["name"]))
    return mods


def categories():
    """[(category, color, [modules...])] in display order."""
    load()
    cats = {cat: [] for cat, _ in CATEGORY_ORDER}
    for mod in tools():
        cats[mod.META["category"]].append(mod)
    return [(cat, color, cats[cat]) for cat, color in CATEGORY_ORDER]


def failures():
    load()
    return list(_FAILED)


def warn_failures():
    """One-line warnings for tools that failed to load (never fatal)."""
    for name, why in failures():
        print_warning(f"Tool '{name}' disabled: {why}")
