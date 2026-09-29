"""
Vantic Utils - Shared visual system and helpers
A cohesive styling layer: every tool draws through this.
"""

import os
import re
import sys
import time
import shutil
import threading
from datetime import datetime

ANSI_RE = re.compile(r'\033\[[0-9;]*m')

# Global output modes (set once by the CLI from --json / --quiet)
JSON_MODE = False   # True: machine JSON on stdout, all human output to stderr
QUIET_MODE = False  # True: suppress info-level chatter (errors still shown)

_REAL_STDOUT = sys.stdout


def _out(*args, **kwargs):
    """Route human output: stderr when --json so stdout stays machine-clean."""
    print(*args, file=sys.stderr if JSON_MODE else sys.stdout, **kwargs)


def emit_json(doc):
    """Print the machine-readable JSON document to the real stdout (--json mode)."""
    import json
    _REAL_STDOUT.write(json.dumps(doc, indent=2, default=str) + "\n")
    _REAL_STDOUT.flush()


def set_json_mode(enabled):
    """Enable JSON mode: swap sys.stdout to stderr so every raw print() in
    any tool routes human output away from the machine stream."""
    global JSON_MODE
    JSON_MODE = bool(enabled)
    if enabled:
        sys.stdout = sys.stderr
    else:
        sys.stdout = _REAL_STDOUT


def set_quiet_mode(enabled):
    global QUIET_MODE
    QUIET_MODE = bool(enabled)


# --- terminal auto-sizing -------------------------------------------------
# The UI (banner, tables, two-level menu) reads best at >= these sizes.
# auto_size_terminal() grows a smaller window via the XTWINOPS escape
# sequence - honored by iTerm2, Windows Terminal (1.22+) and most Linux
# terminals; silently ignored by macOS Terminal.app (the .app launcher sets
# its window bounds via AppleScript instead) and legacy conhost (the
# Windows .bat uses `mode con` instead). Only ever grows, never shrinks.
MIN_COLS = 110
MIN_ROWS = 36


def auto_size_terminal(min_cols=MIN_COLS, min_rows=MIN_ROWS):
    """Grow the terminal window up to the UI minimum when it's smaller.

    Safe everywhere: no-op when piped (non-TTY), in --json mode, or
    when the window is already big enough. Never shrinks a window the
    user deliberately sized.
    """
    if JSON_MODE or not sys.stdout.isatty():
        return
    try:
        size = shutil.get_terminal_size((min_cols, min_rows))
    except Exception:
        return
    cols = max(size.columns, min_cols)
    rows = max(size.lines, min_rows)
    if size.columns >= min_cols and size.lines >= min_rows:
        return
    try:
        sys.stdout.write(f"\033[8;{rows};{cols}t")
        sys.stdout.flush()
    except Exception:
        pass


class Colors:
    """ANSI color codes. Mutable class attributes so --color/--no-color works."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'

    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'

    @classmethod
    def disable(cls):
        for k, v in list(vars(cls).items()):
            if k.isupper() and isinstance(v, str) and v.startswith('\033'):
                setattr(cls, k, '')

    @classmethod
    def strip(cls, text):
        return ANSI_RE.sub('', text)


def visible_len(text):
    """Length of a string ignoring ANSI escapes."""
    return len(ANSI_RE.sub('', str(text)))


def term_width(default=80):
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default


def _box_width(title, min_w=46, max_w=64):
    w = min(max_w, max(min_w, term_width() - 4))
    return max(w, visible_len(title) + 8)


def print_banner():
    """Print the Vantic Breach banner."""
    from vantic import __version__, __author__, __slogan__
    art = (
        f"{Colors.BOLD}{Colors.BRIGHT_CYAN}\n"
        f"   ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗ ██████╗\n"
        f"   ██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝\n"
        f"   ██║   ██║███████║██╔██╗ ██║   ██║   ██║██║     \n"
        f"   ╚██╗ ██╔╝██╔══██║██║╚██╗██║   ██║   ██║██║     \n"
        f"    ╚████╔╝ ██║  ██║██║ ╚████║   ██║   ██║╚██████╗\n"
        f"     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝"
        f"{Colors.RESET}"
        f"{Colors.BOLD}{Colors.BRIGHT_RED}"
        f"\n   B R E A C H   v{__version__}{Colors.RESET}"
        f"{Colors.DIM}   by {__author__}{Colors.RESET}\n"
        f"{Colors.ITALIC}{Colors.BRIGHT_YELLOW}"
        f"\n   \u201c{__slogan__}\u201d{Colors.RESET}\n"
        f"{Colors.DIM}\n   Red Teaming Tool Application{Colors.RESET}\n"
    )
    _out(art)


def print_header(title, subtitle=None):
    """Rounded panel header, centered."""
    w = _box_width(title)
    t = f"  {title}  "
    pad = max(0, (w - visible_len(t)) // 2)
    centered = ' ' * pad + t
    _out()
    _out(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}╭{'─' * (w - 2)}╮{Colors.RESET}")
    _out(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}│{Colors.RESET}{Colors.BOLD}{centered:<{w - 2}}{Colors.RESET}{Colors.BOLD}{Colors.BRIGHT_CYAN}│{Colors.RESET}")
    if subtitle:
        line = f"  {Colors.DIM}{subtitle}{Colors.RESET}"
        line += ' ' * max(0, w - 2 - visible_len(line))
        _out(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}│{Colors.RESET}{line}{Colors.BOLD}{Colors.BRIGHT_CYAN}│{Colors.RESET}")
    _out(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}╰{'─' * (w - 2)}╯{Colors.RESET}")


def print_subheader(title, count=None):
    """Inline section marker: ── TITLE ──────────────"""
    if count is not None:
        title = f"{title} ({count})"
    used = visible_len(title) + 4
    w = max(20, min(term_width() - 4, 64) - used)
    _out()
    _out(f"{Colors.BOLD}{Colors.CYAN}── {title} {'─' * w}{Colors.RESET}")


def print_success(msg):
    _out(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {msg}")


def print_error(msg):
    _out(f"  {Colors.BRIGHT_RED}[-]{Colors.RESET} {msg}")


def print_warning(msg):
    _out(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {msg}")


def print_info(msg):
    _out(f"  {Colors.CYAN}[*]{Colors.RESET} {msg}")


def print_critical(msg):
    _out(f"  {Colors.BOLD}{Colors.BRIGHT_RED}[!!] {msg}{Colors.RESET}")


def print_skip(msg):
    _out(f"  {Colors.DIM}[·] {msg}{Colors.RESET}")


def bullet(msg, color=None, marker='▸'):
    color = color or Colors.CYAN
    _out(f"  {color}{marker}{Colors.RESET} {msg}")


def kv(label, value, color=None, width=18):
    """Aligned key/value row with dotted leader."""
    label = str(label)
    pad = ' ' * max(1, width - visible_len(label))
    val = f"{color}{value}{Colors.RESET}" if color else str(value)
    _out(f"  {Colors.CYAN}{label}{Colors.RESET}{pad}{Colors.DIM}··{Colors.RESET} {val}")


def status_badge(status):
    """Colored badge for port/status text."""
    s = str(status).upper()
    if s in ('OPEN', 'ALIVE', 'VALID', 'OK', 'FOUND'):
        return f"{Colors.BOLD}{Colors.BRIGHT_GREEN}[{s}]{Colors.RESET}"
    if s in ('CLOSED', 'DOWN', 'FAILED'):
        return f"{Colors.DIM}[{s}]{Colors.RESET}"
    if s in ('FILTERED', 'UNKNOWN', 'DEMO'):
        return f"{Colors.YELLOW}[{s}]{Colors.RESET}"
    return f"{Colors.CYAN}[{s}]{Colors.RESET}"


def print_box(content, width=64, color=None, padding=1):
    """Print text in a rounded box, wrapping long lines."""
    import textwrap
    color = color or Colors.CYAN
    inner = width - 2 - padding * 2
    _out()
    _out(f"{color}╭{'─' * (width - 2)}╮{Colors.RESET}")
    for raw_line in content.split('\n'):
        for line in (textwrap.wrap(raw_line, inner) or ['']):
            line = line[:inner] if visible_len(line) > inner else line
            text = f"{line}{' ' * max(0, inner - visible_len(line))}"
            _out(f"{color}│{Colors.RESET}{' ' * padding}{text}{' ' * padding}{color}│{Colors.RESET}")
    _out(f"{color}╰{'─' * (width - 2)}╯{Colors.RESET}")


def print_table(headers, rows, widths=None, min_pad=2):
    """Bordered table. Rows may be plain lists or (cells, color) tuples."""
    rows = list(rows)
    if rows and not isinstance(rows[0], (list, tuple)):
        rows = [rows]
    n_cols = len(headers)
    if not widths:
        widths = [visible_len(str(h)) for h in headers]
        for row in rows:
            cells = row[0] if isinstance(row, tuple) else row
            for i, cell in enumerate(cells[:n_cols]):
                widths[i] = max(widths[i], visible_len(str(cell)))
        widths = [w + min_pad for w in widths]

    def line(l, m, r):
        return f"{Colors.DIM}{l}{m.join('─' * w for w in widths)}{r}{Colors.RESET}"

    def fmt(cells, color=None):
        out = []
        for cell, w in zip(list(cells) + [''] * n_cols, widths):
            cell = str(cell)
            cell = f"{color}{cell}{Colors.RESET}" if color else cell
            out.append(cell + ' ' * max(0, w - visible_len(str(cell))))
        return out

    _out()
    _out('  ' + line('┌', '┬', '┐'))
    _out('  ' + f"{Colors.DIM}│{Colors.RESET}" + f"{Colors.DIM}│{Colors.RESET}".join(fmt(headers, Colors.BOLD)) + f"{Colors.DIM}│{Colors.RESET}")
    _out('  ' + line('├', '┼', '┤'))
    for row in rows:
        cells, color = (row if isinstance(row, tuple) else (row, None))
        _out('  ' + f"{Colors.DIM}│{Colors.RESET}" + f"{Colors.DIM}│{Colors.RESET}".join(fmt(cells, color)) + f"{Colors.DIM}│{Colors.RESET}")
    _out('  ' + line('└', '┴', '┘'))


def print_summary(title, rows, color=None):
    """Summary panel: pairs of (label, value)."""
    color = color or Colors.BRIGHT_CYAN
    w = _box_width(title, min_w=40)
    label_w = max((visible_len(str(k)) for k, _ in rows), default=10) + 2
    _out()
    _out(f"{color}╭{'─' * (w - 2)}╮{Colors.RESET}")
    t = f" {title} "
    _out(f"{color}│{Colors.RESET}{Colors.BOLD}{t:<{w - 2}}{Colors.RESET}{color}│{Colors.RESET}")
    _out(f"{color}├{'─' * (w - 2)}┤{Colors.RESET}")
    for k, v in rows:
        v_str = str(v)
        v_col = v_str
        line = f" {k:<{label_w}}{v_str}"
        if visible_len(line) > w - 4:
            line = line[:w - 5] + '…'
        _out(f"{color}│{Colors.RESET}{line:<{w - 2}}{color}│{Colors.RESET}")
    _out(f"{color}╰{'─' * (w - 2)}╯{Colors.RESET}")


class ProgressBar:
    """Single-line, throttled progress bar: ▸ desc [████░░░] 45.2% (123/272) 88.4/s eta 0:07"""

    def __init__(self, total, desc='', width=28, color=None):
        self.total = max(1, total)
        self.desc = desc
        self.width = width
        self.color = color
        self.current = 0
        self.start = time.time()
        self._last_render = 0.0
        self._rendered_current = -1
        self._done = False
        self._tty = sys.stdout.isatty() and not JSON_MODE

    def _bar_color(self):
        return self.color or Colors.CYAN

    def update(self, n=1, desc=None):
        self.current += n
        if desc is not None:
            self.desc = desc
        if not self._tty:
            return
        now = time.time()
        if now - self._last_render > 0.05 or self.current >= self.total:
            self._render()
            self._last_render = now
        if self.current >= self.total and not self._done:
            self.finish()

    def _render(self):
        elapsed = time.time() - self.start
        pct = self.current / self.total
        filled = int(self.width * pct)
        c = self._bar_color()
        bar = f"{c}{'█' * filled}{Colors.DIM}{'░' * (self.width - filled)}{Colors.RESET}"
        rate = self.current / elapsed if elapsed > 0.5 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0
        eta_s = f"{int(eta // 60)}:{int(eta % 60):02d}" if eta > 0 else '--:--'
        rate_s = f"{rate:6.1f}/s" if rate > 0 else '      '
        line = (f"\r  {c}▸{Colors.RESET} {self.desc:<18} {bar} "
                f"{pct * 100:5.1f}% ({self.current}/{self.total}) {Colors.DIM}{rate_s} eta {eta_s}{Colors.RESET}")
        stream = sys.stderr if JSON_MODE else sys.stdout
        stream.write('\r\033[K' + line[:term_width() - 1])
        stream.flush()
        self._rendered_current = self.current

    def interrupt(self):
        """Erase the bar line so callers can print a hit above it."""
        if not self._tty:
            return
        stream = sys.stderr if JSON_MODE else sys.stdout
        stream.write('\r\033[K')
        stream.flush()
        self._last_render = 0.0

    def finish(self, note=None):
        if self._done:
            return
        self._done = True
        if not self._tty:
            return
        if self._rendered_current != self.current:
            self._render()
        suffix = f"  {Colors.BRIGHT_GREEN}✓{Colors.RESET} {note}" if note else ''
        stream = sys.stderr if JSON_MODE else sys.stdout
        if suffix:
            stream.write(f"\r\033[K{suffix}")
        stream.write('\n')
        stream.flush()


class Spinner:
    """Indeterminate spinner on one line, safe inside with-blocks."""

    FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def __init__(self, message='', color=None, delay=0.08):
        self.message = message
        self.color = color
        self.delay = delay
        self._stop = threading.Event()
        self._thread = None

    def _spin(self):
        i = 0
        c = self.color or Colors.CYAN
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write(f"\r  {c}{frame}{Colors.RESET} {self.message}   ")
            sys.stdout.flush()
            i += 1
            self._stop.wait(self.delay)
        sys.stdout.write('\r' + ' ' * (visible_len(self.message) + 10) + '\r')
        sys.stdout.flush()

    def update(self, message):
        self.message = message

    def __enter__(self):
        if self._stop.is_set() or not sys.stdout.isatty() or JSON_MODE:
            self._stop.set()
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join()
        return False


def timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def format_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


def indent(text, spaces=4):
    return '\n'.join(' ' * spaces + line for line in text.split('\n'))


def clear_screen():
    _out('\033[2J\033[H', end='')


def yes_no_prompt(question, default=True):
    default_str = "Y/n" if default else "y/N"
    try:
        response = input(f"  {Colors.CYAN}{question}{Colors.RESET} {Colors.DIM}[{default_str}]{Colors.RESET} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        _out()
        return default
    if not response:
        return default
    return response in ('y', 'yes')


def input_prompt(prompt, default=""):
    suffix = f" {Colors.DIM}[{default}]{Colors.RESET}" if default else ''
    try:
        response = input(f"  {Colors.CYAN}{prompt}{Colors.RESET}{suffix} ").strip()
    except (EOFError, KeyboardInterrupt):
        _out()
        return default
    return response if response else default


def resolve_wordlist(path, name=None):
    """Resolve a wordlist path: as-given, or bundled wordlists/ dir.

    Search roots cover: PyInstaller _MEIPASS (frozen exe), project root,
    the executable's folder (app bundles), and the current directory.
    """
    import pathlib
    if path and os.path.isfile(path):
        return path
    if name:
        here = pathlib.Path(__file__).resolve()
        roots = []
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            roots.append(pathlib.Path(meipass) / 'wordlists')
        roots += [
            pathlib.Path.cwd() / 'wordlists',
            pathlib.Path(sys.argv[0]).resolve().parent / 'wordlists',
            here.parent.parent / 'wordlists',
        ]
        for root in roots:
            candidate = root / name
            if candidate.is_file():
                return str(candidate)
    return path


def load_lines(filepath):
    """Load non-empty, non-comment lines from a file."""
    lines = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
    except FileNotFoundError:
        return None
    return lines


def resolve_datafile(name):
    """Resolve a bundled data file/dir (vantic/data/<name>).

    Search roots: package data dir, PyInstaller _MEIPASS, cwd.
    Returns an absolute path string or None.
    """
    import pathlib
    here = pathlib.Path(__file__).resolve()
    roots = [here.parent.parent / 'data']
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        roots.append(pathlib.Path(meipass) / 'data')
        roots.append(pathlib.Path(meipass))
    roots.append(pathlib.Path.cwd() / 'data')
    for root in roots:
        for candidate in (root / name, root / 'checks' / name):
            if candidate.exists():
                return str(candidate)
    return None


def load_json_data(name):
    """Load a bundled JSON data file (vantic/data/<name>)."""
    import json
    path = resolve_datafile(name)
    if not path:
        return None
    try:
        with open(path, 'r', errors='ignore') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
