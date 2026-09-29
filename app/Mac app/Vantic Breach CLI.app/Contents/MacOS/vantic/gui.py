"""
Vantic Breach - GUI Edition
A point-and-click front end that wraps the same CLI modules.
Tools run through the real CLI in a subprocess, so output, flags and
export behavior stay identical to the terminal experience.
"""

import os
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from vantic.core import registry

ROOT = Path(__file__).resolve().parent.parent
FROZEN = getattr(sys, 'frozen', False)

ANSI_RE = re.compile(r'\033\[[0-9;]*m')

BG = '#0f1220'
BG_PANEL = '#161a2e'
BG_INPUT = '#0b0e1a'
BG_SIDEBAR = '#0b0e1a'
FG = '#e6e6f0'
FG_DIM = '#7a7f95'
ACCENT = '#39d6e0'
GREEN = '#4ade80'
RED = '#f87171'
YELLOW = '#facc15'
CYAN = '#39d6e0'
MAGENTA = '#e879f9'
BORDER = '#262b45'

MONO = ('Menlo', 11) if sys.platform == 'darwin' else ('Consolas', 10)
UI = ('Helvetica', 12) if sys.platform == 'darwin' else ('Segoe UI', 10)
UI_BOLD = ('Helvetica', 13, 'bold') if sys.platform == 'darwin' else ('Segoe UI', 11, 'bold')


class Field:
    def __init__(self, label, flag=None, kind='entry', default='', values=None,
                 required=False, hint=None, extra=False):
        self.label = label
        self.flag = flag
        self.kind = kind
        self.default = default
        self.values = values or []
        self.required = required
        self.hint = hint
        self.extra = extra


class ToolSpec:
    def __init__(self, cmd, title, desc, fields):
        self.cmd = cmd
        self.title = title
        self.desc = desc
        self.fields = fields


def _fields_from_meta(meta):
    """Convert a META flow spec into GUI Fields (+ an Extra args escape hatch)."""
    fields = []
    choices = meta.get("choices", {})
    for step in meta.get("flow", []):
        kind = step[0]
        if kind == 'sub':
            _, dest, label, default = step
            fields.append(Field(label, kind='choice', default=default,
                               values=choices.get(dest, []), required=True))
        elif kind == 'arg':
            _, dest, label, default = step
            fields.append(Field(label, kind='entry', default=default or '',
                               required=default is None))
        elif kind == 'opt':
            _, flag, label, default = step
            fields.append(Field(label, flag=flag, default=default or '',
                               required=False))
        elif kind == 'flag':
            _, flag, label = step
            fields.append(Field(label, flag=flag, kind='check'))
    fields.append(Field('Extra args', kind='entry', hint='raw CLI flags, e.g. --delay 1'))
    return fields


def build_specs():
    """Generate every ToolSpec from the registry (no hand-maintained list)."""
    registry.load()
    specs = {}
    for mod in registry.tools():
        meta = mod.META
        specs[meta["name"]] = ToolSpec(meta["name"], meta["title"],
                                      meta["description"],
                                      _fields_from_meta(meta))
    return specs


SPECS = build_specs()


def build_argv(spec, values):
    """Turn form values into a CLI argv list. Raises ValueError on missing required."""
    import shlex
    argv = [spec.cmd]

    for f in spec.fields:
        if f.extra:
            raw = (values.get(f.label) or '').strip()
            if raw:
                argv.extend(shlex.split(raw))
            continue
        v = values.get(f.label)
        if f.kind == 'check':
            if v:
                argv.append(f.flag)
        elif f.flag:
            v = (v or '').strip()
            if v:
                argv.extend([f.flag, v])
        else:  # positional or subcommand
            v = (v or '').strip()
            if f.required and not v:
                raise ValueError(f"'{f.label}' is required")
            if v:
                argv.append(v)
    return argv


def spawn_command(argv):
    """Full command to run the CLI headless. In frozen builds we respawn the
    exe itself in CLI mode so Stop (process terminate) still works."""
    if FROZEN:
        env = dict(os.environ, VANTIC_CLI_RUN='1')
        return [sys.executable, '--cli-run', '--no-banner', '--color', 'never'] + argv, env
    return [sys.executable, str(ROOT / 'vantic.py'),
            '--no-banner', '--color', 'never'] + argv, None


def strip_ansi(text):
    return ANSI_RE.sub('', text)


class Runner:
    """Subprocess runner streaming lines into a queue."""

    def __init__(self):
        self.proc = None
        self.thread = None

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, argv, on_line, on_done):
        cmd, env = spawn_command(argv)
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=str(ROOT), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors='replace', bufsize=1
            )
        except OSError as e:
            on_line(f"[-] Failed to start: {e}")
            on_done(1)
            return

        def reader():
            assert self.proc and self.proc.stdout
            for line in self.proc.stdout:
                on_line(line.rstrip('\n'))
            code = self.proc.wait()
            on_done(code)

        self.thread = threading.Thread(target=reader, daemon=True)
        self.thread.start()

    def stop(self):
        if self.running():
            try:
                self.proc.terminate()
            except Exception:
                pass


class VanticGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        from vantic import __version__
        self.title(f"Vantic Breach v{__version__}")
        self.configure(bg=BG)
        self.geometry('1180x720')
        self.minsize(960, 600)

        self.queue = queue.Queue()
        self.runner = Runner()
        self.run_started = None
        self.current_cmd = None
        self.buttons = {}

        self._style_ttk()
        self._build_layout()
        self._select_tool('scan')
        self.after(80, self._drain)

    def _style_ttk(self):
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('Vantic.TCombobox',
                        fieldbackground=BG_INPUT, background=BG_PANEL,
                        foreground=FG, arrowcolor=ACCENT, bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER)
        style.map('Vantic.TCombobox', fieldbackground=[('readonly', BG_INPUT)],
                  foreground=[('readonly', FG)])

    def _build_layout(self):
        sidebar = tk.Frame(self, bg=BG_SIDEBAR, width=250)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="VANTIC BREACH", bg=BG_SIDEBAR, fg=ACCENT,
                 font=('Menlo', 15, 'bold') if sys.platform == 'darwin' else ('Consolas', 14, 'bold')
                 ).pack(pady=(18, 2))
        tk.Label(sidebar, text="Red Teaming Tool Application", bg=BG_SIDEBAR,
                 fg=FG_DIM, font=UI).pack(pady=(0, 14))

        for category, color, mods in registry.categories():
            if not mods:
                continue
            tk.Label(sidebar, text=category.upper(), bg=BG_SIDEBAR, fg=FG_DIM,
                     font=(UI[0], 9, 'bold'), anchor='w', padx=18
                     ).pack(fill='x', pady=(10, 2))
            for mod in mods:
                meta = mod.META
                cmd, name = meta["name"], meta["title"]
                btn = tk.Button(sidebar, text=f"  {name}", anchor='w', bd=0,
                                bg=BG_SIDEBAR, fg=FG, activebackground=BG_PANEL,
                                activeforeground=ACCENT, font=UI,
                                command=lambda c=cmd: self._select_tool(c))
                btn.pack(fill='x', ipady=5)
                self.buttons[cmd] = btn

        main = tk.Frame(self, bg=BG)
        main.pack(side='right', fill='both', expand=True)

        self.title_label = tk.Label(main, bg=BG, fg=FG, font=UI_BOLD, anchor='w')
        self.title_label.pack(fill='x', padx=22, pady=(16, 0))
        self.desc_label = tk.Label(main, bg=BG, fg=FG_DIM, font=UI, anchor='w')
        self.desc_label.pack(fill='x', padx=22, pady=(0, 8))

        self.form = tk.Frame(main, bg=BG)
        self.form.pack(fill='x', padx=22)

        btnbar = tk.Frame(main, bg=BG)
        btnbar.pack(fill='x', padx=22, pady=10)
        self.run_btn = tk.Button(btnbar, text="Run", command=self._run, bd=0,
                                 bg='#123b2a', fg=GREEN, activebackground='#1a5238',
                                 font=UI_BOLD, padx=22, pady=6)
        self.run_btn.pack(side='left')
        self.stop_btn = tk.Button(btnbar, text="Stop", command=self._stop, bd=0,
                                  bg=BG_PANEL, fg=RED, activebackground=BORDER,
                                  font=UI_BOLD, padx=18, pady=6, state='disabled')
        self.stop_btn.pack(side='left', padx=(8, 0))
        tk.Button(btnbar, text="Save output", command=self._save, bd=0,
                  bg=BG_PANEL, fg=FG, activebackground=BORDER, font=UI,
                  padx=14, pady=6).pack(side='left', padx=(8, 0))
        tk.Button(btnbar, text="Clear", command=self._clear, bd=0,
                  bg=BG_PANEL, fg=FG_DIM, activebackground=BORDER, font=UI,
                  padx=14, pady=6).pack(side='left', padx=(8, 0))

        outwrap = tk.Frame(main, bg=BORDER, bd=0)
        outwrap.pack(fill='both', expand=True, padx=22, pady=(2, 10))
        self.output = tk.Text(outwrap, bg=BG_INPUT, fg=FG, font=MONO, bd=0,
                              relief='flat', wrap='none', state='disabled',
                              insertbackground=ACCENT, selectbackground=BORDER,
                              padx=12, pady=10)
        scroll = tk.Scrollbar(outwrap, command=self.output.yview, bg=BG_PANEL,
                              troughcolor=BG_INPUT, width=10, bd=0,
                              activebackground=BORDER)
        self.output.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.output.pack(side='left', fill='both', expand=True)

        for tag, cfg in {
            'ok': {'foreground': GREEN},
            'err': {'foreground': RED},
            'crit': {'foreground': RED, 'font': (MONO[0], MONO[1], 'bold')},
            'warn': {'foreground': YELLOW},
            'info': {'foreground': CYAN},
            'dim': {'foreground': FG_DIM},
            'head': {'foreground': ACCENT},
            'body': {'foreground': FG},
        }.items():
            self.output.tag_configure(tag, **cfg)

        self.status = tk.Label(self, bg=BG, fg=FG_DIM, font=UI, anchor='w')
        self.status.pack(fill='x', padx=24, pady=(0, 8))

    def _select_tool(self, cmd):
        for c, btn in self.buttons.items():
            btn.configure(bg=BG_SIDEBAR, fg=FG)
        btn = self.buttons.get(cmd)
        if btn:
            btn.configure(bg=BG_PANEL, fg=ACCENT)

        spec = SPECS[cmd]
        self.selected = spec
        self.title_label.configure(text=spec.title)
        self.desc_label.configure(text=spec.desc)
        for child in self.form.winfo_children():
            child.destroy()

        self.widgets = {}
        row = 0
        for f in spec.fields:
            label = f.label + (' *' if f.required else '')
            tk.Label(self.form, text=label, bg=BG, fg=FG_DIM, font=UI,
                     anchor='w').grid(row=row, column=0, sticky='w', pady=3, padx=(0, 14))

            if f.kind == 'check':
                var = tk.BooleanVar(value=bool(f.default))
                cb = tk.Checkbutton(self.form, variable=var, bg=BG, fg=FG,
                                    activebackground=BG, activeforeground=ACCENT,
                                    selectcolor=BG_INPUT, bd=0, highlightthickness=0)
                cb.grid(row=row, column=1, sticky='w', pady=3)
                self.widgets[f.label] = var
            elif f.kind == 'choice':
                var = tk.StringVar(value=f.default or (f.values[0] if f.values else ''))
                combo = ttk.Combobox(self.form, textvariable=var, values=f.values,
                                     state='readonly', width=28, style='Vantic.TCombobox')
                combo.grid(row=row, column=1, sticky='w', pady=3)
                self.widgets[f.label] = var
            else:
                entry = tk.Entry(self.form, bg=BG_INPUT, fg=FG, font=MONO, bd=0,
                                 relief='flat', insertbackground=ACCENT,
                                 highlightthickness=1, highlightbackground=BORDER,
                                 highlightcolor=ACCENT, width=42)
                if f.default:
                    entry.insert(0, str(f.default))
                entry.grid(row=row, column=1, sticky='w', pady=3)
                self.widgets[f.label] = entry
            row += 1

        hint = ' · '.join(f"{f.label}: {f.hint}" for f in spec.fields if f.hint)
        if hint:
            tk.Label(self.form, text=hint, bg=BG, fg=FG_DIM,
                     font=(UI[0], 9), anchor='w').grid(row=row, column=0,
                                                       columnspan=2, sticky='w', pady=(6, 0))

    def _collect(self):
        values = {}
        for f in self.selected.fields:
            w = self.widgets.get(f.label)
            if f.kind == 'check':
                values[f.label] = bool(w.get())
            else:
                values[f.label] = w.get() if hasattr(w, 'get') else ''
        return values

    def _run(self):
        if self.runner.running():
            return
        try:
            argv = build_argv(self.selected, self._collect())
        except ValueError as e:
            messagebox.showerror("Vantic Breach", str(e))
            return

        self.current_cmd = self.selected.cmd
        self._append(f"── {self.selected.title} · {time.strftime('%H:%M:%S')} ──\n", 'head')
        self.run_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.run_started = time.time()
        self.status.configure(text=f"Running {self.selected.title}...", fg=YELLOW)
        self.runner.start(argv, self._on_line, self._on_done)

    def _stop(self):
        self.runner.stop()
        self._append("[!] Stopped by user\n", 'warn')

    def _on_line(self, line):
        self.queue.put(line)

    def _on_done(self, code):
        elapsed = time.time() - self.run_started if self.run_started else 0
        self.queue.put(f"\x00DONE\x00{code}\x00{elapsed:.1f}")

    def _drain(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if item.startswith('\x00DONE\x00'):
                    _, _, code, elapsed = item.split('\x00')
                    self._finish(code, elapsed)
                else:
                    self._append(strip_ansi(item) + '\n')
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _append(self, text, tag=None):
        self.output.configure(state='normal')
        for line in text.split('\n')[:-1] or [text]:
            t = tag or self._tag_for(line)
            self.output.insert('end', line + '\n', t)
        self.output.see('end')
        self.output.configure(state='disabled')

    def _tag_for(self, line):
        s = line.strip()
        if '[!!]' in s:
            return 'crit'
        if '[+]' in s:
            return 'ok'
        if '[-]' in s:
            return 'err'
        if '[!]' in s:
            return 'warn'
        if '[*]' in s:
            return 'info'
        if s.startswith('──') or s.startswith('╭') or s.startswith('│') or s.startswith('╰'):
            return 'head'
        if '[·]' in s:
            return 'dim'
        return 'body'

    def _finish(self, code, elapsed):
        self.run_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        color = GREEN if code == '0' else RED
        self.status.configure(
            text=f"{'Finished' if code == '0' else 'Stopped'} in {elapsed}s "
                 f"({self.current_cmd})", fg=color)

    def _clear(self):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')

    def _save(self):
        content = self.output.get('1.0', 'end').rstrip()
        if not content:
            messagebox.showinfo("Vantic Breach", "Nothing to save yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('Text files', '*.txt'), ('All files', '*.*')],
            initialfile=f"vantic_{self.current_cmd or 'output'}.txt")
        if path:
            Path(path).write_text(content, encoding='utf-8')
            self.status.configure(text=f"Output saved to {path}", fg=GREEN)


def run_gui(smoke=False):
    app = VanticGUI()
    if smoke:
        app.after(500, app.destroy)
        app.mainloop()
        print("GUI_SMOKE_OK")
        return
    app.mainloop()


def smoke_test():
    """Headless verification: spec generation, argv building, one real run."""
    spec = SPECS['scan']
    values = {}
    for f in spec.fields:
        values[f.label] = f.default if f.kind != 'check' else False
    values['Target IP or host'] = '127.0.0.1'
    values['Ports (80 | 1-100 | 22,80,443)'] = '5000'
    argv = build_argv(spec, values)
    assert argv[0] == 'scan' and '127.0.0.1' in argv, argv
    assert '-p' in argv and '5000' in argv, argv

    # Every registered tool must generate a form
    assert len(SPECS) >= 40, f"only {len(SPECS)} specs"

    lines = []
    runner = Runner()
    cmd, _ = spawn_command(argv)
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors='replace')
    for line in proc.stdout:
        lines.append(strip_ansi(line.rstrip()))
    code = proc.wait()
    joined = '\n'.join(lines)
    assert 'PORT SCANNER' in joined, joined[:500]
    assert 'Completed at' in joined
    print(f"RUNNER_OK exit={code} lines={len(lines)}")