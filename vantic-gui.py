#!/usr/bin/env python3
"""
Vantic Breach - GUI launcher
Also routes to CLI mode for frozen (PyInstaller) builds: the GUI spawns the
exe itself with --cli-run so Stop (process kill) works in the packaged app.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    argv = sys.argv[1:]

    if '--smoke' in argv:
        from vantic.gui import run_gui
        run_gui(smoke=True)
        return

    if '--cli-run' in argv:
        idx = argv.index('--cli-run')
        sys.argv = ['vantic'] + argv[idx + 1:]
        if sys.stdout is None or not hasattr(sys.stdout, 'write'):
            try:
                sys.stdout = open(1, 'w', buffering=1, encoding='utf-8', closefd=False)
                sys.stderr = open(2, 'w', buffering=1, encoding='utf-8', closefd=False)
            except Exception:
                pass
        from vantic.cli import main as cli_main
        cli_main()
        return

    from vantic.gui import run_gui
    run_gui()


if __name__ == '__main__':
    main()