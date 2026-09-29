"""
Vantic CLI - registry-driven entry point

Tools declare META in vantic/tools/*.py; this module wires them into
argparse, the scope guard, the audit log, the engagement store and the
two-level interactive menu. Exit codes: 0 ok · 1 error · 2 usage ·
3 scope refusal · 4 interrupted/partial.
"""

import argparse
import shlex
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vantic.utils import (
    print_banner, print_header, print_subheader, print_box,
    print_success, print_error, print_warning, print_info,
    kv, timestamp, Colors, input_prompt, yes_no_prompt, clear_screen,
    auto_size_terminal
)

from vantic import __version__, __author__, __slogan__
from vantic.core import registry, store, audit, guard
from vantic.core.registry import CATEGORY_ORDER

RISK_BADGE = {
    "safe": lambda: f"{Colors.DIM}safe{Colors.RESET}",
    "intrusive": lambda: f"{Colors.BRIGHT_YELLOW}intrusive{Colors.RESET}",
    "destructive": lambda: f"{Colors.BRIGHT_RED}destructive{Colors.RESET}",
}


def _epilog():
    lines = [f"{Colors.BOLD}EXAMPLES:{Colors.RESET}"]
    shown = 0
    for mod in registry.tools():
        for ex in mod.META.get("examples", []):
            lines.append(f"  {ex}")
            shown += 1
            if shown >= 10:
                break
        if shown >= 10:
            break
    lines.append(f"  vantic            interactive menu (categories -> tools)")
    lines.append(f"  vantic engage     manage engagements and scope")
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='vantic',
        description=f"Vantic Breach v{__version__} - {__slogan__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog()
    )

    parser.add_argument('-V', '--version', action='version',
                        version=f'Vantic Breach v{__version__} | by {__author__}')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-banner', action='store_true', help='Suppress banner')
    parser.add_argument('--color', choices=['auto', 'always', 'never'], default='auto',
                        help='Color output')
    parser.add_argument('--json', action='store_true',
                        help='Machine-readable JSON to stdout (human output to stderr)')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    parser.add_argument('--engagement', metavar='NAME',
                        help='Run against engagement NAME (one-shot override)')

    subparsers = parser.add_subparsers(dest='command')

    # Tool subcommands from the registry
    for mod in registry.tools():
        meta = mod.META
        tool_parser = subparsers.add_parser(
            meta["name"],
            help=f"{meta['title']} - {meta['description']}",
            description=f"{meta['title']} - {meta['description']}",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=("\n".join(f"  {ex}" for ex in meta.get("examples", [])) or None))
        tool_parser.add_argument('--json', action='store_true',
                                 default=argparse.SUPPRESS,
                                 help='Machine-readable JSON output')
        mod.add_arguments(tool_parser)

    # GUI launcher
    subparsers.add_parser('gui', help='Launch the GUI edition')

    # Engagement management
    eng = subparsers.add_parser('engage', help='Engagement & scope management')
    eng_sub = eng.add_subparsers(dest='engage_cmd')
    p = eng_sub.add_parser('new', help='Create an engagement')
    p.add_argument('name')
    p.add_argument('--client')
    p.add_argument('--auth-ref', help='Authorization reference (ticket / contract)')
    p.add_argument('--start')
    p.add_argument('--end')
    p = eng_sub.add_parser('list', help='List engagements')
    p = eng_sub.add_parser('use', help='Set the active engagement')
    p.add_argument('name')
    p = eng_sub.add_parser('off', help='Deactivate engagement mode')
    p = eng_sub.add_parser('show', help='Show active engagement + scope + stats')
    p = eng_sub.add_parser('scope', help='Replace scope entries')
    for kind in ('cidr', 'domain', 'host', 'url'):
        p.add_argument(f'--allow-{kind}', action='append', default=[], metavar='V')
        p.add_argument(f'--deny-{kind}', action='append', default=[], metavar='V')

    return parser


def dispatch(args, parser):
    """Run one tool command with guard + audit + store wiring."""
    auto_size_terminal()
    mod = registry.get(args.command)
    if mod is None:
        print_error(f"Unknown tool: {args.command}")
        return 1

    meta = mod.META
    argv = sys.argv[1:]

    try:
        guard.check(meta, args)
    except guard.ScopeRefusal as e:
        print_error(f"SCOPE REFUSAL: {e}")
        print(f"      {Colors.DIM}adjust scope with: vantic engage scope --allow-...{Colors.RESET}")
        return guard.ScopeRefusal.EXIT_CODE

    run_id = store.run_start(args.command, argv)
    verdict = "allowed" if store.active_engagement() else "no-engagement"
    with audit.run_timer(args.command, argv, verdict):
        try:
            mod.run(args)
            store.run_finish(run_id, 0)
            return 0
        except KeyboardInterrupt:
            store.run_finish(run_id, 4)
            return 4
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 0
            store.run_finish(run_id, code)
            raise
        except Exception as e:
            store.run_finish(run_id, 1)
            print_error(f"{args.command} failed: {e}")
            if getattr(args, 'verbose', False):
                import traceback
                traceback.print_exc()
            return 1


# ============ ENGAGEMENT COMMANDS ============

def run_engage(args):
    from vantic.utils import set_json_mode
    cmd = getattr(args, 'engage_cmd', None)
    if cmd == 'new':
        store.create(args.name, client=args.client, auth_ref=args.auth_ref,
                    start=args.start, end=args.end)
        store.set_active(args.name)
        print_success(f"Engagement '{args.name}' created and active")
        print_info("Declare scope now so the guard can enforce it:")
        print(f"      {Colors.CYAN}vantic engage scope --allow-cidr 10.0.0.0/24 "
              f"--allow-domain example.com{Colors.RESET}")
    elif cmd == 'list':
        active = store.active_engagement()
        names = store.list_engagements()
        if not names:
            print_info("No engagements yet - create one: vantic engage new <name>")
            return
        rows = []
        for n in names:
            meta = store.metadata(n) or {}
            badge = f"{Colors.BRIGHT_GREEN}ACTIVE{Colors.RESET}" if n == active else ""
            rows.append(((n, meta.get('client') or '-', meta.get('auth_ref') or '-', badge), None))
        from vantic.utils import print_table
        print_table(["NAME", "CLIENT", "AUTH REF", ""], rows, widths=[18, 16, 18, 10])
    elif cmd == 'use':
        if args.name not in store.list_engagements():
            print_error(f"No such engagement: {args.name}")
            return 1
        store.set_active(args.name)
        print_success(f"Engagement '{args.name}' is now active")
    elif cmd == 'off':
        store.set_active(None)
        print_success("Engagement mode off (standalone runs)")
    elif cmd == 'show':
        name = store.active_engagement()
        if not name:
            print_info("No active engagement (standalone mode)")
            return
        meta = store.metadata(name) or {}
        print_header("ENGAGEMENT", name)
        kv("Client", meta.get('client') or '-')
        kv("Authorization", meta.get('auth_ref') or '-')
        kv("Created", meta.get('created_at') or '-')
        scope = store.get_scope()
        print()
        print_subheader("SCOPE", len(scope))
        if not scope:
            print_warning("No scope declared - all targets allowed (declare one for enforcement)")
        for kind, value, allowed in scope:
            mark = f"{Colors.BRIGHT_GREEN}allow{Colors.RESET}" if allowed else f"{Colors.BRIGHT_RED}deny {Colors.RESET}"
            print(f"  {mark} {Colors.BOLD}{kind:<7}{Colors.RESET} {value}")
        findings = store.findings_all()
        services = store.services_all()
        runs = store.run_list(10)
        print()
        print_subheader("STATE")
        kv("Findings", len(findings))
        kv("Services", len(services))
        kv("Runs recorded", len(runs))
    elif cmd == 'scope':
        entries = []
        for kind in ('cidr', 'domain', 'host', 'url'):
            for v in getattr(args, f'allow_{kind}', []):
                entries.append((kind, v, 1))
            for v in getattr(args, f'deny_{kind}', []):
                entries.append((kind, v, 0))
        if not entries:
            print_error("No scope entries given (--allow-cidr/--allow-domain/--allow-host/--allow-url/--deny-...)")
            return 1
        store.set_scope(entries)
        print_success(f"Scope set: {len(entries)} entries "
                      f"({sum(1 for e in entries if e[2])} allow, {sum(1 for e in entries if not e[2])} deny)")
        print_info("Deny entries always beat allow entries")
    else:
        eng_parser_help = ("Commands: new · list · use · off · show · scope\n"
                           "  vantic engage new acme --client 'Acme Corp' --auth-ref 'PO-1234'\n"
                           "  vantic engage scope --allow-cidr 10.0.0.0/24 --deny-host 10.0.0.1\n"
                           "  vantic engage show")
        print_box(eng_parser_help, width=68)
    return 0


# ============ INTERACTIVE MENU ============

def _flow_argv(meta):
    """Turn a META flow spec into an argv token list, or None on cancel."""
    tokens = [meta["name"]]
    spec = meta.get("flow")
    if not spec:
        # Bare fallback: prompt every positional via 'arg' steps if declared
        spec = []
    for step in spec:
        kind = step[0]
        if kind == 'sub':
            _, dest, label, default = step
            val = input_prompt(label, default).lower()
            if not val:
                print_warning("Cancelled")
                return None
            tokens.append(val)
        elif kind == 'arg':
            _, dest, label, default = step
            val = input_prompt(label, default if default else "")
            if not val and default is None:
                print_warning("Cancelled")
                return None
            tokens.append(shlex.quote(val))
        elif kind == 'opt':
            _, flag, label, default = step
            val = input_prompt(label, default if default else "")
            if val:
                tokens.append(f"{flag} {shlex.quote(val)}")
        elif kind == 'flag':
            _, flag, label = step
            if yes_no_prompt(label, False):
                tokens.append(flag)
    return tokens


def _run_flow(parser, meta):
    tokens = _flow_argv(meta)
    if not tokens:
        return
    print()
    print(f"  {Colors.DIM}> vantic {' '.join(tokens)}{Colors.RESET}")
    print()
    try:
        args = parser.parse_args([t for t in tokens])
        dispatch(args, parser)
    except SystemExit:
        pass
    except KeyboardInterrupt:
        print()
        print_warning("Interrupted")
    input_prompt("Press Enter to return to the menu")


def _category_menu(parser, cat_name, color, mods):
    while True:
        auto_size_terminal()
        clear_screen()
        print_banner()
        print(f"  {Colors.BOLD}{color}{cat_name}{Colors.RESET} "
              f"{Colors.DIM}· {len(mods)} tools{Colors.RESET}")
        print()
        n = 1
        numbered = {}
        for mod in mods:
            meta = mod.META
            badge = RISK_BADGE.get(meta.get('risk', 'safe'), RISK_BADGE['safe'])()
            print(f"  {Colors.BOLD}{Colors.DIM}{n:>2}{Colors.RESET}  "
                  f"{Colors.BOLD}{color}{meta['name']:<13}{Colors.RESET}"
                  f"{Colors.BOLD}{meta['title']:<24}{Colors.RESET} {badge}")
            numbered[n] = meta['name']
            n += 1
        print()
        print(f"  {Colors.DIM}b back · tools name also works · q quit{Colors.RESET}")
        print()
        try:
            choice = input(f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}{cat_name.split(' ')[0].lower()}>{Colors.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if not choice:
            continue
        low = choice.lower()
        if low in ('b', 'back', 'q', 'quit', 'exit'):
            return
        name = None
        if low.isdigit():
            idx = int(low)
            name = numbered.get(idx)
        elif low in numbered.values():
            name = low
        if name:
            mod = registry.get(name)
            if mod:
                _run_flow(parser, mod.META)
        else:
            print_error(f"Unknown selection: {choice}")
            input_prompt("Press Enter to continue")


def _engage_menu():
    while True:
        clear_screen()
        print_banner()
        active = store.active_engagement()
        print_header("ENGAGEMENT MANAGER", active or "standalone mode")
        print()
        print(f"  {Colors.BOLD}1{Colors.RESET}  new        create an engagement")
        print(f"  {Colors.BOLD}2{Colors.RESET}  use        switch active engagement")
        print(f"  {Colors.BOLD}3{Colors.RESET}  scope      declare allow/deny entries")
        print(f"  {Colors.BOLD}4{Colors.RESET}  show       scope + collected data")
        print(f"  {Colors.BOLD}5{Colors.RESET}  off        standalone mode")
        print(f"  {Colors.DIM}b back · q quit{Colors.RESET}")
        print()
        try:
            choice = input(f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}engage>{Colors.RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice in ('b', 'back', 'q', 'quit', 'exit'):
            return
        if choice == '1':
            name = input_prompt("Engagement name")
            if not name:
                continue
            client = input_prompt("Client")
            auth = input_prompt("Authorization reference")
            store.create(name, client=client or None, auth_ref=auth or None)
            store.set_active(name)
            print_success(f"Created + active: {name}")
        elif choice == '2':
            names = store.list_engagements()
            if not names:
                print_warning("No engagements yet")
            else:
                for i, n in enumerate(names, 1):
                    mark = f" {Colors.BRIGHT_GREEN}(active){Colors.RESET}" if n == active else ""
                    print(f"  {Colors.BOLD}{i}{Colors.RESET}  {n}{mark}")
                pick = input_prompt("Number or name")
                sel = None
                if pick.isdigit() and 1 <= int(pick) <= len(names):
                    sel = names[int(pick) - 1]
                elif pick in names:
                    sel = pick
                if sel:
                    store.set_active(sel)
                    print_success(f"Active: {sel}")
        elif choice == '3':
            entries = []
            while True:
                kind = input_prompt("Kind (cidr/domain/host/url, blank=done)", "cidr")
                if not kind or kind not in ('cidr', 'domain', 'host', 'url'):
                    break
                value = input_prompt("Value")
                if not value:
                    break
                allowed = yes_no_prompt("Allow? (No = deny)", True)
                entries.append((kind, value, 1 if allowed else 0))
            if entries:
                existing = store.get_scope()
                store.set_scope(entries + [e for e in existing
                                          if (e[0], e[1]) not in [(x[0], x[1]) for x in entries]])
                print_success(f"Scope updated ({len(entries)} new entries)")
        elif choice == '4':
            sys.argv = ['vantic', 'engage', 'show']
            from vantic.cli import main as _m
            _m()
            return
        elif choice == '5':
            store.set_active(None)
            print_success("Standalone mode")
        elif choice:
            print_error(f"Unknown: {choice}")
        input_prompt("Press Enter to continue")


def print_tools():
    """Full listing: every tool grouped by category."""
    cats = registry.categories()
    total = sum(len(mods) for _, _, mods in cats)
    print_header("AVAILABLE TOOLS", f"v{__version__} - {total} modules")
    for cat_name, color, mods in cats:
        if not mods:
            continue
        print()
        print(f"  {Colors.BOLD}{color}{cat_name}{Colors.RESET}")
        for mod in mods:
            meta = mod.META
            badge = RISK_BADGE.get(meta.get('risk', 'safe'), RISK_BADGE['safe'])()
            print(f"    {Colors.BOLD}{color}{meta['name']:<14}{Colors.RESET} "
                  f"{Colors.BOLD}{meta['title']:<24}{Colors.RESET} {meta['description']}")
        print()
    print(f"  {Colors.DIM}Run 'vantic' with no arguments for the interactive menu.{Colors.RESET}")
    print(f"  {Colors.DIM}Run 'vantic <tool> -h' for per-tool options.{Colors.RESET}")
    registry.warn_failures()
    print()


def interactive(parser):
    """Two-level menu: categories first, then tools."""
    while True:
        auto_size_terminal()
        clear_screen()
        print_banner()
        cats = registry.categories()
        total = sum(len(mods) for _, _, mods in cats)

        active = store.active_engagement()
        if active:
            print(f"  {Colors.BRIGHT_GREEN}[engagement]{Colors.RESET} "
                  f"{Colors.BOLD}{active}{Colors.RESET} "
                  f"{Colors.DIM}(guard + store + audit on){Colors.RESET}")

        print(f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}CATEGORIES{Colors.RESET} "
              f"{Colors.DIM}· {total} tools{Colors.RESET}")
        print()
        n = 1
        numbered = {}
        for cat_name, color, mods in cats:
            if not mods:
                continue
            print(f"  {Colors.BOLD}{Colors.DIM}{n:>2}{Colors.RESET}  "
                  f"{Colors.BOLD}{color}{cat_name:<24}{Colors.RESET}"
                  f"{Colors.DIM}{len(mods)} tools{Colors.RESET}")
            numbered[n] = (cat_name, color, mods)
            n += 1
        print()
        print(f"  {Colors.DIM}tools  full list   |   engage  engagements & scope   |   "
              f"gui  graphical   |   help  usage   |   q  quit{Colors.RESET}")
        print()
        try:
            choice = input(f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}vantic>{Colors.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            print_success("Goodbye.")
            return

        if not choice:
            continue
        low = choice.lower()
        if low in ('q', 'quit', 'exit'):
            print_success("Goodbye.")
            return
        if low == 'clear':
            continue
        if low == 'gui':
            from vantic.gui import run_gui
            run_gui()
            continue
        if low == 'tools':
            print_tools()
            input_prompt("Press Enter to continue")
            continue
        if low == 'help':
            parser.print_help()
            input_prompt("Press Enter to continue")
            continue
        if low == 'engage':
            _engage_menu()
            continue

        # Tool name typed directly?
        mod = registry.get(low)
        if mod:
            _run_flow(parser, mod.META)
            continue

        if low.isdigit():
            idx = int(low)
            if idx in numbered:
                cat_name, color, mods = numbered[idx]
                _category_menu(parser, cat_name, color, mods)
                continue

        print_error(f"Unknown selection: {choice}")
        input_prompt("Press Enter to continue")


def main():
    parser = build_parser()
    registry.load()

    argv = sys.argv[1:]
    if not argv:
        interactive(parser)
        return

    args = parser.parse_args(argv)

    from vantic.utils import set_json_mode, set_quiet_mode, Colors
    color_mode = getattr(args, 'color', 'auto')
    if color_mode == 'never' or (color_mode == 'auto' and not sys.stdout.isatty()):
        Colors.disable()
    if getattr(args, 'json', False):
        set_json_mode(True)
    if getattr(args, 'quiet', False):
        set_quiet_mode(True)
    if getattr(args, 'engagement', None):
        if args.engagement not in store.list_engagements():
            print_error(f"No such engagement: {args.engagement}")
            sys.exit(1)
        store.set_override(args.engagement)

    if args.command is None:
        interactive(parser)
        return

    if not args.no_banner and not getattr(args, 'json', False):
        print_banner()
    if not getattr(args, 'json', False):
        print_info(f"Started at {timestamp()}")
        print()

    exit_code = 0
    try:
        if args.command == 'gui':
            from vantic.gui import run_gui
            run_gui()
        elif args.command == 'engage':
            exit_code = run_engage(args) or 0
        else:
            exit_code = dispatch(args, parser)
    except KeyboardInterrupt:
        print()
        print_warning("Interrupted by user")
        exit_code = 4
    except guard.ScopeRefusal as e:
        print_error(f"SCOPE REFUSAL: {e}")
        exit_code = guard.ScopeRefusal.EXIT_CODE
    except Exception as e:
        print_error(f"Error: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        exit_code = 1

    if exit_code == 4:
        print_warning("Run may be partial - check results")

    if not getattr(args, 'json', False):
        print()
        print_success(f"Completed at {timestamp()}")

    store.close_all()
    if exit_code:
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
