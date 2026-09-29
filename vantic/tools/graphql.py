"""
GraphQL Tool
Endpoint discovery + introspection + batching + suggestion leakage

Detects: open introspection (schema disclosure), JSON-array batching
(brute-force enabler), "Did you mean" suggestion leakage, missing
depth limits.
"""

import json
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import net, findings

META = {
    "name": "graphql",
    "title": "GraphQL Audit",
    "category": "WEB ANALYSIS",
    "description": "Introspection, batching, suggestions",
    "risk": "safe",
    "examples": [
        "vantic graphql https://api.example.com",
        "vantic graphql https://api.example.com/graphql --introspect",
    ],
    "flow": [
        ("arg", "url", "Base URL or GraphQL endpoint", None),
        ("flag", "--introspect", "Run introspection query?"),
    ],
    "guard": {"url": "url"},
}

ENDPOINT_PATHS = ['/graphql', '/api/graphql', '/graphiql', '/graphql/v1',
                 '/api', '/query', '/playground', '/api/graph']


def gql_post(url, query, timeout=10):
    """POST a GraphQL query. Returns (status, data_or_text)."""
    try:
        resp = net.request(url, "POST", timeout=timeout,
                           data={"query": query},
                           follow_redirects=False, max_retries=0)
        try:
            return resp.status, json.loads(resp.body.decode("utf-8", errors="replace"))
        except ValueError:
            return resp.status, resp.text(500)
    except Exception:
        return None, None


INTROSPECTION_QUERY = """
{ __schema { queryType { name } types { name kind description } } }
"""

DEPTH_QUERY = """
query { __schema { types { fields { type { fields { type { fields { type { fields {
  type { fields { type { fields { name } } } } } } } } } } } }
"""


def add_arguments(parser):
    parser.add_argument('url', help='Base URL or GraphQL endpoint')
    parser.add_argument('--introspect', action='store_true', help='Introspection query')
    parser.add_argument('--batch', action='store_true', help='Test array batching')
    parser.add_argument('--suggestions', action='store_true', help='Typo suggestion check')


def run(args):
    url = args.url
    if '://' not in url:
        url = 'https://' + url
    base = url.rstrip('/')

    print_header("GRAPHQL AUDIT", url)
    print()

    # Endpoint discovery
    print_subheader("ENDPOINT DISCOVERY")
    endpoints = []
    candidates = [base] if base.endswith(tuple(ENDPOINT_PATHS)) else \
        [base + p for p in ENDPOINT_PATHS]
    for cand in candidates:
        status, data = gql_post(cand, "{ __typename }")
        if status is not None and isinstance(data, dict):
            ok = 'data' in data or 'errors' in data
            if ok:
                endpoints.append(cand)
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {cand} "
                      f"{Colors.DIM}(responds as GraphQL){Colors.RESET}")
    if not endpoints:
        print_warning("No GraphQL endpoint found at common paths")
        return
    endpoint = endpoints[0]
    print()

    # Introspection
    if getattr(args, 'introspect', True):
        print_subheader("INTROSPECTION")
        status, data = gql_post(endpoint, INTROSPECTION_QUERY)
        if isinstance(data, dict) and data.get('data', {}).get('__schema'):
            types = data['data']['__schema'].get('types', [])
            print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} Introspection OPEN "
                  f"({len(types)} types disclosed)")
            findings.make(family="graphql-introspection",
                          title="GraphQL introspection enabled",
                          severity="medium", target=endpoint,
                          evidence=f"{len(types)} types enumerated",
                          remediation="Disable introspection in production "
                                     "(graphql-disable-introspection etc.)",
                          tool="graphql")
            for t in types[:15]:
                name = t.get('name', '?')
                if not name.startswith('__'):
                    print(f"      {Colors.DIM}{name} ({t.get('kind', '?')}){Colors.RESET}")
        else:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} Introspection closed")
        print()

    # Batching
    if getattr(args, 'batch', False):
        print_subheader("BATCHING")
        status, data = gql_post(endpoint, json.dumps(
            [{"query": "{ __typename }"}, {"query": "{ __typename }"}]))
        # JSON array body needs different content handling - send raw
        try:
            resp = net.request(endpoint, "POST", timeout=10,
                               data=json.dumps([{"query": "{ __typename }"},
                                               {"query": "{ __typename }"}]),
                               follow_redirects=False, max_retries=0)
            if isinstance(resp.body, bytes):
                body = resp.body.decode('utf-8', errors='replace')
                if body.startswith('['):
                    print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} Array batching "
                          f"accepted (brute-force enabler)")
                    findings.make(family="graphql-batching",
                                  title="GraphQL array batching accepted",
                                  severity="low", target=endpoint,
                                  evidence="JSON array of queries answered",
                                  remediation="Limit batch size / depth",
                                  tool="graphql")
                else:
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} Array body rejected")
        except Exception:
            pass
        print()

    # Suggestions
    if getattr(args, 'suggestions', False):
        print_subheader("SUGGESTION LEAKAGE")
        status, data = gql_post(endpoint, "{ userr }")
        text = json.dumps(data) if isinstance(data, dict) else str(data)
        if 'Did you mean' in text or 'did you mean' in text:
            print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} Field suggestions leak "
                  f"(schema discovery without introspection)")
            findings.make(family="graphql-suggestions",
                          title="GraphQL field suggestions enabled",
                          severity="info", target=endpoint,
                          evidence="Did-you-mean present on invalid field",
                          remediation="Disable suggestions in production",
                          tool="graphql")
        else:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} No suggestion leakage")
        print()

    # Depth limit probe
    print_subheader("DEPTH LIMIT")
    status, data = gql_post(endpoint, DEPTH_QUERY)
    text = json.dumps(data)[:200] if data else ''
    if status == 200 and ('data' in (data or {}) or 'errors' in (data or {})):
        print_info(f"Deep query accepted (status {status}) - check for cost limits")
    else:
        print_info(f"Deep query rejected/errored (status {status})")
    print()

    print_summary("GRAPHQL", [
        ("Endpoint", endpoint.split('/')[-1] or '/'),
        ("Introspection", "open" if getattr(args, 'introspect', True) else "?"),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "graphql", "target": endpoint,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"endpoints": endpoints}})

    net.close_connections()
    print_success("GraphQL audit completed")
