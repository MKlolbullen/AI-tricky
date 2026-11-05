"""Declarative passive-source adapters.

Each adapter is a pure request builder (`build`) and response parser (`parse`) —
there is NO network I/O here. The ingestor performs the gated, allowlisted HTTP;
these functions are pure and unit-tested against representative response
fixtures. Everything a provider returns is a third-party CLAIM, tagged with its
source; nothing here produces a finding.

A parsed record is one of:
  {'t':'e','kind':<entity_kind>,'canonical':<str>,'data':{...}}         # entity
  {'t':'x','rel':<rel>,'src':[<kind>,<canonical>],'dst':[<kind>,<canonical>]}  # edge
"""
import base64

from .observations import canonical_asset


def _host(value):
    return canonical_asset(value) if isinstance(value, str) and value and '://' not in value else None


def _tech(name):
    return name.strip()[:120] if isinstance(name, str) and name.strip() else None


def E(kind, canonical, **data):
    return {'t': 'e', 'kind': kind, 'canonical': canonical, 'data': data}


def X(rel, src, dst):
    return {'t': 'x', 'rel': rel, 'src': list(src), 'dst': list(dst)}


# -- Shodan -------------------------------------------------------------------
def _shodan_build(qt, q, creds):
    key = creds['SHODAN_API_KEY']
    path = f'shodan/host/{q}' if qt == 'ip' else f'dns/domain/{q}'
    return {'url': f'https://api.shodan.io/{path}?key={key}', 'headers': {}}


def _shodan_parse(qt, q, resp):
    out = []
    if not isinstance(resp, dict):
        return out
    if qt == 'ip':
        ip = _host(resp.get('ip_str') or q)
        if not ip:
            return out
        out.append(E('ip', ip, ip=ip))
        asn = resp.get('asn')
        if isinstance(asn, str) and asn.strip():
            out.append(E('netblock', asn.strip(), asn=asn.strip(), org=resp.get('org')))
            out.append(X('member_of', ['ip', ip], ['netblock', asn.strip()]))
        for svc in resp.get('data', []) if isinstance(resp.get('data'), list) else []:
            if not isinstance(svc, dict) or not isinstance(svc.get('port'), int):
                continue
            sid = f"{ip}:{svc['port']}/tcp"
            out.append(E('service', sid, host=ip, port=svc['port'], transport='tcp', state='open'))
            out.append(X('exposes', ['ip', ip], ['service', sid]))
            tech = _tech(svc.get('product'))
            if tech:
                out.append(E('technology', tech.lower(), name=tech))
                out.append(X('runs', ['ip', ip], ['technology', tech.lower()]))
            vulns = svc.get('vulns')
            cves = vulns.keys() if isinstance(vulns, dict) else vulns if isinstance(vulns, list) else []
            for cve in cves:
                if isinstance(cve, str) and cve.upper().startswith('CVE-'):
                    out.append(E('vulnerability', cve.upper(), cve=cve.upper(), source='shodan'))
                    out.append(X('reported_vulnerable', ['service', sid], ['vulnerability', cve.upper()]))
    else:
        dom = _host(resp.get('domain') or q)
        if not dom:
            return out
        for sub in resp.get('subdomains', []) if isinstance(resp.get('subdomains'), list) else []:
            fqdn = _host(f'{sub}.{dom}') if isinstance(sub, str) and sub else None
            if fqdn:
                out.append(E('host', fqdn, host=fqdn))
                out.append(X('subdomain_of', ['host', fqdn], ['host', dom]))
        for rec in resp.get('data', []) if isinstance(resp.get('data'), list) else []:
            if isinstance(rec, dict) and rec.get('type') == 'A':
                sub = rec.get('subdomain')
                fqdn = _host(f'{sub}.{dom}') if sub else dom
                ip = _host(rec.get('value'))
                if fqdn and ip:
                    out.append(E('ip', ip, ip=ip))
                    out.append(X('resolves_to', ['host', fqdn], ['ip', ip]))
    return out


# -- Censys -------------------------------------------------------------------
def _censys_build(qt, q, creds):
    token = base64.b64encode(f"{creds['CENSYS_API_ID']}:{creds['CENSYS_API_SECRET']}".encode()).decode()
    return {'url': f'https://search.censys.io/api/v2/hosts/{q}', 'headers': {'Authorization': f'Basic {token}'}}


def _censys_parse(qt, q, resp):
    out = []
    result = resp.get('result') if isinstance(resp, dict) else None
    if not isinstance(result, dict):
        return out
    ip = _host(result.get('ip') or q)
    if not ip:
        return out
    out.append(E('ip', ip, ip=ip))
    asys = result.get('autonomous_system')
    if isinstance(asys, dict) and asys.get('asn'):
        asn = f"AS{asys['asn']}"
        out.append(E('netblock', asn, asn=asn, org=asys.get('name')))
        out.append(X('member_of', ['ip', ip], ['netblock', asn]))
    for svc in result.get('services', []) if isinstance(result.get('services'), list) else []:
        if not isinstance(svc, dict) or not isinstance(svc.get('port'), int):
            continue
        sid = f"{ip}:{svc['port']}/tcp"
        out.append(E('service', sid, host=ip, port=svc['port'], transport='tcp', state='open'))
        out.append(X('exposes', ['ip', ip], ['service', sid]))
        tech = _tech(svc.get('service_name'))
        if tech:
            out.append(E('technology', tech.lower(), name=tech))
            out.append(X('runs', ['ip', ip], ['technology', tech.lower()]))
        tls = svc.get('tls') if isinstance(svc.get('tls'), dict) else {}
        leaf = (((tls.get('certificates') or {}).get('leaf_data')) or {}) if isinstance(tls, dict) else {}
        fp = leaf.get('fingerprint') if isinstance(leaf, dict) else None
        if isinstance(fp, str) and fp.strip():
            out.append(E('certificate', fp.strip(), fingerprint=fp.strip()))
            out.append(X('covers', ['certificate', fp.strip()], ['ip', ip]))
    return out


# -- VirusTotal ---------------------------------------------------------------
def _vt_build(qt, q, creds):
    return {'url': f'https://www.virustotal.com/api/v3/domains/{q}/subdomains?limit=40',
            'headers': {'x-apikey': creds['VIRUSTOTAL_API_KEY']}}


def _vt_parse(qt, q, resp):
    out = []
    dom = _host(q)
    for item in (resp.get('data', []) if isinstance(resp, dict) else []):
        sub = _host(item.get('id')) if isinstance(item, dict) else None
        if sub:
            out.append(E('host', sub, host=sub))
            if dom and sub != dom and sub.endswith('.' + dom):
                out.append(X('subdomain_of', ['host', sub], ['host', dom]))
    return out


# -- Netlas -------------------------------------------------------------------
def _netlas_build(qt, q, creds):
    return {'url': f'https://app.netlas.io/api/domains/?q=domain:*.{q}&fields=domain&source_type=include',
            'headers': {'X-API-Key': creds['NETLAS_API_KEY']}}


def _netlas_parse(qt, q, resp):
    out = []
    dom = _host(q)
    items = resp.get('items') if isinstance(resp, dict) else None
    for it in items if isinstance(items, list) else []:
        data = it.get('data') if isinstance(it, dict) else None
        name = data.get('domain') if isinstance(data, dict) else None
        sub = _host(name)
        if sub:
            out.append(E('host', sub, host=sub))
            if dom and sub != dom and sub.endswith('.' + dom):
                out.append(X('subdomain_of', ['host', sub], ['host', dom]))
    return out


ADAPTERS = {
    'shodan': {'name': 'Shodan', 'vars': ['SHODAN_API_KEY'], 'hosts': {'api.shodan.io'},
               'supports': ('ip', 'domain'), 'build': _shodan_build, 'parse': _shodan_parse},
    'censys': {'name': 'Censys', 'vars': ['CENSYS_API_ID', 'CENSYS_API_SECRET'], 'hosts': {'search.censys.io'},
               'supports': ('ip',), 'build': _censys_build, 'parse': _censys_parse},
    'virustotal': {'name': 'VirusTotal', 'vars': ['VIRUSTOTAL_API_KEY'], 'hosts': {'www.virustotal.com'},
                   'supports': ('domain',), 'build': _vt_build, 'parse': _vt_parse},
    'netlas': {'name': 'Netlas', 'vars': ['NETLAS_API_KEY'], 'hosts': {'app.netlas.io'},
               'supports': ('domain',), 'build': _netlas_build, 'parse': _netlas_parse},
}

ALLOWED_HOSTS = frozenset(host for a in ADAPTERS.values() for host in a['hosts'])


def query_types(provider, target_kind):
    """Which query shapes an adapter supports for a domain- or ip-kind target."""
    want = 'ip' if target_kind == 'ip' else 'domain'
    return [want] if want in ADAPTERS[provider]['supports'] else []


def parse_response(provider, query_type, query, response):
    adapter = ADAPTERS.get(provider)
    if adapter is None or query_type not in adapter['supports']:
        return []
    try:
        return adapter['parse'](query_type, query, response)
    except Exception:  # noqa: BLE001 - a malformed provider response yields no records
        return []
