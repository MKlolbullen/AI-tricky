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


# -- FOFA ---------------------------------------------------------------------
def _fofa_build(qt, q, creds):
    field = 'ip' if qt == 'ip' else 'domain'
    qb64 = base64.b64encode(f'{field}="{q}"'.encode()).decode()
    return {'url': (f'https://fofa.info/api/v1/search/all?email={creds["FOFA_EMAIL"]}&key={creds["FOFA_KEY"]}'
                    f'&qbase64={qb64}&fields=ip,port,domain,server&size=100'), 'headers': {}}


def _fofa_parse(qt, q, resp):
    out = []
    if not isinstance(resp, dict) or resp.get('error'):
        return out
    dom = _host(q) if qt == 'domain' else None
    for row in resp.get('results', []) if isinstance(resp.get('results'), list) else []:
        if not isinstance(row, list) or len(row) < 4:
            continue
        ip, port, domain, server = _host(row[0]), row[1], _host(row[2]), row[3]
        if ip:
            out.append(E('ip', ip, ip=ip))
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = None
        if ip and port and 1 <= port <= 65535:
            sid = f'{ip}:{port}/tcp'
            out.append(E('service', sid, host=ip, port=port, transport='tcp', state='open'))
            out.append(X('exposes', ['ip', ip], ['service', sid]))
            tech = _tech(server)
            if tech:
                out.append(E('technology', tech.lower(), name=tech))
                out.append(X('runs', ['ip', ip], ['technology', tech.lower()]))
        if domain:
            out.append(E('host', domain, host=domain))
            if dom and domain != dom and domain.endswith('.' + dom):
                out.append(X('subdomain_of', ['host', domain], ['host', dom]))
            if ip:
                out.append(X('resolves_to', ['host', domain], ['ip', ip]))
    return out


# -- BeVigil ------------------------------------------------------------------
def _bevigil_build(qt, q, creds):
    return {'url': f'https://osint.bevigil.com/api/{q}/subdomains/', 'headers': {'X-Access-Token': creds['BEVIGIL_API_KEY']}}


def _bevigil_parse(qt, q, resp):
    out = []
    dom = _host(q)
    for sub in (resp.get('subdomains', []) if isinstance(resp, dict) else []):
        s = _host(sub)
        if s:
            out.append(E('host', s, host=s))
            if dom and s != dom and s.endswith('.' + dom):
                out.append(X('subdomain_of', ['host', s], ['host', dom]))
    return out


# -- Hunter.io ----------------------------------------------------------------
def _hunter_build(qt, q, creds):
    return {'url': f'https://api.hunter.io/v2/domain-search?domain={q}&api_key={creds["HUNTER_API_KEY"]}&limit=50', 'headers': {}}


def _hunter_parse(qt, q, resp):
    out = []
    dom = _host(q)
    data = resp.get('data') if isinstance(resp, dict) else None
    if not isinstance(data, dict):
        return out
    if dom:
        out.append(E('host', dom, host=dom))
    pattern = data.get('pattern')
    if isinstance(pattern, str) and pattern.strip():
        pid = f'pattern:{pattern.strip()[:120]}'
        out.append(E('contact', pid, pattern=pattern.strip()[:120], contact_kind='email_pattern'))
        if dom:
            out.append(X('has_contact', ['host', dom], ['contact', pid]))
    for em in (data.get('emails', []) if isinstance(data.get('emails'), list) else [])[:100]:
        value = em.get('value') if isinstance(em, dict) else None
        if isinstance(value, str) and '@' in value:
            cid = value.strip().lower()[:200]
            out.append(E('contact', cid, email=cid, contact_kind='email'))
            if dom:
                out.append(X('has_contact', ['host', dom], ['contact', cid]))
    return out


# -- ZoomEye ------------------------------------------------------------------
def _zoomeye_build(qt, q, creds):
    headers = {'API-KEY': creds['ZOOMEYE_API_KEY']}
    if qt == 'ip':
        return {'url': f'https://api.zoomeye.org/host/search?query=ip:%22{q}%22&page=1', 'headers': headers}
    return {'url': f'https://api.zoomeye.org/domain/search?q={q}&type=1&page=1', 'headers': headers}


def _zoomeye_parse(qt, q, resp):
    out = []
    if not isinstance(resp, dict):
        return out
    if qt == 'ip':
        for m in (resp.get('matches', []) if isinstance(resp.get('matches'), list) else []):
            mip = _host(m.get('ip')) if isinstance(m, dict) else None
            if not mip:
                continue
            out.append(E('ip', mip, ip=mip))
            pi = m.get('portinfo') if isinstance(m.get('portinfo'), dict) else {}
            try:
                port = int(pi.get('port'))
            except (TypeError, ValueError):
                port = None
            if port and 1 <= port <= 65535:
                sid = f'{mip}:{port}/tcp'
                out.append(E('service', sid, host=mip, port=port, transport='tcp', state='open'))
                out.append(X('exposes', ['ip', mip], ['service', sid]))
                tech = _tech(pi.get('app') or pi.get('service'))
                if tech:
                    out.append(E('technology', tech.lower(), name=tech))
                    out.append(X('runs', ['ip', mip], ['technology', tech.lower()]))
    else:
        dom = _host(q)
        for item in (resp.get('list', []) if isinstance(resp.get('list'), list) else []):
            sub = _host(item.get('name')) if isinstance(item, dict) else None
            if not sub:
                continue
            out.append(E('host', sub, host=sub))
            if dom and sub != dom and sub.endswith('.' + dom):
                out.append(X('subdomain_of', ['host', sub], ['host', dom]))
            for ipv in (item.get('ip', []) if isinstance(item.get('ip'), list) else []):
                cip = _host(ipv)
                if cip:
                    out.append(E('ip', cip, ip=cip))
                    out.append(X('resolves_to', ['host', sub], ['ip', cip]))
    return out


# -- Intelligence X (two-step phonebook search) -------------------------------
async def _intelx_collect(http, qt, q, creds):
    headers = {'x-key': creds['INTELX_API_KEY']}
    start = await http({'method': 'POST', 'url': 'https://2.intelx.io/phonebook/search', 'headers': headers,
                        'json': {'term': q, 'maxresults': 100, 'media': 0, 'target': 0, 'timeout': 5}})
    sid = start.get('id') if isinstance(start, dict) else None
    if not isinstance(sid, str) or not sid:
        return {'selectors': []}
    result = await http({'method': 'GET', 'headers': headers,
                         'url': f'https://2.intelx.io/phonebook/search/result?id={sid}&limit=100&offset=0'})
    return result if isinstance(result, dict) else {'selectors': []}


def _intelx_parse(qt, q, resp):
    out = []
    dom = _host(q)
    for sel in (resp.get('selectors', []) if isinstance(resp, dict) else []):
        value = sel.get('selectorvalue') if isinstance(sel, dict) else None
        if not isinstance(value, str) or not value.strip():
            continue
        v = value.strip()
        if '@' in v:
            cid = v.lower()[:200]
            out.append(E('contact', cid, email=cid, contact_kind='email'))
            if dom:
                out.append(X('has_contact', ['host', dom], ['contact', cid]))
        else:
            s = _host(v)
            if s:
                out.append(E('host', s, host=s))
                if dom and s != dom and s.endswith('.' + dom):
                    out.append(X('subdomain_of', ['host', s], ['host', dom]))
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
    'fofa': {'name': 'FOFA', 'vars': ['FOFA_EMAIL', 'FOFA_KEY'], 'hosts': {'fofa.info'},
             'supports': ('ip', 'domain'), 'build': _fofa_build, 'parse': _fofa_parse},
    'bevigil': {'name': 'BeVigil', 'vars': ['BEVIGIL_API_KEY'], 'hosts': {'osint.bevigil.com'},
                'supports': ('domain',), 'build': _bevigil_build, 'parse': _bevigil_parse},
    'hunter': {'name': 'Hunter.io', 'vars': ['HUNTER_API_KEY'], 'hosts': {'api.hunter.io'},
               'supports': ('domain',), 'build': _hunter_build, 'parse': _hunter_parse},
    'zoomeye': {'name': 'ZoomEye', 'vars': ['ZOOMEYE_API_KEY'], 'hosts': {'api.zoomeye.org'},
                'supports': ('ip', 'domain'), 'build': _zoomeye_build, 'parse': _zoomeye_parse},
    'intelx': {'name': 'Intelligence X', 'vars': ['INTELX_API_KEY'], 'hosts': {'2.intelx.io'},
               'supports': ('domain',), 'collect': _intelx_collect, 'parse': _intelx_parse},
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
