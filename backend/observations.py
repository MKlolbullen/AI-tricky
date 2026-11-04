"""Offline, versioned parsers. Parsing output never verifies a vulnerability."""
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

PARSER_VERSION = '2'
SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}
CLI_PARSERS = {'httpx', 'dnsx', 'naabu', 'nmap', 'katana', 'nuclei', 'nuclei-takeover'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def canonical_asset(value):
    """Normalize host/default-port spelling while preserving URL path/query semantics."""
    if not isinstance(value, str) or not value or len(value) > 4096 or any(c.isspace() for c in value):
        return None
    try:
        if '://' in value:
            u = urlsplit(value)
            if u.scheme.lower() not in ('http', 'https', 'tcp') or not u.hostname or u.username or u.password:
                return None
            host = canonical_asset(u.hostname)
            if host is None:
                return None
            host = f'[{host}]' if ':' in host else host
            port = u.port
            if port is not None and not 1 <= port <= 65535:
                return None
            authority = host + (f':{port}' if port is not None and (u.scheme.lower(), port) not in {('http', 80), ('https', 443)} else '')
            return urlunsplit((u.scheme.lower(), authority, u.path or '/', u.query, ''))
        try:
            return ipaddress.ip_address(value.strip('[]')).compressed
        except ValueError:
            host = value.rstrip('.').encode('idna').decode('ascii').lower()
            return host if len(host) <= 253 and all(re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', p) for p in host.split('.')) else None
    except (ValueError, UnicodeError):
        return None


def observation(kind, asset, source, data, key='', finding=None):
    asset = canonical_asset(asset)
    if asset is None:
        return None
    identity = [source, kind, asset, key]
    return {'kind': kind, 'asset': asset, 'source': source, 'key': key,
            'fingerprint': digest(identity), 'value_hash': digest(data), 'data': data,
            'parser_version': PARSER_VERSION, 'finding': finding}


def port_observation(host, port, source, state='open', **extra):
    try:
        if type(port) not in (int, str) or isinstance(port, str) and not port.isdecimal():
            return None
        port = int(port)
        if not 1 <= port <= 65535:
            return None
    except (ValueError, TypeError):
        return None
    return observation('service', host, source, {'port': port, 'transport': 'tcp', 'state': state, **extra}, str(port))


def http_observation(row, source):
    status = row.get('status', row.get('status_code'))
    if type(status) is not int or not 100 <= status <= 599:
        return None
    headers = row.get('headers') if isinstance(row.get('headers'), dict) else {}
    # Volatile timestamps and credentials are not part of comparison values.
    headers = {str(k).lower(): str(v)[:2000] for k, v in headers.items()
               if str(k).lower() in {'server', 'content-type', 'x-powered-by', 'content-security-policy',
                                    'strict-transport-security', 'x-frame-options', 'x-content-type-options'}}
    data = {'status': status, 'headers': headers}
    for k in ('title', 'webserver', 'tech', 'host', 'connected_ip', 'content_type'):
        if k in row:
            data[k] = row[k]
    if 'body' in row:
        data['body_sha256'] = hashlib.sha256(str(row['body']).encode()).hexdigest()
        data['body_truncated'] = bool(row.get('truncated'))
    return observation('http', row.get('url'), source, data)


def parse_cli(tool, stdout):
    """Parse the default text/JSONL formats of six common tool families."""
    records, skipped = [], 0
    current_host = None
    for line in str(stdout).splitlines():
        line = line.strip()
        if not line:
            continue
        result = None
        try:
            def reject_constant(value):
                raise ValueError('Non-finite JSON number')
            row = json.loads(line, parse_constant=reject_constant)
            row = row if isinstance(row, dict) else {}
        except ValueError:
            row = {}
        if tool == 'httpx':
            if row:
                result = http_observation(row, tool)
            if result is None:
                url = row.get('url') or line.split()[0]
                if isinstance(url, str) and url.startswith(('http://', 'https://')):
                    result = observation('endpoint', url, tool, {'discovered': True})
        elif tool == 'katana':
            request = row.get('request') if isinstance(row.get('request'), dict) else {}
            url = request.get('endpoint') or row.get('url') or line
            if isinstance(url, str) and url.startswith(('http://', 'https://')):
                result = observation('endpoint', url, tool, {'discovered': True})
        elif tool == 'dnsx':
            if row:
                host = row.get('host') or row.get('input')
                answers = {k: sorted(str(v) for v in row[k]) for k in ('a', 'aaaa', 'cname', 'mx', 'ns') if isinstance(row.get(k), list)}
            else:
                match = re.fullmatch(r'(\S+)\s+(?:\[([A-Z][A-Z0-9]*)\]\s+)?\[([^\]]+)\]', line)
                host = match[1] if match else line
                answers = {'answers': sorted(re.split(r'[,\s]+', match[3]))} if match else {}
                if match and match[2]:
                    answers['record_type'] = match[2]
            result = observation('dns', host, tool, answers)
        elif tool == 'naabu':
            host, port = row.get('host') or row.get('ip'), row.get('port')
            if not row and ':' in line:
                host, port = line.rsplit(':', 1)
            result = port_observation(host, port, tool)
        elif tool == 'nmap':
            match = re.fullmatch(r'Nmap scan report for (?:.* \()?([^ ()]+)\)?', line)
            if match:
                current_host = match[1]
            port = re.match(r'^(\d+)/tcp\s+(open|closed|filtered|open\|filtered)\s+(.*)$', line)
            if port and current_host:
                result = port_observation(current_host, port[1], tool, port[2], service=port[3][:500])
        elif tool in ('nuclei', 'nuclei-takeover'):
            info = row.get('info') if isinstance(row.get('info'), dict) else {}
            rule = row.get('template-id')
            asset = row.get('matched-at') or row.get('host')
            if isinstance(rule, str) and rule and isinstance(info.get('name'), str) and info['name'].strip():
                severity = info.get('severity', 'info')
                severity = severity if isinstance(severity, str) and severity in SEVERITIES else 'info'
                key = encoded([rule, row.get('matcher-name', ''), row.get('type', ''), row.get('method', '')])
                data = {'rule_id': rule, 'title': info['name'][:200], 'severity': severity,
                        'matcher': str(row.get('matcher-name', ''))[:500], 'type': str(row.get('type', ''))[:100],
                        'extracted': row.get('extracted-results', [])}
                finding = {'rule_id': key, 'title': data['title'], 'severity': severity,
                           'rationale': str(info.get('description') or 'Scanner match; review the captured evidence.')[:4000],
                           'evidence_status': 'CANDIDATE', 'confidence': 'unknown'}
                result = observation('detection', asset, 'nuclei', data, key, finding)
        if result:
            records.append(result)
        else:
            skipped += 1
    return records, {'supported': tool in CLI_PARSERS, 'parsed_records': len(records), 'unparsed_lines': skipped,
                     'parser_version': PARSER_VERSION, 'tool': tool}


def parse_artifact(name, content):
    """Only known capture formats are indexed; raw evidence always remains available."""
    if name.startswith('http-') and isinstance(content, dict):
        record = http_observation(content, 'native-http')
        return ([record] if record else []), {'supported': True, 'parser_version': PARSER_VERSION, 'partial': bool(content.get('truncated'))}
    if name == 'tcp-inventory.json' and isinstance(content, list):
        records = [port_observation(r.get('host'), r.get('port'), 'native-tcp', r.get('state'))
                   for r in content if isinstance(r, dict) and r.get('state') in ('open', 'closed_or_filtered')]
        return [r for r in records if r], {'supported': True, 'parser_version': PARSER_VERSION,
                                         'partial': any(isinstance(r, dict) and r.get('state') in ('blocked', 'budget_exhausted', 'error') for r in content)}
    if name.startswith('cli-') and isinstance(content, dict) and isinstance(content.get('tool_id'), str):
        records, report = parse_cli(content['tool_id'], content.get('stdout', ''))
        report['partial'] = content.get('exit_code') != 0 or bool(content.get('error'))
        return records, report
    return [], {'supported': False, 'parser_version': PARSER_VERSION}
