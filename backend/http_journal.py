"""Always-on, bounded HTTP exchange history for application-owned target traffic."""
import base64
from datetime import datetime
import json
import uuid
import hashlib
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, parse_qsl

from .store import now
from .scope import ScopeError, authorize, parse_target

MAX_HEADERS=65536
MAX_BODY=131072


def message(start_line,headers,body=b'',**fields):
    kept=[];size=len(start_line.encode('latin1',errors='replace'))+4;truncated=False
    for name,value in headers:
        encoded=f'{name}: {value}\r\n'.encode('latin1',errors='replace')
        if len(kept)>=100 or size+len(encoded)>MAX_HEADERS:truncated=True;break
        kept.append([name,value]);size+=len(encoded)
    raw=(start_line+'\r\n'+''.join(f'{k}: {v}\r\n' for k,v in kept)+'\r\n').encode('latin1',errors='replace')
    return {**fields,'headers':kept,'raw_headers_base64':base64.b64encode(raw).decode(),
            'body_base64':base64.b64encode(body[:MAX_BODY]).decode(),'body_bytes':min(len(body),MAX_BODY),
            'body_truncated':len(body)>MAX_BODY,'headers_truncated':truncated,
            'representation':'normalized_http1_headers_and_captured_entity_body'}


def request_message(url,headers=None,*,request_target=None):
    p=urlsplit(url);target=request_target or (p.path or '/')+('?' + p.query if p.query else '')
    host=p.netloc
    pairs=list((headers or {'Host':host,'User-Agent':'AI-tricky/0.8.0','Accept-Encoding':'identity'}).items())
    return message('GET '+target+' HTTP/1.1',pairs,method='GET',url=url,http_version='HTTP/1.1',request_target=target)


class HTTPJournal:
    def __init__(self,store):
        self.store=store
        with store.connect() as c:
            c.executescript('''CREATE TABLE IF NOT EXISTS http_exchanges(
                id TEXT PRIMARY KEY,run_id TEXT NOT NULL,node_id TEXT,number INTEGER NOT NULL,
                started TEXT NOT NULL,finished TEXT,state TEXT NOT NULL,url TEXT NOT NULL,
                route TEXT NOT NULL,request TEXT NOT NULL,response TEXT,error TEXT,
                artifact_id TEXT,cancel_requested INTEGER NOT NULL DEFAULT 0,source TEXT NOT NULL DEFAULT 'native');
                CREATE INDEX IF NOT EXISTS http_exchanges_run ON http_exchanges(run_id,started);
            ''')
            c.execute("UPDATE http_exchanges SET state='interrupted',finished=? WHERE finished IS NULL",(now(),))

    def begin(self,rid,node_id,number,url,route,request):
        identifier=str(uuid.uuid4())
        with self.store.connect() as c:
            c.execute('INSERT INTO http_exchanges(id,run_id,node_id,number,started,state,url,route,request) VALUES(?,?,?,?,?,?,?,?,?)',
                (identifier,rid,node_id,number,now(),'pending',url,json.dumps(route),json.dumps(request)))
        return identifier

    def prepared(self,identifier,request):
        with self.store.connect() as c:
            c.execute("UPDATE http_exchanges SET request=?,state='dispatching' WHERE id=? AND finished IS NULL",(json.dumps(request),identifier))

    def finish(self,identifier,*,response=None,artifact_id=None,error=None,route=None):
        with self.store.connect() as c:
            c.execute('UPDATE http_exchanges SET response=?,artifact_id=?,error=?,finished=?,state=?,route=COALESCE(?,route) WHERE id=? AND finished IS NULL',
                (json.dumps(response) if response is not None else None,artifact_id,error,now(),'failed' if error else 'completed',json.dumps(route) if route else None,identifier))

    def cancelled(self,identifier):
        with self.store.connect() as c:c.execute('UPDATE http_exchanges SET cancel_requested=1 WHERE id=?',(identifier,))

    def get(self,identifier):
        with self.store.connect() as c:row=c.execute('SELECT * FROM http_exchanges WHERE id=?',(identifier,)).fetchone()
        if row is None:raise KeyError(identifier)
        return {**dict(row),**{k:json.loads(row[k]) if row[k] is not None else None for k in ('request','response','route')}}

    def import_burp_xml(self,rid,xml):
        """Import explicit Burp saved-items exports; never dispatch or verify them."""
        if len(xml.encode())>10_000_000 or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():
            raise ScopeError('Burp XML must be under 10 MB and cannot contain document types or entities.')
        try:root=ET.fromstring(xml)
        except ET.ParseError:raise ScopeError('Invalid Burp saved-items XML.') from None
        if root.tag!='items':raise ScopeError('Expected a Burp saved-items <items> document.')
        items=list(root)
        if not items or len(items)>100 or any(e.tag!='item' for e in items):
            raise ScopeError('Import 1–100 saved HTTP items at a time.')
        scopes=[parse_target(t) for t in self.store.run(rid)['config']['targets']]
        fingerprint=hashlib.sha256(xml.encode()).hexdigest();records=[]
        def decode(element):
            raw=element.text or ''
            try:return base64.b64decode(''.join(raw.split()),validate=True) if element.get('base64')=='true' else raw.encode('utf-8')
            except ValueError:raise ScopeError('Invalid base64 in Burp HTTP item.') from None
        def parse(raw,*,url=None):
            head,separator,body=raw.partition(b'\r\n\r\n')
            if not separator or len(head)>MAX_HEADERS:raise ScopeError('HTTP item needs a bounded CRLF header block.')
            lines=head.decode('latin1').split('\r\n');parts=lines[0].split(' ',2);headers=[]
            for line in lines[1:]:
                if ':' not in line:raise ScopeError('Unsupported HTTP header line in Burp item.')
                k,v=line.split(':',1);headers.append([k,v.strip()])
            if len(headers)>100:raise ScopeError('HTTP item exceeds 100 headers.')
            if url:
                if len(parts)!=3 or not parts[2].startswith('HTTP/'):raise ScopeError('Invalid saved request line.')
                result=message(lines[0],headers,body,method=parts[0],request_target=parts[1],http_version=parts[2],url=url)
            else:
                if len(parts)<2 or not parts[0].startswith('HTTP/') or not parts[1].isdigit() or not 100<=int(parts[1])<=599:
                    raise ScopeError('Invalid saved response line.')
                result=message(lines[0],headers,body,status=int(parts[1]),reason=parts[2] if len(parts)>2 else '',http_version=parts[0])
            result['raw_headers_base64']=base64.b64encode(head+b'\r\n\r\n').decode()
            result['representation']='exported_http_headers_and_captured_body'
            return result
        for index,item in enumerate(items):
            url=item.findtext('url') or '';authorize(url,scopes)
            request=item.find('request');response=item.find('response')
            if request is None:raise ScopeError('A saved request is required for each imported item.')
            records.append((str(uuid.uuid5(uuid.NAMESPACE_URL,rid+fingerprint+str(index))),url,
                parse(decode(request),url=url),parse(decode(response)) if response is not None and response.text else None,
                (item.findtext('time') or '')[:120]))
        # Parse and scope-check the entire batch before any persistence.
        with self.store.connect() as c:
            for identifier,url,request,response,captured_time in records:
                route={'mode':'external','origin_peer_observed':False,'import_sha256':fingerprint,
                       'exported_time':captured_time,'provenance':'operator-imported, not independently verified'}
                c.execute('INSERT OR IGNORE INTO http_exchanges(id,run_id,number,started,finished,state,url,route,request,response,error,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                    (identifier,rid,0,now(),now(),'imported',url,json.dumps(route),json.dumps(request),
                     json.dumps(response) if response else None,None if response else 'Imported item has no response','burp_xml'))
        return {'imported_ids':[r[0] for r in records],'items':len(records),'source':'burp_xml',
                'note':'Stored as externally supplied captures. No requests were sent and no findings were verified.'}

    def history(self,*,run_id=None,q='',limit=50,offset=0):
        where=[];args=[]
        if run_id is not None:where.append('run_id=?');args.append(run_id)
        if q:where.append('instr(lower(url),lower(?))>0');args.append(q)
        clause=' WHERE '+' AND '.join(where) if where else ''
        with self.store.connect() as c:
            c.execute('BEGIN')
            total=c.execute('SELECT COUNT(*) FROM http_exchanges'+clause,args).fetchone()[0]
            rows=c.execute("SELECT id,run_id,node_id,number,started,finished,state,url,route,error,artifact_id,cancel_requested,source,json_extract(response,'$.status') AS status,json_extract(request,'$.method') AS method FROM http_exchanges"+clause+' ORDER BY started DESC,id LIMIT ? OFFSET ?',
                [*args,limit,offset]).fetchall()
        return {'schema':'ai-tricky.http-history/v1','items':[{**dict(r),'route':json.loads(r['route'])} for r in rows],
                'total':total,'limit':limit,'offset':offset,'has_more':offset+len(rows)<total}

    def har(self,**filters):
        page=self.history(**filters);entries=[]
        for item in page['items']:
            row=self.get(item['id']);request=row['request'];response=row['response'] or {}
            elapsed=max(0,(datetime.fromisoformat(row['finished'])-datetime.fromisoformat(row['started'])).total_seconds()*1000) if row['finished'] else 0
            def headers(value):return [{'name':k,'value':v} for k,v in value.get('headers',[])]
            content_type=next((v for k,v in response.get('headers',[]) if k.lower()=='content-type'),'application/octet-stream')
            entries.append({'startedDateTime':row['started'],'time':elapsed,
                'request':{'method':request['method'],'url':row['url'],'httpVersion':request['http_version'],
                    'headers':headers(request),'queryString':[{'name':k,'value':v} for k,v in parse_qsl(urlsplit(row['url']).query,keep_blank_values=True)],
                    'cookies':[],'headersSize':-1,'bodySize':request['body_bytes']},
                'response':{'status':response.get('status',0),'statusText':response.get('reason',''),'httpVersion':response.get('http_version',''),
                    'headers':headers(response),'cookies':[],'redirectURL':next((v for k,v in response.get('headers',[]) if k.lower()=='location'),''),
                    'headersSize':-1,'bodySize':response.get('body_bytes',0),
                    'content':{'size':response.get('body_bytes',0),'mimeType':content_type,'text':response.get('body_base64',''),'encoding':'base64'}},
                'cache':{},'timings':{'send':0,'wait':elapsed,'receive':0},
                '_ai_tricky':{'exchange_id':row['id'],'run_id':row['run_id'],'node_id':row['node_id'],'state':row['state'],
                    'route':row['route'],'error':row['error'],'cancel_requested':bool(row['cancel_requested']),
                    'body_truncated':response.get('body_truncated',False),'headers_truncated':response.get('headers_truncated',False),
                    'timing_precision':'total_elapsed_only','source':row['source']}})
            if request.get('body_bytes'):
                raw=base64.b64decode(request['body_base64'])
                try:post={'text':raw.decode('utf-8')}
                except UnicodeError:post={'text':request['body_base64'],'_encoding':'base64'}
                entries[-1]['request']['postData']={'mimeType':next((v for k,v in request.get('headers',[]) if k.lower()=='content-type'),'application/octet-stream'),**post}
        return {'log':{'version':'1.2','creator':{'name':'AI-tricky','version':'0.8.0'},'entries':entries,
                       '_capture_page':{k:page[k] for k in ('total','limit','offset','has_more')}}}
