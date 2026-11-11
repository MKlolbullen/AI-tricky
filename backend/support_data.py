"""Versioned data inputs, never executable installers or target requests."""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import threading
import urllib.request
import uuid
import zipfile

from .catalog import ROOT, TOOLS, registered_path
from .cli_runner import digest, input_fingerprint, snapshot_folder
from .scope import ScopeError
from .store import now

MANIFEST = ROOT / 'support-data/manifest.json'
MAX_ARCHIVE = 50_000_000
MAX_EXPANDED = 100_000_000
MAX_FILES = 30000
PATH_TOOLS = {'ffuf','gobuster','dirsearch','feroxbuster','wfuzz','dirb','mkpath'}
DNS_WORD_TOOLS = {'shuffledns','puredns','mksub'}


def requirements(tool):
    tid = tool['id']; result = {}
    if tid in ('nuclei','nuclei-takeover'):
        result['templates'] = 'nuclei-takeovers' if tid.endswith('takeover') else 'nuclei-templates'
    elif tid == 'jaeles':
        result['templates'] = 'jaeles-signatures'
    if tid in ('massdns','shuffledns','puredns'):
        result['resolvers'] = 'resolvers'
    if tid=='puredns':
        result['resolvers_trusted'] = 'resolvers-trusted'
    if any('{wordlist_file}' in arg for arg in tool['command']):
        result['wordlist'] = 'wordlist-subdomains' if tid in DNS_WORD_TOOLS else 'wordlist-paths' if tid in PATH_TOOLS else None
    if any('{paths_file}' in arg for arg in tool['command']):
        result['paths_file'] = 'paths'
    return result


def download(url, destination):
    # URLs are exclusively from the committed manifest; never client input.
    request = urllib.request.Request(url, headers={'User-Agent':'AI-tricky-support-data/1'})
    total = 0
    with urllib.request.urlopen(request, timeout=30) as response, destination.open('wb') as out:
        while chunk := response.read(65536):
            total += len(chunk)
            if total > MAX_ARCHIVE:
                raise ScopeError('Support archive exceeds 50 MB.')
            out.write(chunk)


def extract_archive(archive, destination, prefix):
    """Reject links, duplicate paths, traversal and oversized expansions."""
    total = 0; paths = set(); count = 0
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            raw = info.filename
            parts = raw.rstrip('/').split('/')
            mode = info.external_attr >> 16
            if (not parts or parts[0] != prefix or any(p in ('','.', '..') for p in parts) or
                    '\\' in raw or ':' in raw or any(ord(c)<32 for c in raw) or raw.startswith('/') or
                    stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR)):
                raise ScopeError('Unsafe support archive entry.')
            relative = PurePosixPath(*parts[1:])
            if str(relative) == '.':
                continue
            if relative in paths:
                raise ScopeError('Duplicate support archive entry.')
            paths.add(relative)
            if info.is_dir():
                continue
            total += info.file_size; count += 1
            if total > MAX_EXPANDED or count > MAX_FILES or info.file_size > 20_000_000:
                raise ScopeError('Support archive expansion exceeds limits.')
            out = destination.joinpath(*relative.parts)
            out.parent.mkdir(parents=True,exist_ok=True)
            with z.open(info) as source, out.open('xb') as target:
                shutil.copyfileobj(source,target,65536)
            if out.stat().st_size != info.file_size:
                raise ScopeError('Incomplete support archive entry.')


class SupportData:
    def __init__(self, store, *, manifest=None, resources=None, downloader=download):
        self.store = store
        self.manifest = copy.deepcopy(manifest) if manifest is not None else json.loads(MANIFEST.read_text())
        self.resources = Path(resources or ROOT/'support-data/bundled').resolve()
        self.root = (store.root/'support-data').resolve()
        if (store.root/'support-data').is_symlink():
            raise ScopeError('Support data directory cannot be a symlink.')
        self.downloader = downloader
        self.lock = threading.Lock()

    def _root(self, entry):
        # Binding metadata is versioned too: a new role must not reuse an old
        # receipt that lacks it, or change IDs already selected by a workflow.
        revision = hashlib.sha256(json.dumps([entry['revision'],entry['sha256'],entry.get('roles',[])],sort_keys=True).encode()).hexdigest()
        return self.root/(entry['id']+'-'+revision[:16])

    def _register(self, identifier, name, kind, path, roles):
        fingerprint = input_fingerprint(path,kind) if kind=='folder' else digest(path)
        iid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(path)))
        with self.store.connect() as c:
            row = c.execute('SELECT * FROM inputs WHERE id=?',(iid,)).fetchone()
            if row and (row['path']!=str(path) or row['kind']!=kind or row['sha256']!=fingerprint):
                raise ScopeError('Installed support input changed; preserve it and install a new version.')
            c.execute('INSERT OR IGNORE INTO inputs VALUES(?,?,?,?,?,?)',(iid,name,kind,str(path),fingerprint,now()))
        return {'id':identifier,'name':name,'kind':kind,'path':str(path.relative_to(self.root)),
                'input_id':iid,'sha256':fingerprint,'roles':roles}

    def _receipt(self, entry):
        root = self._root(entry)
        if root.is_symlink():
            raise ScopeError('Support package cannot be a symlink.')
        path = root/'installed.json'
        if not path.exists():
            return None
        if path.is_symlink() or path.stat().st_size>100000:
            raise ScopeError('Invalid support package receipt.')
        receipt = json.loads(path.read_text())
        if receipt.get('id')!=entry['id'] or receipt.get('revision')!=entry['revision']:
            raise ScopeError('Support package receipt does not match its pinned version.')
        return receipt

    def _checked_inputs(self, entry, *, validate=False):
        receipt = self._receipt(entry)
        if receipt is None:
            return []
        result = []
        for row in receipt['inputs']:
            path = self.root/row['path']
            if path.resolve()!=path or not path.is_relative_to(self._root(entry)):
                raise ScopeError('Invalid support input path.')
            if not path.exists():
                continue
            try:
                registered = self.store.input(row['input_id'])
            except KeyError:
                continue
            if registered['path']!=str(path) or registered['sha256']!=row['sha256']:
                raise ScopeError('Support input registration changed.')
            if validate:
                registered_path(self.store,row['input_id'],row['kind'])
            result.append(row)
        return result

    def status(self):
        result = {'bundled':[],'remote':[],'requirements':[],
                  'built_in':['GF patterns are materialized in each GF job.', 'Licensed payload lists are already bundled with the catalog.'],
                  'catalog':{'tools':len(TOOLS),'migrated_workflows':57,'trickest_parity':False}}
        for category in ('bundled','remote'):
            for entry in self.manifest[category]:
                inputs = self._checked_inputs(entry)
                result[category].append({k:entry[k] for k in ('id','name','revision')} | {
                    'source':entry.get('source') or 'https://github.com/'+entry['repository'],
                    'installed':bool(inputs),'inputs':inputs})
        available = {role:row['input_id'] for group in result['bundled']+result['remote'] for row in group['inputs'] for role in row['roles']}
        for tool in TOOLS.values():
            req = requirements(tool)
            if req:
                result['requirements'].append({'tool_id':tool['id'],'bindings':[{'slot':slot,'role':role,'input_id':available.get(role)} for slot,role in req.items()]})
        return result

    def install(self, identifier='bundled'):
        with self.lock:
            entries = self.manifest['bundled'] if identifier=='bundled' else [e for e in self.manifest['remote'] if e['id']==identifier]
            if not entries:
                raise ScopeError('Unknown support package.')
            self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
            for entry in entries:
                if self._receipt(entry):
                    # Recover registration after an interruption between the
                    # atomic package publish and its database insertions.
                    for row in self._receipt(entry)['inputs']:
                        path=self.root/row['path']
                        if path.resolve()!=path or not path.is_relative_to(self._root(entry)):
                            raise ScopeError('Invalid support input path.')
                        fingerprint=input_fingerprint(path,row['kind']) if row['kind']=='folder' else digest(path)
                        if fingerprint!=row['sha256']:raise ScopeError('Installed support input changed.')
                        self._register(row['id'],row['name'],row['kind'],path,row['roles'])
                    self._checked_inputs(entry,validate=True)
                    continue
                self._install(entry,remote=identifier!='bundled')
            return self.status()

    def _install(self, entry, *, remote):
        destination = self._root(entry)
        with tempfile.TemporaryDirectory(prefix='.stage-',dir=self.root) as temp:
            stage = Path(temp)/'package'; stage.mkdir()
            views = []
            if not remote:
                source = self.resources/entry['path']
                if source.is_dir():snapshot_folder(source)
                actual = {p.relative_to(source).as_posix():digest(p) for p in source.rglob('*') if p.is_file()} if source.is_dir() else {'.':digest(source)}
                if actual != entry['sha256']:
                    raise ScopeError('Bundled support data checksum mismatch.')
                if source.is_dir():
                    snapshot_folder(source,stage/'input')
                else:
                    (stage/'input').mkdir(); shutil.copyfile(source,stage/'input'/source.name)
                    license_file=source.parent/'LICENSE'
                    if license_file.is_file():shutil.copyfile(license_file,stage/'LICENSE')
                relative = 'input' if entry['kind']=='folder' else 'input/'+source.name
                views.append((entry['id'],entry['name'],entry['kind'],relative,entry['roles']))
            else:
                archive = Path(temp)/'archive.zip'
                self.downloader(entry['url'],archive)
                if digest(archive)!=entry['sha256']:
                    raise ScopeError('Support archive checksum mismatch; no inputs installed.')
                full=stage/'upstream';full.mkdir()
                extract_archive(archive,full,entry['archive_prefix'])
                if not (full/entry['license_file']).is_file():
                    raise ScopeError('Pinned support archive is missing its license declaration.')
                if entry['id']=='nuclei-templates':
                    for group in sorted((full/'http').iterdir()):
                        if not group.is_dir():continue
                        relative='views/http-'+group.name; target=stage/relative;target.mkdir(parents=True)
                        (target/'http').mkdir();shutil.copytree(group,target/'http'/group.name)
                        for name in ('helpers','LICENSE.md','.nuclei-ignore'):
                            source=full/name
                            if source.is_dir():shutil.copytree(source,target/name)
                            elif source.is_file():shutil.copyfile(source,target/name)
                        snapshot_folder(target)
                        roles=['nuclei-takeovers'] if group.name=='takeovers' else []
                        views.append(('nuclei-http-'+group.name,'Nuclei HTTP / '+group.name,'folder',relative,roles))
                    # Full upstream is retained for inspection; only bounded HTTP
                    # category views become executable template input choices.
                else:
                    snapshot_folder(full)
                    views.append((entry['id'],entry['name'],'folder','upstream',['jaeles-signatures']))
            # Write the receipt before publication so interrupted DB registration
            # is recoverable without re-downloading or replacing existing files.
            rows=[]
            for pid,name,kind,relative,roles in views:
                path=stage/relative
                fingerprint=input_fingerprint(path,kind) if kind=='folder' else digest(path)
                published=destination/relative
                rows.append({'id':pid,'name':name,'kind':kind,'path':str(published.relative_to(self.root)),
                             'input_id':str(uuid.uuid5(uuid.NAMESPACE_URL,str(published))),
                             'sha256':fingerprint,'roles':roles})
            receipt={'id':entry['id'],'revision':entry['revision'],'archive_sha256':entry['sha256'] if remote else None,
                     'installed_at':now(),'inputs':rows}
            (stage/'installed.json').write_text(json.dumps(receipt,indent=2)+'\n')
            # Rename once. Existing versions are never overwritten or silently updated.
            if destination.exists():raise ScopeError('Incomplete support package exists; inspect it before reinstalling.')
            os.rename(stage,destination)
        for row in rows:self._register(row['id'],row['name'],row['kind'],self.root/row['path'],row['roles'])

    def bind(self, graph, *, bundled_only=False):
        from .workflows import validate_workflow
        validate_workflow(graph,live=True)
        result=copy.deepcopy(graph);available={};changes=[];missing=[]
        entries = self.manifest['bundled'] + ([] if bundled_only else self.manifest['remote'])
        for entry in entries:
            for row in self._checked_inputs(entry,validate=True):
                for role in row['roles']:available[role]=row['input_id']
        for node in result['nodes']:
            data=node['data']
            if data['kind']!='catalog_tool':continue
            refs=dict(data.get('inputRefs',{}))
            connected={(e.get('targetHandle') or 'in:'+next(n for n in result['nodes'] if n['id']==e['source'])['data']['output']).removeprefix('in:') for e in result['edges'] if e['target']==node['id']}
            for slot,role in requirements(TOOLS[data['toolId']]).items():
                if slot in refs or slot in connected:continue
                if role in available:
                    refs[slot]=available[role];changes.append({'node_id':node['id'],'slot':slot,'input_id':available[role]})
                else:missing.append({'node_id':node['id'],'slot':slot,'role':role})
            if refs:data['inputRefs']=refs
        validate_workflow(result,live=True)
        return {'graph':result,'bindings':changes,'missing':missing}
