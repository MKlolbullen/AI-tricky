"""Owned identity argv and bounded interpretation of tool-reported diagnostics."""
import json
import re


TESTED_RELEASES={'impacket':'0.13.1','azurehound':'3.1.3'}


def collection_command(profile,binary,scope,auth,credential_path,output):
    if profile['platform']=='ad':
        return [str(binary),*(['-all'] if profile['id']=='impacket-ad-users' else []),'-k','-no-pass',
                '-dc-ip',auth['dc_ip'],'-dc-host',auth['dc_host'],scope['domain']+'/'+auth['username']]
    return [str(binary),'list','az-ad','--tenant',scope['tenant_id'],'--config',str(credential_path),'--output',str(output),'--json']


def collection_health(profile,stdout,stderr,exit_code):
    """Exit zero is not evidence of successful or complete collection.

    Only documented log prefixes/JSON levels are interpreted. The metadata
    contains fixed messages and counts, never raw diagnostics or credentials.
    """
    errors=warnings=unknown=0
    for stream,text in [('stdout',stdout),('stderr',stderr)]:
        for line in text.splitlines():
            if not line.strip():continue
            if profile['platform']=='ad':
                if re.match(r'^\s*\[-\]',line):errors+=1
                elif re.match(r'^\s*\[!\]',line):warnings+=1
                elif stream=='stderr':unknown+=1
            else:
                try:record=json.loads(line)
                except (ValueError,RecursionError):record=None
                if isinstance(record,dict) and isinstance(record.get('level'),str):
                    level=record['level'].lower()
                    if level in ('error','fatal','panic'):errors+=1
                    elif level in ('warn','warning'):warnings+=1
                elif stream=='stderr':unknown+=1
    # Impacket can print an error and exit 0. Retain actual table rows when
    # errors concern only part of a result; otherwise stop the graph branch.
    headers={'impacket-ad-users':'Name','impacket-spns':'ServicePrincipalName','impacket-delegation':'AccountName'}
    table=False
    if profile['platform']=='ad':
        lines=stdout.splitlines()
        for index,line in enumerate(lines[:-2]):
            if line.strip().startswith(headers[profile['id']]+' ') and re.fullmatch(r'[\s-]+',lines[index+1]) and any(row.strip() and not row.lstrip().startswith('[') for row in lines[index+2:]):
                table=True;break
    failed=exit_code!=0 or profile['platform']=='ad' and errors>0 and not table
    status='failed' if failed else 'partial' if errors or warnings or unknown else 'unverified'
    return {'schema':'ai-tricky.collection-health/v1','status':status,'error_count':errors,'warning_count':warnings,
            'unclassified_stderr_lines':unknown,'exit_code':exit_code,'table_rows_observed':table,
            'coverage_verified':False,'note':'Tool diagnostics and exit status do not establish complete collection or absence of risk.'}
