import {spawn} from 'node:child_process';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
const args=process.argv.slice(2);
const preview=args.includes('4173');
const env={...process.env,...(preview?{AI_TRICKY_PREVIEW:'1'}:{})};
let python=resolve('.venv/bin/python');
// The Work preview container mounts the project but not its original Python runtime.
// Its system Python has the same 3.12 ABI, so use the project's installed modules there.
if(preview&&!existsSync(python)&&existsSync('.venv/lib/python3.12/site-packages')){
 python='/usr/bin/python3';env.PYTHONPATH=resolve('.venv/lib/python3.12/site-packages');
}
const children=[];
if(existsSync(python))children.push(spawn(python,['-m','backend'],{stdio:'inherit',env}));
else console.warn('Python backend unavailable. Create .venv and install requirements first.');
children.push(spawn(process.execPath,['node_modules/vite/bin/vite.js',...(args.includes('--host')?[]:['--host','127.0.0.1']),...args],{stdio:'inherit',env}));
let stopping=false;
function stop(code=0){if(stopping)return;stopping=true;for(const child of children)child.kill('SIGTERM');setTimeout(()=>process.exit(code),300).unref();}
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>stop());
for(const child of children){child.on('error',e=>{console.error(e.message);stop(1)});child.on('exit',code=>{if(!stopping)stop(code||0)})}
