export async function api(path,body){
 const response=await fetch('/api'+path,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 const data=await response.json().catch(()=>({detail:'The local backend is unavailable.'}));
 if(!response.ok)throw Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||'Request failed'));
 return data;
}
export function downloadJSON(name,value){
 const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));
 const a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);
}
