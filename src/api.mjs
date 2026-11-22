export async function api(path,body){
 const response=await fetch('/api'+path,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 const data=await response.json().catch(()=>({detail:'The local backend is unavailable.'}));
 if(!response.ok)throw Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||'Request failed'));
 return data;
}
export function downloadJSON(name,value){
 downloadText(name,JSON.stringify(value,null,2),'application/json');
}
export function downloadText(name,value,type){
 const url=URL.createObjectURL(new Blob([value],{type}));
 const a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);
}
