export default {
async fetch(req, env) {
const O=’*’,M=‘GET,PUT,POST,DELETE,OPTIONS’,H=‘Content-Type,X-Auth-Token’;
const h=()=>({‘Access-Control-Allow-Origin’:O,‘Access-Control-Allow-Methods’:M,‘Access-Control-Allow-Headers’:H,‘Content-Type’:‘application/json’});
const ok=d=>new Response(JSON.stringify(d),{headers:h()});
const fail=(m,s)=>new Response(JSON.stringify({error:m}),{status:s||400,headers:h()});
if(req.method===‘OPTIONS’)return new Response(null,{status:204,headers:{‘Access-Control-Allow-Origin’:O,‘Access-Control-Allow-Methods’:M,‘Access-Control-Allow-Headers’:H}});
const url=new URL(req.url);
const kv=env.MANAGER_KV;
async function getSess(r){
const t=r.headers.get(‘X-Auth-Token’);if(!t)return null;
const raw=await kv.get(‘sessions’);const ss=raw?JSON.parse(raw):{};
const s=ss[t];if(!s)return null;
if(s.expires<Date.now()){delete ss[t];await kv.put(‘sessions’,JSON.stringify(ss));return null;}
return s;
}
async function needRole(r,roles){const s=await getSess(r);if(!s)return null;if(roles&&!roles.includes(s.role))return null;return s;}
if(url.pathname===’/auth/login’&&req.method===‘POST’){
const b=await req.json();const login=(b.login||’’).trim().toLowerCase();const ph=b.passHash||’’;
let ur=await kv.get(‘users’);let ul=ur?JSON.parse(ur):[];
if(!ul.length){ul=[{id:1,login:‘admin’,passHash:‘8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918’,role:‘admin’,name:‘Administrator’}];await kv.put(‘users’,JSON.stringify(ul));}
const u=ul.find(x=>x.login===login&&x.passHash===ph);if(!u)return fail(‘Bad credentials’,401);
const tok=crypto.randomUUID();const sr=await kv.get(‘sessions’);const ss=sr?JSON.parse(sr):{};
ss[tok]={userId:u.id,login:u.login,name:u.name,role:u.role,expires:Date.now()+7*24*60*60*1000};
await kv.put(‘sessions’,JSON.stringify(ss));return ok({token:tok,role:u.role,name:u.name,login:u.login});
}
if(url.pathname===’/auth/logout’&&req.method===‘POST’){
const t=req.headers.get(‘X-Auth-Token’);if(t){const sr=await kv.get(‘sessions’);const ss=sr?JSON.parse(sr):{};delete ss[t];await kv.put(‘sessions’,JSON.stringify(ss));}
return ok({ok:true});
}
if(url.pathname===’/auth/me’&&req.method===‘GET’){const s=await getSess(req);if(!s)return fail(‘No session’,401);return ok(s);}
if(url.pathname===’/users’&&req.method===‘GET’){if(!await needRole(req,[‘admin’]))return fail(‘Forbidden’,403);const ur=await kv.get(‘users’);const ul=ur?JSON.parse(ur):[];return ok(ul.map(u=>({id:u.id,login:u.login,role:u.role,name:u.name})));}
if(url.pathname===’/users’&&req.method===‘POST’){
if(!await needRole(req,[‘admin’]))return fail(‘Forbidden’,403);
const b=await req.json();if(!b.login||!b.passHash||!b.role)return fail(‘Missing fields’);
const ur=await kv.get(‘users’);const ul=ur?JSON.parse(ur):[];
if(ul.find(u=>u.login===b.login.toLowerCase()))return fail(‘Login exists’);
const mid=ul.reduce((m,u)=>Math.max(m,u.id),0);const nu={id:mid+1,login:b.login.toLowerCase(),passHash:b.passHash,role:b.role,name:b.name||b.login};
ul.push(nu);await kv.put(‘users’,JSON.stringify(ul));return ok({id:nu.id,login:nu.login,role:nu.role,name:nu.name});
}
if(url.pathname===’/users’&&req.method===‘PUT’){
if(!await needRole(req,[‘admin’]))return fail(‘Forbidden’,403);
const uid=parseInt(url.searchParams.get(‘id’));const b=await req.json();
const ur=await kv.get(‘users’);const ul=ur?JSON.parse(ur):[];const idx=ul.findIndex(u=>u.id===uid);
if(idx===-1)return fail(‘Not found’,404);
if(b.name!==undefined)ul[idx].name=b.name;if(b.role!==undefined)ul[idx].role=b.role;if(b.passHash)ul[idx].passHash=b.passHash;
await kv.put(‘users’,JSON.stringify(ul));return ok({ok:true});
}
if(url.pathname===’/users’&&req.method===‘DELETE’){
if(!await needRole(req,[‘admin’]))return fail(‘Forbidden’,403);
const uid=parseInt(url.searchParams.get(‘id’));const ur=await kv.get(‘users’);let ul=ur?JSON.parse(ur):[];
const tgt=ul.find(u=>u.id===uid);const ac=ul.filter(u=>u.role===‘admin’).length;
if(tgt&&tgt.role===‘admin’&&ac<=1)return fail(‘Cannot delete last admin’);
ul=ul.filter(u=>u.id!==uid);await kv.put(‘users’,JSON.stringify(ul));return ok({ok:true});
}
if(url.pathname===’/data’){
const s=await getSess(req);if(!s)return fail(‘Unauthorized’,401);
const key=url.searchParams.get(‘key’)||‘apts’;
if(req.method===‘GET’){const v=await kv.get(key);return new Response(v||‘null’,{headers:h()});}
if(req.method===‘PUT’){if(s.role===‘cleaner’||s.role===‘viewer’)return fail(‘Forbidden’,403);await kv.put(key,await req.text());return ok({ok:true});}
}
if(url.pathname===’/inquiry’&&req.method===‘POST’){
const b=await req.json();const raw=await kv.get(‘inquiries’);let list=raw?JSON.parse(raw):[];
const inq={id:Date.now(),ts:new Date().toISOString(),apt:b.apt||’’,from:b.from||’’,to:b.to||’’,nights:b.nights||0,name:b.name||’’,phone:b.phone||’’,email:b.email||’’,people:b.people||’’,note:b.note||’’,lang:b.lang||‘pl’,channel:b.channel||’’,status:‘new’};
list.unshift(inq);if(list.length>200)list=list.slice(0,200);await kv.put(‘inquiries’,JSON.stringify(list));return ok({ok:true,id:inq.id});
}
if(url.pathname===’/inquiry’&&req.method===‘GET’){if(!await getSess(req))return fail(‘Unauthorized’,401);const raw=await kv.get(‘inquiries’);return ok(raw?JSON.parse(raw):[]);}
if(url.pathname===’/inquiry’&&req.method===‘PUT’){
if(!await getSess(req))return fail(‘Unauthorized’,401);
const id=parseInt(url.searchParams.get(‘id’));const b=await req.json();
const raw=await kv.get(‘inquiries’);const list=raw?JSON.parse(raw):[];const idx=list.findIndex(q=>q.id===id);
if(idx===-1)return fail(‘Not found’,404);Object.assign(list[idx],b);await kv.put(‘inquiries’,JSON.stringify(list));return ok({ok:true});
}
if(url.pathname===’/inquiry’&&req.method===‘DELETE’){
if(!await getSess(req))return fail(‘Unauthorized’,401);
const id=parseInt(url.searchParams.get(‘id’));const raw=await kv.get(‘inquiries’);let list=raw?JSON.parse(raw):[];
list=list.filter(q=>q.id!==id);await kv.put(‘inquiries’,JSON.stringify(list));return ok({ok:true});
}
if(!await getSess(req))return fail(‘Unauthorized’,401);
const target=url.searchParams.get(‘url’);if(!target)return fail(‘Missing url’,400);
const res=await fetch(target,{headers:{‘User-Agent’:‘Mozilla/5.0’,‘Accept’:’text/calendar,*/*’}});
const txt=await res.text();return new Response(txt,{status:res.status,headers:{‘Access-Control-Allow-Origin’:O,‘Content-Type’:‘text/plain;charset=utf-8’}});
}
};