export default {
async fetch(req, env) {
const kv = env.MANAGER_KV;
const AO = [[“Access-Control-Allow-Origin”,”*”],[“Access-Control-Allow-Methods”,“GET,PUT,POST,DELETE,OPTIONS”],[“Access-Control-Allow-Headers”,“Content-Type,X-Auth-Token”],[“Content-Type”,“application/json”]];
function cors() { return Object.fromEntries(AO); }
function ok(d) { return new Response(JSON.stringify(d), { headers: cors() }); }
function fail(m, s) { return new Response(JSON.stringify({ error: m }), { status: s || 400, headers: cors() }); }
if (req.method === “OPTIONS”) return new Response(null, { status: 204, headers: Object.fromEntries(AO.slice(0,3)) });
const url = new URL(req.url);
async function getSess(r) {
const t = r.headers.get(“X-Auth-Token”);
if (!t) return null;
const raw = await kv.get(“sessions”);
const ss = raw ? JSON.parse(raw) : {};
const s = ss[t];
if (!s) return null;
if (s.expires < Date.now()) { delete ss[t]; await kv.put(“sessions”, JSON.stringify(ss)); return null; }
return s;
}
async function needRole(r, roles) {
const s = await getSess(r);
if (!s || (roles && !roles.includes(s.role))) return null;
return s;
}
if (url.pathname === “/auth/login” && req.method === “POST”) {
const b = await req.json();
const login = (b.login || “”).trim().toLowerCase();
const ur = await kv.get(“users”);
let ul = ur ? JSON.parse(ur) : [];
if (!ul.length) { ul = [{id:1,login:“admin”,passHash:“8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918”,role:“admin”,name:“Administrator”}]; await kv.put(“users”, JSON.stringify(ul)); }
const u = ul.find(x => x.login === login && x.passHash === (b.passHash || “”));
if (!u) return fail(“Bad credentials”, 401);
const tok = crypto.randomUUID();
const sr = await kv.get(“sessions”);
const ss = sr ? JSON.parse(sr) : {};
ss[tok] = { userId: u.id, login: u.login, name: u.name, role: u.role, expires: Date.now() + 604800000 };
await kv.put(“sessions”, JSON.stringify(ss));
return ok({ token: tok, role: u.role, name: u.name, login: u.login });
}
if (url.pathname === “/auth/logout” && req.method === “POST”) {
const t = req.headers.get(“X-Auth-Token”);
if (t) { const sr = await kv.get(“sessions”); const ss = sr ? JSON.parse(sr) : {}; delete ss[t]; await kv.put(“sessions”, JSON.stringify(ss)); }
return ok({ ok: true });
}
if (url.pathname === “/auth/me”) { const s = await getSess(req); return s ? ok(s) : fail(“No session”, 401); }
if (url.pathname === “/users” && req.method === “GET”) {
if (!await needRole(req, [“admin”])) return fail(“Forbidden”, 403);
const ur = await kv.get(“users”); const ul = ur ? JSON.parse(ur) : [];
return ok(ul.map(u => ({ id: u.id, login: u.login, role: u.role, name: u.name })));
}
if (url.pathname === “/users” && req.method === “POST”) {
if (!await needRole(req, [“admin”])) return fail(“Forbidden”, 403);
const b = await req.json(); if (!b.login || !b.passHash || !b.role) return fail(“Missing fields”);
const ur = await kv.get(“users”); const ul = ur ? JSON.parse(ur) : [];
if (ul.find(u => u.login === b.login.toLowerCase())) return fail(“Login exists”);
const nu = { id: ul.reduce((m,u) => Math.max(m,u.id), 0) + 1, login: b.login.toLowerCase(), passHash: b.passHash, role: b.role, name: b.name || b.login };
ul.push(nu); await kv.put(“users”, JSON.stringify(ul)); return ok(nu);
}
if (url.pathname === “/users” && req.method === “PUT”) {
if (!await needRole(req, [“admin”])) return fail(“Forbidden”, 403);
const b = await req.json(); const ur = await kv.get(“users”); const ul = ur ? JSON.parse(ur) : [];
const idx = ul.findIndex(u => u.id === parseInt(url.searchParams.get(“id”)));
if (idx === -1) return fail(“Not found”, 404);
if (b.name !== undefined) ul[idx].name = b.name; if (b.role) ul[idx].role = b.role; if (b.passHash) ul[idx].passHash = b.passHash;
await kv.put(“users”, JSON.stringify(ul)); return ok({ ok: true });
}
if (url.pathname === “/users” && req.method === “DELETE”) {
if (!await needRole(req, [“admin”])) return fail(“Forbidden”, 403);
const uid = parseInt(url.searchParams.get(“id”)); const ur = await kv.get(“users”); let ul = ur ? JSON.parse(ur) : [];
const tgt = ul.find(u => u.id === uid);
if (tgt && tgt.role === “admin” && ul.filter(u => u.role === “admin”).length <= 1) return fail(“Cannot delete last admin”);
await kv.put(“users”, JSON.stringify(ul.filter(u => u.id !== uid))); return ok({ ok: true });
}
if (url.pathname === “/data”) {
const s = await getSess(req); if (!s) return fail(“Unauthorized”, 401);
const key = url.searchParams.get(“key”) || “apts”;
if (req.method === “GET”) { const v = await kv.get(key); return new Response(v || “null”, { headers: cors() }); }
if (req.method === “PUT”) { if (s.role === “cleaner” || s.role === “viewer”) return fail(“Forbidden”, 403); await kv.put(key, await req.text()); return ok({ ok: true }); }
}
if (url.pathname === “/inquiry” && req.method === “POST”) {
const b = await req.json(); const raw = await kv.get(“inquiries”); let list = raw ? JSON.parse(raw) : [];
list.unshift({ id: Date.now(), ts: new Date().toISOString(), apt: b.apt||””, from: b.from||””, to: b.to||””, nights: b.nights||0, name: b.name||””, phone: b.phone||””, email: b.email||””, people: b.people||””, note: b.note||””, lang: b.lang||“pl”, channel: b.channel||””, status: “new” });
if (list.length > 200) list = list.slice(0, 200);
await kv.put(“inquiries”, JSON.stringify(list)); return ok({ ok: true });
}
if (url.pathname === “/inquiry” && req.method === “GET”) { if (!await getSess(req)) return fail(“Unauthorized”, 401); const raw = await kv.get(“inquiries”); return ok(raw ? JSON.parse(raw) : []); }
if (url.pathname === “/inquiry” && req.method === “PUT”) {
if (!await getSess(req)) return fail(“Unauthorized”, 401);
const b = await req.json(); const raw = await kv.get(“inquiries”); const list = raw ? JSON.parse(raw) : [];
const idx = list.findIndex(q => q.id === parseInt(url.searchParams.get(“id”)));
if (idx === -1) return fail(“Not found”, 404);
Object.assign(list[idx], b); await kv.put(“inquiries”, JSON.stringify(list)); return ok({ ok: true });
}
if (url.pathname === “/inquiry” && req.method === “DELETE”) {
if (!await getSess(req)) return fail(“Unauthorized”, 401);
const id = parseInt(url.searchParams.get(“id”)); const raw = await kv.get(“inquiries”); let list = raw ? JSON.parse(raw) : [];
await kv.put(“inquiries”, JSON.stringify(list.filter(q => q.id !== id))); return ok({ ok: true });
}
if (!await getSess(req)) return fail(“Unauthorized”, 401);
const target = url.searchParams.get(“url”); if (!target) return fail(“Missing url”, 400);
const resp = await fetch(target, { headers: { “User-Agent”: “Mozilla/5.0” } });
return new Response(await resp.text(), { status: resp.status, headers: { “Access-Control-Allow-Origin”: “*”, “Content-Type”: “text/plain;charset=utf-8” } });
}
};