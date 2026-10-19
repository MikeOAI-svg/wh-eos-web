// ───────────────────────────────────────────────────────────────────────────
// HEART.OS — read-only MCP server (Company Pulse)
//
// Lets a Claude agent connect to HEART.OS and READ operational EOS data live:
// Rocks, Scorecards, open Issues, recent L10s, Headlines — company-wide or per team.
//
// SECURITY
//  • Auth: every request must send  Authorization: Bearer <MCP_AUTH_TOKEN>  (set in Netlify env).
//  • Data: read via the Firestore REST API using a Google service account (FIREBASE_SERVICE_ACCOUNT,
//    the JSON key, set in Netlify env). No firebase-admin dependency.
//  • READ-ONLY. This server never writes, edits, or deletes anything.
//  • CONFIDENTIAL DATA IS EXCLUDED: People Analyzer / evaluations, hire dates, and personal/email
//    fields are never read or returned. Only operational EOS metrics are exposed.
// ───────────────────────────────────────────────────────────────────────────
import crypto from "crypto";

const SA_RAW = (process.env.FIREBASE_SERVICE_ACCOUNT || "").trim();
const AUTH_TOKEN = (process.env.MCP_AUTH_TOKEN || "").trim();   // tolerate a trailing newline/space from pasting into Netlify
const WS_PATH = "workspaces/main";
const TEAMS_COL = "workspaces/main/teams";

function res(status, obj, extraHeaders){
  return { statusCode: status, headers: Object.assign({ "content-type": "application/json" }, extraHeaders || {}), body: obj == null ? "" : JSON.stringify(obj) };
}
function rpcOk(id, result){ return { jsonrpc: "2.0", id, result }; }
function rpcErr(id, code, message){ return { jsonrpc: "2.0", id, error: { code, message } }; }

// ── Google service-account auth → short-lived access token (cached) ─────────
let _sa = null;
function sa(){
  if(_sa) return _sa;
  if(!SA_RAW) throw new Error("FIREBASE_SERVICE_ACCOUNT is not set");
  _sa = JSON.parse(SA_RAW);
  if(_sa.private_key && _sa.private_key.indexOf("\\n") >= 0) _sa.private_key = _sa.private_key.replace(/\\n/g, "\n"); // in case newlines got escaped
  return _sa;
}
function b64url(buf){ return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"); }
let _tok = null, _tokExp = 0;
async function accessToken(){
  const now = Math.floor(Date.now() / 1000);
  if(_tok && now < _tokExp - 60) return _tok;
  const s = sa();
  const header = { alg: "RS256", typ: "JWT" };
  const claim = { iss: s.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 };
  const data = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(claim));
  const sig = crypto.sign("RSA-SHA256", Buffer.from(data), s.private_key);
  const assertion = data + "." + b64url(sig);
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion })
  });
  const j = await r.json();
  if(!j.access_token) throw new Error("Google token exchange failed: " + JSON.stringify(j));
  _tok = j.access_token; _tokExp = now + (j.expires_in || 3600);
  return _tok;
}

// ── Firestore REST ──────────────────────────────────────────────────────────
function fsBase(){ return `https://firestore.googleapis.com/v1/projects/${sa().project_id}/databases/(default)/documents`; }
function fromFs(v){
  if(v == null) return null;
  if("stringValue" in v) return v.stringValue;
  if("integerValue" in v) return Number(v.integerValue);
  if("doubleValue" in v) return v.doubleValue;
  if("booleanValue" in v) return v.booleanValue;
  if("nullValue" in v) return null;
  if("timestampValue" in v) return v.timestampValue;
  if("mapValue" in v){ const o = {}, f = (v.mapValue.fields) || {}; for(const k in f) o[k] = fromFs(f[k]); return o; }
  if("arrayValue" in v){ return ((v.arrayValue.values) || []).map(fromFs); }
  return null;
}
function docFields(doc){ const o = {}, f = (doc && doc.fields) || {}; for(const k in f) o[k] = fromFs(f[k]); return o; }
async function fsGet(path){
  const t = await accessToken();
  const r = await fetch(`${fsBase()}/${path}`, { headers: { authorization: "Bearer " + t } });
  const j = await r.json();
  if(j.error) throw new Error("Firestore read failed (" + path + "): " + (j.error.message || JSON.stringify(j.error)));
  return j;
}
async function fsList(coll){
  const t = await accessToken();
  let out = [], pageToken = "";
  do {
    const url = `${fsBase()}/${coll}?pageSize=300` + (pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : "");
    const r = await fetch(url, { headers: { authorization: "Bearer " + t } });
    const j = await r.json();
    if(j.error) throw new Error("Firestore list failed (" + coll + "): " + (j.error.message || JSON.stringify(j.error)));
    (j.documents || []).forEach(d => out.push(d));
    pageToken = j.nextPageToken || "";
  } while(pageToken);
  return out;
}

// ── Load operational data (confidential fields never touched) ───────────────
async function loadCompany(){ const d = docFields(await fsGet(WS_PATH)); return d.state || {}; }
async function loadTeams(){ return (await fsList(TEAMS_COL)).map(doc => docFields(doc).team).filter(Boolean); }

// ── EOS helpers ─────────────────────────────────────────────────────────────
function todayIso(){ return new Date().toISOString().slice(0, 10); }
function isoAddDays(iso, n){ const d = new Date(iso + "T00:00:00"); d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); }
// Matches the app's currentWeekIndex: 13 weeks/quarter, week i spans its Monday..Sunday; today picks the
// first week whose Sunday is >= today, capped at index 12.
function weekIndex(week1Start){
  if(!week1Start) return 0;
  const t = todayIso();
  for(let i = 0; i < 13; i++){ if(t <= isoAddDays(week1Start, i * 7 + 6)) return i; }
  return 12;
}
function rockPct(r){
  const ms = (r && r.milestones) || [];
  if(!ms.length) return r && r.status === "done" ? 100 : 0;
  return Math.round(100 * ms.filter(m => m && m.done).length / ms.length);
}
function teamStats(t){
  const wi = weekIndex(t.week1Start);
  const rocks = t.rocks || [];
  const rOn = rocks.filter(r => r.status === "on").length;
  const rOff = rocks.filter(r => r.status === "off" || r.status === "notdone").length;
  const rDone = rocks.filter(r => r.status === "done").length;
  const meas = t.measurables || [];
  let sOn = 0, sOff = 0, sNo = 0;
  meas.forEach(m => { const e = (m.values || {})[wi] || (m.values || {})[String(wi)]; const s = e && e.s; if(s === "on") sOn++; else if(s === "off") sOff++; else sNo++; });
  const openIssues = (t.issues || []).filter(i => i && !i.solved);
  const last = (t.meetings || [])[(t.meetings || []).length - 1] || null;
  return { name: t.name || "(team)", wi, rOn, rOff, rDone, rTot: rocks.length, sOn, sOff, sNo, sTot: meas.length, openIssues, last };
}
function line(s){ return s + "\n"; }

// ── Tool implementations (return readable text) ─────────────────────────────
async function tool_company_pulse(){
  const teams = await loadTeams();
  if(!teams.length) return "No teams found.";
  let out = line(`COMPANY PULSE — ${todayIso()}`) + line(`${teams.length} team${teams.length === 1 ? "" : "s"}`) + "\n";
  let tRocksOff = 0, tIssues = 0;
  teams.forEach(t => {
    const s = teamStats(t);
    tRocksOff += s.rOff; tIssues += s.openIssues.length;
    out += line(`● ${s.name}`);
    out += line(`   Rocks: ${s.rOn} on · ${s.rOff} off · ${s.rDone} done  (of ${s.rTot})`);
    out += line(`   Scorecard (wk ${s.wi + 1}): ${s.sOn} on · ${s.sOff} off · ${s.sNo} no-data  (of ${s.sTot})`);
    out += line(`   Open issues: ${s.openIssues.length}`);
    out += line(`   Last L10: ${s.last ? `${s.last.date} · avg ${s.last.avg != null ? s.last.avg : "—"}/10` : "none recorded"}`);
    out += "\n";
  });
  out += line(`SUMMARY: ${tRocksOff} off-track Rock(s) and ${tIssues} open issue(s) across the company.`);
  return out.trim();
}
async function tool_list_teams(){
  const teams = await loadTeams();
  if(!teams.length) return "No teams found.";
  return teams.map(t => `• ${t.name || "(team)"}  [id: ${t.id || "?"}]`).join("\n");
}
function matchTeam(teams, q){
  q = String(q || "").trim().toLowerCase();
  return teams.find(t => (t.id || "").toLowerCase() === q) ||
         teams.find(t => (t.name || "").toLowerCase() === q) ||
         teams.find(t => (t.name || "").toLowerCase().indexOf(q) >= 0) || null;
}
async function tool_team_detail(args){
  const teams = await loadTeams();
  const t = matchTeam(teams, args && args.team);
  if(!t) return `No team matched "${(args && args.team) || ""}". Use list_teams to see names.`;
  const wi = weekIndex(t.week1Start);
  let out = line(`TEAM: ${t.name || "(team)"}  (week ${wi + 1})`) + "\n";

  out += line("ROCKS");
  const rocks = t.rocks || [];
  out += rocks.length ? rocks.map(r => `  • [${(r.status || "off").toUpperCase()}] ${r.title || "(untitled)"} — ${r.owner || "unassigned"} · ${rockPct(r)}%`).join("\n") : "  (none)";
  out += "\n\n";

  out += line("SCORECARD (this week)");
  const meas = t.measurables || [];
  out += meas.length ? meas.map(m => { const e = (m.values || {})[wi] || (m.values || {})[String(wi)]; const v = e ? (e.v || "—") : "—"; const s = e ? (e.s || "") : ""; return `  • ${m.name || "(measurable)"} — ${m.owner || "—"} · goal ${m.goal || "—"} · this week: ${v}${s === "on" ? " ✓on" : s === "off" ? " ✗off" : ""}`; }).join("\n") : "  (none)";
  out += "\n\n";

  out += line("OPEN ISSUES");
  const iss = (t.issues || []).filter(i => i && !i.solved);
  out += iss.length ? iss.map(i => `  • ${i.text || ""}${i.owner ? " — raised by " + i.owner : ""}`).join("\n") : "  (none) 🎉";
  out += "\n\n";

  out += line("RECENT L10s");
  const ms = (t.meetings || []).slice(-5).reverse();
  out += ms.length ? ms.map(m => `  • ${m.date} · ${m.durationMin || "?"} min · avg ${m.avg != null ? m.avg : "—"}/10`).join("\n") : "  (none)";

  const hl = (t.headlines || []);
  if(hl.length){ out += "\n\n" + line("HEADLINES"); out += hl.slice(0, 10).map(h => `  • ${h.text || "(photo)"}${h.owner ? " — " + h.owner : ""}`).join("\n"); }
  return out.trim();
}
async function tool_open_issues(args){
  const teams = await loadTeams();
  let list = teams;
  if(args && args.team){ const t = matchTeam(teams, args.team); list = t ? [t] : []; }
  const rows = [];
  list.forEach(t => (t.issues || []).filter(i => i && !i.solved).forEach(i => rows.push(`  • [${t.name || "team"}] ${i.text || ""}${i.owner ? " — " + i.owner : ""}`)));
  return rows.length ? line(`OPEN ISSUES (${rows.length})`) + rows.join("\n") : "No open issues. 🎉";
}

const TOOLS = [
  { name: "company_pulse", description: "A company-wide operational health snapshot: for every team, Rocks on/off/done, Scorecard on/off/no-data for the current week, open-issue count, and the last L10 date + average rating.", inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: tool_company_pulse },
  { name: "list_teams", description: "List every team with its id, so you can look one up by name.", inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: tool_list_teams },
  { name: "team_detail", description: "Full operational detail for ONE team: its Rocks (status + % complete), this week's Scorecard numbers, open issues, recent L10s, and headlines.", inputSchema: { type: "object", properties: { team: { type: "string", description: "Team name or id." } }, required: ["team"], additionalProperties: false },
    run: tool_team_detail },
  { name: "open_issues", description: "Every open (unsolved) issue across the company, or for one team if 'team' is given.", inputSchema: { type: "object", properties: { team: { type: "string", description: "Optional team name or id to filter by." } }, additionalProperties: false },
    run: tool_open_issues }
];

// ── JSON-RPC (MCP) dispatch ─────────────────────────────────────────────────
async function handleRpc(msg){
  const { id, method, params } = msg || {};
  if(method === "initialize"){
    const pv = (params && params.protocolVersion) || "2025-06-18";
    return rpcOk(id, { protocolVersion: pv, capabilities: { tools: { listChanged: false } }, serverInfo: { name: "heartos", version: "1.0.0" } });
  }
  if(method === "ping") return rpcOk(id, {});
  if(method === "tools/list") return rpcOk(id, { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) });
  if(method === "tools/call"){
    const name = params && params.name;
    const tool = TOOLS.find(t => t.name === name);
    if(!tool) return rpcErr(id, -32602, `Unknown tool: ${name}`);
    try {
      const text = await tool.run((params && params.arguments) || {});
      return rpcOk(id, { content: [{ type: "text", text: String(text) }], isError: false });
    } catch(e){
      return rpcOk(id, { content: [{ type: "text", text: "Error: " + (e && e.message || String(e)) }], isError: true });
    }
  }
  return rpcErr(id, -32601, `Method not found: ${method}`);
}

export async function handler(event){
  const method = event.httpMethod || "POST";
  if(method === "OPTIONS") return { statusCode: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "authorization, content-type, mcp-protocol-version" }, body: "" };
  if(method === "GET") return res(405, { error: "This is the HEART.OS MCP endpoint — use POST (JSON-RPC)." }, { allow: "POST, OPTIONS" });
  if(method !== "POST") return res(405, { error: "Method not allowed" }, { allow: "POST, OPTIONS" });

  // ── Auth: bearer token must match MCP_AUTH_TOKEN ──
  if(!AUTH_TOKEN) return res(500, rpcErr(null, -32000, "Server not configured: MCP_AUTH_TOKEN is unset."));
  const authz = event.headers && (event.headers.authorization || event.headers.Authorization) || "";
  const presented = authz.replace(/^Bearer\s+/i, "").trim();
  const ok = presented.length === AUTH_TOKEN.length &&
             crypto.timingSafeEqual(Buffer.from(presented), Buffer.from(AUTH_TOKEN));
  if(!ok) return res(401, rpcErr(null, -32001, "Unauthorized — missing or invalid bearer token."), { "www-authenticate": "Bearer" });

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch(e){ return res(400, rpcErr(null, -32700, "Parse error")); }

  // Batch of messages
  if(Array.isArray(body)){
    const replies = [];
    for(const m of body){ if(m && m.id !== undefined && m.method) replies.push(await handleRpc(m)); } // skip notifications (no id)
    return replies.length ? res(200, replies) : { statusCode: 202, body: "" };
  }
  // Notification (no id) → no response body
  if(body && body.id === undefined && body.method){ return { statusCode: 202, body: "" }; }
  const reply = await handleRpc(body);
  return res(200, reply);
}
