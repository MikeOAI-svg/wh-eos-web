// Daily evaluation reminder emails for the Warriors Heart EOS app (HEART.OS).
//
// Annual performance evaluations come due on each person's hire-date anniversary. This scheduled function
// runs once a day, reads the company doc, works out whose review is coming due (or overdue), and emails
// their SUPERVISOR a reminder from a Warriors Heart address (via Resend) — one digest per supervisor.
//
// Cadence (decided with Mike): 30, 15, 7 and 1 day before, a "due today" nudge, then once a week while
// overdue, until the review is filed. Recipient: the supervisor only.
//
// PRIVACY: this reads ONLY the org chart, the people↔email list, hire dates and the completed-cycle flags
// — all of which live on the shared company doc (workspaces/main). It never opens a confidential
// per-supervisor evaluation file, so no review content or rating ever leaves Firestore here.
//
// Secrets live ONLY in Netlify env vars (same ones the invite email uses — no new secrets):
//   FIREBASE_SERVICE_ACCOUNT   service-account JSON with Firestore read access
//   RESEND_API_KEY             a Resend API key, sending from a verified Warriors Heart domain
//   INVITE_FROM                e.g.  Warriors Heart <noreply@mail.warriorsheart.com>
//   APP_URL                    the app's URL (default warriorsos.netlify.app)
import { importPKCS8, SignJWT } from "jose";

const PROJECT_ID = "wh-operating-system";
const APP_URL = process.env.APP_URL || "https://warriorsos.netlify.app";

// Run every day at 13:00 UTC ≈ 7–8am Central — a morning nudge before the day fills up.
export const config = { schedule: "0 13 * * *" };

/* ---------- small date helpers (UTC; mirror the client's eval math) ---------- */
const pad2 = n => String(n).padStart(2, "0");
const isoOfDate = d => d.getUTCFullYear() + "-" + pad2(d.getUTCMonth() + 1) + "-" + pad2(d.getUTCDate());
const parseIso = iso => new Date(iso + "T00:00:00Z");
const todayIso = () => new Date().toISOString().slice(0, 10);
function addDaysIso(iso, n){ const d = parseIso(iso); d.setUTCDate(d.getUTCDate() + n); return isoOfDate(d); }
function daysUntil(iso, today){ return Math.round((parseIso(iso) - parseIso(today || todayIso())) / 86400000); }
function fmtLong(iso){ try{ return parseIso(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }); }catch(e){ return iso; } }
function nextAnniversary(hireISO, fromISO){
  if(!hireISO) return "";
  const h = parseIso(hireISO), f = parseIso(fromISO);
  let due = new Date(Date.UTC(f.getUTCFullYear(), h.getUTCMonth(), h.getUTCDate()));
  if(due < f) due = new Date(Date.UTC(f.getUTCFullYear() + 1, h.getUTCMonth(), h.getUTCDate()));
  return isoOfDate(due);
}
function currentEvalDue(hireISO, fromISO){
  if(!hireISO) return "";
  const h = parseIso(hireISO), f = parseIso(fromISO);
  let due = new Date(Date.UTC(f.getUTCFullYear(), h.getUTCMonth(), h.getUTCDate()));
  if(due <= h) due = new Date(Date.UTC(f.getUTCFullYear() + 1, h.getUTCMonth(), h.getUTCDate()));
  return isoOfDate(due);
}
const OVERDUE_GRACE = 60;
function evalDueFromHire(hireISO, today){
  if(!hireISO) return "";
  const cur = currentEvalDue(hireISO, today);
  return (daysUntil(cur, today) >= -OVERDUE_GRACE) ? cur : nextAnniversary(hireISO, today);
}
// The review a person currently owes, from the COMPANY doc alone (hire date + completed-cycle flag) —
// mirrors the roster's hireDue() without the confidential per-supervisor file.
function dueForPerson(nameKey, hireDates, evalDone, today){
  const hire = hireDates[nameKey]; if(!hire) return "";
  const done = evalDone[nameKey];
  if(done) return nextAnniversary(hire, addDaysIso(done, 1));
  return evalDueFromHire(hire, today);
}

/* ---------- chart / people helpers (mirror the client) ---------- */
const normName = s => String(s == null ? "" : s).trim().toLowerCase();
const isOpenName = s => { const n = normName(s); return !n || n === "open" || n === "vacant" || n === "tbd" || n === "open seat"; };
function seatNamesOf(seat){ const raw = Array.isArray(seat.names) ? seat.names : (seat.name ? [seat.name] : []); return raw.filter(n => n && !isOpenName(n)); }
function seatHasName(seat, name){ return seatNamesOf(seat).some(n => normName(n) === normName(name)); }
// Nearest FILLED seat above this person, climbing past OPEN seats — their real supervisor.
function managerOf(seats, name){
  const byId = id => seats.find(x => x && x.id === id);
  for(const s of seats){ if(seatHasName(s, name) && s.parent){
    let p = byId(s.parent), guard = 0;
    while(p && guard++ < 100){
      const nm = seatNamesOf(p).filter(n => normName(n) !== normName(name))[0];
      if(nm) return nm;
      p = p.parent ? byId(p.parent) : null;
    }
  } }
  return "";
}
function seatRoleOf(seats, name){ const s = seats.find(x => seatHasName(x, name)); return (s && s.role) || ""; }
function emailForName(people, name){ const p = people.find(x => x && normName(x.name) === normName(name)); return (p && p.email) ? String(p.email).trim() : ""; }

/* ---------- Firestore REST value decoding ---------- */
function fsDecode(v){
  if(v == null) return null;
  if("stringValue" in v) return v.stringValue;
  if("booleanValue" in v) return !!v.booleanValue;
  if("integerValue" in v) return Number(v.integerValue);
  if("doubleValue" in v) return Number(v.doubleValue);
  if("nullValue" in v) return null;
  if("timestampValue" in v) return v.timestampValue;
  if("mapValue" in v){ const o = {}, f = (v.mapValue && v.mapValue.fields) || {}; for(const k in f) o[k] = fsDecode(f[k]); return o; }
  if("arrayValue" in v){ return ((v.arrayValue && v.arrayValue.values) || []).map(fsDecode); }
  return null;
}

/* ---------- the core: who to remind, grouped by supervisor ---------- */
// Pure + exported so it can be unit-tested with a synthetic state. Returns:
//   [{ email, name, items:[{ name, role, due, days, status }] }]
export function buildReminders(state, today){
  today = today || todayIso();
  const seats = ((state && state.accountability) || {}).seats || [];
  const people = (state && state.people) || [];
  const hireDates = (state && state.hireDates) || {};
  const evalDone = (state && state.evalDone) || {};

  // Every distinct person the chart knows, keyed by lowercased name → display spelling.
  const nameByKey = {};
  seats.forEach(s => seatNamesOf(s).forEach(n => { const k = normName(n); if(!nameByKey[k]) nameByKey[k] = n; }));
  people.forEach(p => { if(p && p.name){ const k = normName(p.name); if(!nameByKey[k]) nameByKey[k] = p.name; } });

  const groups = {};   // mgrEmail → { email, name, items:[] }
  Object.keys(hireDates).forEach(key => {
    if(!hireDates[key]) return;
    const name = nameByKey[key] || key;
    const due = dueForPerson(key, hireDates, evalDone, today);
    if(!due) return;
    const d = daysUntil(due, today);
    const fire = [30, 15, 7, 1].includes(d) || d === 0 || (d < 0 && (-d) % 7 === 0);
    if(!fire) return;
    const mgr = managerOf(seats, name); if(!mgr) return;            // no supervisor on the chart → skip
    const mgrEmail = emailForName(people, mgr); if(!mgrEmail) return; // supervisor has no sign-in → skip
    const status = d > 0 ? ("Due in " + d + " day" + (d === 1 ? "" : "s"))
      : d === 0 ? "Due today"
      : ("Overdue by " + (-d) + " day" + ((-d) === 1 ? "" : "s"));
    const gk = normName(mgrEmail);
    (groups[gk] = groups[gk] || { email: mgrEmail, name: mgr, items: [] }).items
      .push({ name, role: seatRoleOf(seats, name), due, days: d, status });
  });

  // Most urgent first within each supervisor's digest.
  return Object.values(groups).map(g => {
    g.items.sort((a, b) => a.days - b.days);
    return g;
  });
}

/* ---------- email ---------- */
function esc(s){ return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function reminderHtml(mgrName, items){
  const who = esc((mgrName || "").split(" ")[0]) || "there";
  const rows = items.map(it => {
    const overdue = it.days < 0, soon = it.days >= 0 && it.days <= 7;
    const color = overdue ? "#b42318" : soon ? "#b4530f" : "#44403c";
    return `<tr>
      <td style="padding:10px 0;border-top:1px solid #efeae0;font-size:15px;color:#1c1917"><b>${esc(it.name)}</b>${it.role ? `<div style="font-size:12.5px;color:#78716c">${esc(it.role)}</div>` : ""}</td>
      <td style="padding:10px 0;border-top:1px solid #efeae0;font-size:14px;text-align:right;color:${color};white-space:nowrap"><b>${esc(it.status)}</b><div style="font-size:12px;color:#a8a29e">due ${esc(fmtLong(it.due))}</div></td>
    </tr>`;
  }).join("");
  const n = items.length;
  return `<!doctype html><html><body style="margin:0;background:#f4f1ea;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1c1917">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea;padding:28px 12px"><tr><td align="center">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:540px;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e7e2d8">
      <tr><td style="background:#121212;padding:22px 28px">
        <div style="font-size:20px;font-weight:800;letter-spacing:.5px;color:#fff">HEART<span style="color:#d85e16">.OS</span></div>
        <div style="font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#9b9b9b;margin-top:2px">Warriors Heart</div>
      </td></tr>
      <tr><td style="padding:28px 28px 8px">
        <h1 style="margin:0 0 10px;font-size:19px;line-height:1.3">${n === 1 ? "An evaluation is coming due" : n + " evaluations are coming due"}.</h1>
        <p style="margin:0 0 6px;font-size:15px;line-height:1.55;color:#44403c">Hi ${who} — ${n === 1 ? "one of your direct reports has an annual performance evaluation" : "your direct reports below have annual performance evaluations"} coming up. These are a Joint Commission requirement, so please get ${n === 1 ? "it" : "them"} on the calendar.</p>
      </td></tr>
      <tr><td style="padding:6px 28px 8px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">${rows}</table></td></tr>
      <tr><td style="padding:14px 28px 6px">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="border-radius:10px;background:#d85e16">
          <a href="${esc(APP_URL)}" style="display:inline-block;padding:12px 24px;font-size:15px;font-weight:700;color:#fff;text-decoration:none;border-radius:10px">Open HEART.OS → Evaluations</a>
        </td></tr></table>
      </td></tr>
      <tr><td style="padding:14px 28px 26px">
        <p style="margin:0;font-size:12px;line-height:1.5;color:#a8a29e">In HEART.OS, go to <b>Evaluations</b> to fill out and submit the review. Reminders repeat weekly until it's filed.</p>
      </td></tr>
      <tr><td style="padding:16px 28px 26px;border-top:1px solid #efeae0"><div style="font-size:11px;color:#a8a29e">Warriors Heart · HEART.OS · automated reminder</div></td></tr>
    </table>
  </td></tr></table></body></html>`;
}

async function getAccessToken(){
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}");
  if(!sa.client_email || !sa.private_key) throw new Error("FIREBASE_SERVICE_ACCOUNT is missing or malformed.");
  const key = await importPKCS8(sa.private_key, "RS256");
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({ scope: "https://www.googleapis.com/auth/datastore" })
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuer(sa.client_email).setSubject(sa.client_email)
    .setAudience("https://oauth2.googleapis.com/token")
    .setIssuedAt(now).setExpirationTime(now + 3600).sign(key);
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion })
  });
  const d = await r.json().catch(() => ({}));
  if(!r.ok || !d.access_token) throw new Error("Service-account token exchange failed: " + (d.error_description || d.error || r.status));
  return d.access_token;
}

async function readCompanyState(token){
  const r = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/workspaces/main`,
    { headers: { authorization: "Bearer " + token } });
  if(!r.ok) throw new Error("Couldn't read the company doc (" + r.status + ")");
  const doc = await r.json();
  return (fsDecode({ mapValue: { fields: doc.fields || {} } }) || {}).state || {};
}

async function sendEmail(to, mgrName, items){
  const from = process.env.INVITE_FROM;
  if(!process.env.RESEND_API_KEY || !from) throw new Error("Email sending isn't configured (RESEND_API_KEY / INVITE_FROM).");
  const subject = items.length === 1
    ? `Evaluation due: ${items[0].name} (${items[0].status.toLowerCase()})`
    : `${items.length} evaluations coming due`;
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { authorization: "Bearer " + process.env.RESEND_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject, html: reminderHtml(mgrName, items) })
  });
  const d = await r.json().catch(() => ({}));
  if(!r.ok) throw new Error((d && (d.message || (d.error && d.error.message))) || ("Email send failed (" + r.status + ")"));
  return d.id;
}

export default async function handler(){
  try{
    const token = await getAccessToken();
    const state = await readCompanyState(token);
    const groups = buildReminders(state, todayIso());
    if(!groups.length){ console.log("eval-reminders: nothing due today."); return new Response("nothing due", { status: 200 }); }
    let sent = 0, failed = 0;
    for(const g of groups){
      try{ await sendEmail(g.email, g.name, g.items); sent++; }
      catch(e){ failed++; console.error("eval-reminders send failed for", g.email, e && e.message); }
    }
    const msg = `eval-reminders: ${sent} supervisor email(s) sent, ${failed} failed, ${groups.length} due group(s).`;
    console.log(msg);
    return new Response(msg, { status: 200 });
  }catch(e){
    console.error("eval-reminders failed:", e && e.message);
    return new Response("error: " + (e && e.message), { status: 500 });
  }
}
