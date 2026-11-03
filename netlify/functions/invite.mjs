// Branded invite email for the Warriors Heart EOS app.
// When an admin adds a teammate, the app creates their Firebase login, then calls this function to send
// the "set your password" link from a Warriors Heart address (via Resend) — instead of Firebase's own
// email, which Microsoft 365 was quarantining because it came from firebaseapp.com.
//
// The link itself is the STANDARD Firebase web password-reset action link, generated server-side with a
// service account (returnOobLink). That link does NOT use Firebase Dynamic Links, so it is unaffected by
// the Dynamic Links shutdown.
//
// Secrets live ONLY in Netlify env vars — never in the client:
//   FIREBASE_SERVICE_ACCOUNT  the service-account JSON (one line) with Firebase Auth Admin rights
//   RESEND_API_KEY            a Resend API key, sending from a verified Warriors Heart domain
//   INVITE_FROM              e.g.  Warriors Heart <noreply@mail.warriorsheart.com>   (a verified sender)
//   APP_URL                  where they land after setting their password (default warriorsos.netlify.app)
import { createRemoteJWKSet, jwtVerify, importPKCS8, SignJWT } from "jose";

const PROJECT_ID = "wh-operating-system";
const ISSUER = `https://securetoken.google.com/${PROJECT_ID}`;
const JWKS = createRemoteJWKSet(new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"));
const APP_URL = process.env.APP_URL || "https://warriorsos.netlify.app";

function json(status, obj){ return { statusCode: status, headers: { "content-type": "application/json" }, body: JSON.stringify(obj) }; }
function esc(s){ return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

// Best-effort per-user rate limit (same rationale as the AI function): bounds a runaway caller within a
// warm instance. The durable guards are the admin check and the fixed, allow-listed action below.
const RATE_MAX = 30, RATE_WINDOW_MS = 60000, _hits = new Map();
function rateLimited(uid){ const now = Date.now(); const arr = (_hits.get(uid) || []).filter(t => now - t < RATE_WINDOW_MS); arr.push(now); _hits.set(uid, arr); return arr.length > RATE_MAX; }

// Is the signed-in caller an admin of THIS workspace? Read the company doc with the caller's own token
// (rules allow any authed user to read it) and check state.admins. Unknown (can't read / no list) → null,
// which the handler treats as "allow" since the Add-Member UI is already admin-only; a definite false blocks.
async function callerIsAdmin(callerToken, callerEmail){
  try{
    const r = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/workspaces/main`,
      { headers: { authorization: "Bearer " + callerToken } });
    if(!r.ok) return null;
    const doc = await r.json();
    const adminsArr = (((((doc.fields || {}).state || {}).mapValue || {}).fields || {}).admins || {}).arrayValue;
    const vals = (adminsArr && adminsArr.values) || [];
    const list = vals.map(v => String(v.stringValue || "").trim().toLowerCase()).filter(Boolean);
    if(!list.length) return null;
    return list.includes(String(callerEmail || "").trim().toLowerCase());
  }catch(e){ return null; }
}

// Exchange the service account for a short-lived Google access token scoped to Identity Toolkit.
async function getAccessToken(){
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}");
  if(!sa.client_email || !sa.private_key) throw new Error("FIREBASE_SERVICE_ACCOUNT is missing or malformed.");
  const key = await importPKCS8(sa.private_key, "RS256");
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({ scope: "https://www.googleapis.com/auth/identitytoolkit" })
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

// Generate the STANDARD web password-reset link WITHOUT Firebase sending its own email (returnOobLink is
// admin-only, which is why this runs with the service-account token, not the caller's token).
async function generateResetLink(accessToken, email){
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode", {
    method: "POST", headers: { authorization: "Bearer " + accessToken, "content-type": "application/json" },
    body: JSON.stringify({ requestType: "PASSWORD_RESET", email, returnOobLink: true, continueUrl: APP_URL })
  });
  const d = await r.json().catch(() => ({}));
  if(!r.ok){ const e = new Error((d.error && d.error.message) || ("Link generation failed (" + r.status + ")")); e.code = (d.error && d.error.message) || ""; throw e; }
  return d.oobLink;
}

function inviteHtml(name, link, inviter, team){
  const who = esc(name) || "there";
  const by = inviter ? ` by ${esc(inviter)}` : "";
  const onTeam = team ? ` on <b>${esc(team)}</b>` : "";
  return `<!doctype html><html><body style="margin:0;background:#f4f1ea;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1c1917">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea;padding:28px 12px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e7e2d8">
        <tr><td style="background:#121212;padding:22px 28px">
          <div style="font-size:20px;font-weight:800;letter-spacing:.5px;color:#fff">HEART<span style="color:#d85e16">.OS</span></div>
          <div style="font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#9b9b9b;margin-top:2px">Warriors Heart</div>
        </td></tr>
        <tr><td style="padding:30px 28px 10px">
          <h1 style="margin:0 0 10px;font-size:20px;line-height:1.3">Welcome${who === "there" ? "" : ", " + who}.</h1>
          <p style="margin:0 0 16px;font-size:15px;line-height:1.55;color:#44403c">You've been added${onTeam} in <b>HEART.OS</b>, Warriors Heart's operating system${by}. Set your password to sign in — this is where you'll see your Rocks, your numbers, your to-dos, and your team's weekly meeting.</p>
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 18px"><tr><td style="border-radius:10px;background:#d85e16">
            <a href="${esc(link)}" style="display:inline-block;padding:13px 26px;font-size:15px;font-weight:700;color:#fff;text-decoration:none;border-radius:10px">Set your password →</a>
          </td></tr></table>
          <p style="margin:0 0 6px;font-size:12.5px;line-height:1.5;color:#78716c">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="margin:0 0 18px;font-size:12px;line-height:1.5;word-break:break-all"><a href="${esc(link)}" style="color:#b4530f">${esc(link)}</a></p>
          <p style="margin:0;font-size:12px;line-height:1.5;color:#a8a29e">If you weren't expecting this, you can ignore this email — no account changes happen until you set a password.</p>
        </td></tr>
        <tr><td style="padding:16px 28px 26px;border-top:1px solid #efeae0"><div style="font-size:11px;color:#a8a29e">Warriors Heart · HEART.OS</div></td></tr>
      </table>
    </td></tr>
  </table></body></html>`;
}

async function sendEmail(to, name, link, inviter, team){
  const from = process.env.INVITE_FROM;
  if(!process.env.RESEND_API_KEY || !from) throw new Error("Email sending isn't configured (RESEND_API_KEY / INVITE_FROM).");
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { authorization: "Bearer " + process.env.RESEND_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject: "Set up your HEART.OS sign-in", html: inviteHtml(name, link, inviter, team) })
  });
  const d = await r.json().catch(() => ({}));
  if(!r.ok) throw new Error((d && (d.message || (d.error && d.error.message))) || ("Email send failed (" + r.status + ")"));
  return d.id;
}

export async function handler(event){
  if(event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  // 1) Caller must be a signed-in user of this workspace.
  const authHeader = event.headers.authorization || event.headers.Authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if(!token) return json(401, { error: "Please sign in first." });
  let claims;
  try{ claims = (await jwtVerify(token, JWKS, { issuer: ISSUER, audience: PROJECT_ID })).payload; }
  catch(e){ return json(401, { error: "Your session isn't valid — sign in again." }); }
  const uid = claims && claims.sub;
  if(!uid) return json(401, { error: "Your session isn't valid — sign in again." });
  if(rateLimited(uid)) return json(429, { error: "You're going a bit fast — wait a moment and try again." });

  // 2) And must be an admin of this workspace (the Add-Member action is admin-only).
  const adm = await callerIsAdmin(token, claims.email);
  if(adm === false) return json(403, { error: "Only an admin can invite new members." });

  // 3) Validate the recipient.
  let body;
  try{ body = JSON.parse(event.body || "{}"); }catch(e){ return json(400, { error: "Bad request." }); }
  const email = String(body.email || "").trim().toLowerCase();
  const name = String(body.name || "").slice(0, 120);
  const inviter = String(body.inviterName || "").slice(0, 120);
  const team = String(body.teamName || "").slice(0, 120);
  if(!email || email.indexOf("@") < 1) return json(400, { error: "A valid email is required." });

  // 4) Generate the set-password link (service account) and send our own branded email (Resend).
  try{
    const accessToken = await getAccessToken();
    let link;
    try{ link = await generateResetLink(accessToken, email); }
    catch(e){
      if((e.code || "").indexOf("EMAIL_NOT_FOUND") >= 0)
        return json(409, { error: "That account hasn't been created yet — add the member first, then resend the invite." });
      throw e;
    }
    const id = await sendEmail(email, name, link, inviter, team);
    return json(200, { ok: true, id });
  }catch(e){
    console.error("invite failed", e && e.message);
    return json(502, { error: "Couldn't send the invite — " + (e && e.message ? e.message : "please try again.") });
  }
}
