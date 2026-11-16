// Self-service "email me a sign-in link" for the Warriors Heart EOS app.
//
// WHY THIS EXISTS: Firebase password-reset / set-password links are hard-coded to expire in ~1 hour and
// that window CANNOT be changed (no console setting, no Admin SDK parameter). Staff often don't open the
// invite for a day or two, so the link is dead by the time they click it — and Firebase's own "forgot
// password" email comes from firebaseapp.com, which Microsoft 365 quarantines. This endpoint lets a
// person who is NOT signed in request a FRESH, Warriors Heart-branded link the moment they sit down to
// set up — so the 60-minute clock starts when they're actually ready, not days earlier.
//
// SECURITY: this is a PUBLIC endpoint (first-timers aren't signed in), so it is deliberately narrow:
//   • It can ONLY do one fixed thing — email a standard password-reset link to the address given.
//   • It is rate-limited per IP and per email (best-effort, per warm instance).
//   • It NEVER reveals whether an account exists — an unknown email returns the same generic success as a
//     known one (no account enumeration). A link is generated/sent only when the account already exists.
//   • It uses the service account only to mint the STANDARD reset link (returnOobLink) — the same link the
//     admin invite already sends. No account is created or modified here.
//
// Secrets live ONLY in Netlify env vars — never in the client:
//   FIREBASE_SERVICE_ACCOUNT  the service-account JSON (one line) with Firebase Auth Admin rights
//   RESEND_API_KEY            a Resend API key, sending from a verified Warriors Heart domain
//   INVITE_FROM              e.g.  Warriors Heart <noreply@mail.warriorsheart.com>   (a verified sender)
//   APP_URL                  where they land after setting their password (default warriorsos.netlify.app)
import { importPKCS8, SignJWT } from "jose";

const PROJECT_ID = "wh-operating-system";
const APP_URL = process.env.APP_URL || "https://warriorsos.netlify.app";

function json(status, obj){ return { statusCode: status, headers: { "content-type": "application/json" }, body: JSON.stringify(obj) }; }
function esc(s){ return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

// A generic answer we return in almost every case, so the caller can never tell a real account from a
// typo or a non-member — the message is identical either way.
const GENERIC = "If that email is set up in HEART.OS, a secure sign-in link is on its way — check your inbox (and spam). It's good for 1 hour.";

// Best-effort rate limiting (per warm instance). Two buckets: one per client IP (blunts a spray across many
// addresses) and one per target email (blunts repeatedly bombing one inbox). Bounds abuse without a store.
const IP_MAX = 8, IP_WINDOW_MS = 10 * 60000, _ipHits = new Map();
const EMAIL_MAX = 4, EMAIL_WINDOW_MS = 15 * 60000, _emailHits = new Map();
function bump(map, key, max, windowMs){
  const now = Date.now();
  const arr = (map.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now); map.set(key, arr);
  return arr.length > max;
}
function clientIp(event){
  const h = event.headers || {};
  return (h["x-nf-client-connection-ip"] || (h["x-forwarded-for"] || "").split(",")[0] || "unknown").trim();
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

// Generate the STANDARD web password-reset link WITHOUT Firebase sending its own email. Returns null if the
// account doesn't exist yet (so the caller can stay silent rather than reveal that).
async function generateResetLink(accessToken, email){
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode", {
    method: "POST", headers: { authorization: "Bearer " + accessToken, "content-type": "application/json" },
    body: JSON.stringify({ requestType: "PASSWORD_RESET", email, returnOobLink: true, continueUrl: APP_URL })
  });
  const d = await r.json().catch(() => ({}));
  if(!r.ok){
    const msg = (d.error && d.error.message) || "";
    if(msg.indexOf("EMAIL_NOT_FOUND") >= 0) return null;   // unknown account — stay silent (anti-enumeration)
    const e = new Error(msg || ("Link generation failed (" + r.status + ")")); throw e;
  }
  return d.oobLink;
}

function setupHtml(link){
  return `<!doctype html><html><body style="margin:0;background:#f4f1ea;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1c1917">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea;padding:28px 12px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e7e2d8">
        <tr><td style="background:#121212;padding:22px 28px">
          <div style="font-size:20px;font-weight:800;letter-spacing:.5px;color:#fff">HEART<span style="color:#d85e16">.OS</span></div>
          <div style="font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#9b9b9b;margin-top:2px">Warriors Heart</div>
        </td></tr>
        <tr><td style="padding:30px 28px 10px">
          <h1 style="margin:0 0 10px;font-size:20px;line-height:1.3">Your sign-in link</h1>
          <p style="margin:0 0 16px;font-size:15px;line-height:1.55;color:#44403c">Here's a fresh, secure link to set your password and sign in to <b>HEART.OS</b>. For your security it's good for <b>1 hour</b> — so it's best to open it now while you're here.</p>
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 18px"><tr><td style="border-radius:10px;background:#d85e16">
            <a href="${esc(link)}" style="display:inline-block;padding:13px 26px;font-size:15px;font-weight:700;color:#fff;text-decoration:none;border-radius:10px">Set your password →</a>
          </td></tr></table>
          <p style="margin:0 0 6px;font-size:12.5px;line-height:1.5;color:#78716c">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="margin:0 0 18px;font-size:12px;line-height:1.5;word-break:break-all"><a href="${esc(link)}" style="color:#b4530f">${esc(link)}</a></p>
          <p style="margin:0 0 10px;font-size:12.5px;line-height:1.5;color:#78716c">Expired by the time you open it? No problem — just ask for a new one from the sign-in screen at <a href="${esc(APP_URL)}" style="color:#b4530f">${esc(APP_URL.replace(/^https?:\/\//,""))}</a>.</p>
          <p style="margin:0;font-size:12px;line-height:1.5;color:#a8a29e">If you didn't ask for this, you can ignore this email — no account changes happen until you set a password.</p>
        </td></tr>
        <tr><td style="padding:16px 28px 26px;border-top:1px solid #efeae0"><div style="font-size:11px;color:#a8a29e">Warriors Heart · HEART.OS</div></td></tr>
      </table>
    </td></tr>
  </table></body></html>`;
}

async function sendEmail(to, link){
  const from = process.env.INVITE_FROM;
  if(!process.env.RESEND_API_KEY || !from) throw new Error("Email sending isn't configured (RESEND_API_KEY / INVITE_FROM).");
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { authorization: "Bearer " + process.env.RESEND_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject: "Your HEART.OS sign-in link", html: setupHtml(link) })
  });
  const d = await r.json().catch(() => ({}));
  if(!r.ok) throw new Error((d && (d.message || (d.error && d.error.message))) || ("Email send failed (" + r.status + ")"));
  return d.id;
}

export async function handler(event){
  if(event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  let body;
  try{ body = JSON.parse(event.body || "{}"); }catch(e){ return json(400, { error: "Bad request." }); }
  const email = String(body.email || "").trim().toLowerCase();
  if(!email || email.indexOf("@") < 1 || email.length > 254) return json(400, { error: "Please enter a valid email address." });

  // Rate limit before doing any work. Return the SAME generic success on a per-email trip so a caller can't
  // use the rate limiter itself to probe which addresses exist; a per-IP trip is a hard 429.
  if(bump(_ipHits, clientIp(event), IP_MAX, IP_WINDOW_MS))
    return json(429, { error: "Too many requests from here — wait a few minutes and try again." });
  if(bump(_emailHits, email, EMAIL_MAX, EMAIL_WINDOW_MS))
    return json(200, { ok: true, message: GENERIC });

  try{
    const accessToken = await getAccessToken();
    const link = await generateResetLink(accessToken, email);
    if(link) await sendEmail(email, link);   // only a real account gets an email; unknown emails stay silent
    return json(200, { ok: true, message: GENERIC });
  }catch(e){
    console.error("setup-link failed", e && e.message);
    // Don't leak internals; a generic 502 the UI can show without exposing account state.
    return json(502, { error: "Couldn't send the link just now — please try again in a moment." });
  }
}
