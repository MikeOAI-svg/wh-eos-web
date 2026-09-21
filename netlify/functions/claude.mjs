// Server-side AI endpoint for the Warriors Heart EOS app.
// The browser NEVER sees the Anthropic API key — it lives only in Netlify's environment (ANTHROPIC_API_KEY).
// Every request must carry a valid Firebase ID token from a signed-in user of THIS workspace, and may only
// invoke one of the allow-listed tasks below (prompts + token caps are fixed here), so the public URL can't
// be used as an open, bill-draining Claude proxy.
import { createRemoteJWKSet, jwtVerify } from "jose";

const PROJECT_ID = "wh-operating-system";                       // your Firebase project
const ISSUER = `https://securetoken.google.com/${PROJECT_ID}`;
const JWKS = createRemoteJWKSet(new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"));
const MODEL = "claude-sonnet-5";                                // cheap + plenty capable for drafting/summarizing; change to "claude-opus-5" for more power

function json(status, obj){ return { statusCode: status, headers: { "content-type": "application/json" }, body: JSON.stringify(obj) }; }

// ── Allow-listed tasks. The browser only picks a task name and sends structured data; the prompt and the
//    max-token cap for each task live here on the server.
const TASKS = {
  sharpen_rock(p){
    const idea = String(p.idea || "").slice(0, 2000);
    const owner = String(p.owner || "").slice(0, 120);
    const notes = String(p.context || "").slice(0, 2000);
    return {
      maxTokens: 1024,
      system: "You are an expert EOS (Entrepreneurial Operating System / Traction) implementer helping a leadership team write a strong quarterly Rock — a single, specific 90-day priority owned by one person. Favor a concrete, measurable outcome over a vague activity. Reply with ONLY a JSON object — no prose, no markdown, no code fences.",
      user: `Turn this rough Rock idea into a sharp, SMART Rock.\n\nRough idea: ${idea}\nOwner: ${owner || "(unassigned)"}\n${notes ? `Notes already written:\n${notes}\n` : ""}\nReturn JSON shaped EXACTLY like:\n{"title":"<punchy Rock title, 70 chars or fewer>","smart":{"s":"Specific — what exactly will be true","m":"Measurable — the number/target that proves it's done","a":"Achievable — realistic in 90 days","rel":"Relevant — why it matters to the company","t":"Time-bound — the key dates"},"milestones":[{"text":"<checkpoint>"}]}\nGive 3–5 milestones. Keep each SMART field to one or two sentences.`
    };
  },
  l10_minutes(p){
    const team = String(p.teamName || "the team").slice(0, 120);
    const transcript = String(p.transcript || "").slice(0, 12000);
    const rating = String(p.rating || "").slice(0, 40);
    return {
      maxTokens: 1500,
      system: "You are an expert EOS implementer writing the recap of a weekly Level 10 Meeting for a leadership team. Be concise, concrete, and professional; name owners for to-dos. Reply with ONLY a JSON object — no prose, no markdown, no code fences.",
      user: `Write the recap for ${team}'s Level 10 Meeting from these notes.\n\n${transcript || "(no notes were recorded)"}\n\nAverage rating: ${rating || "(n/a)"}\n\nReturn JSON shaped EXACTLY like:\n{"summary":"<5–8 sentence recap: what was decided, what got solved, and the key to-dos with owners>","cascade":"<a short 2–4 sentence Cascading Message the leaders can relay to their departments — only the few things everyone should hear>"}`
    };
  },
  scorecard_insight(p){
    const team = String(p.teamName || "the team").slice(0, 120);
    const quarter = String(p.quarter || "").slice(0, 40);
    const digest = String(p.digest || "").slice(0, 10000);
    return {
      maxTokens: 1200,
      system: "You are an expert EOS implementer reviewing a leadership team's weekly Scorecard. Be concise, concrete, and practical, and never invent numbers you were not given. Reply in PLAIN TEXT — short paragraphs or bullet lines, not JSON.",
      user: `Review ${team}'s Scorecard for ${quarter}. Each measurable lists its weekly actuals with an [on]/[off] status.\n\n${digest || "(no data)"}\n\nIn 6–10 tight lines: (1) which measurables are trending OFF track, and any pattern across them; (2) the most likely story behind the worst one or two; (3) 2–3 specific things to focus on or put on the Issues list. Be actionable — no filler.`
    };
  }
};

// Best-effort per-user rate limit. Netlify function instances are ephemeral, so this bounds a runaway
// client or a single spammer within a warm instance (the most likely abuse); the DURABLE cost guard is
// your Anthropic account spend cap, plus the fixed max_tokens + input caps + task allow-list that already
// bound per-call cost.
const RATE_MAX = 20, RATE_WINDOW_MS = 60000;
const _hits = new Map();   // uid -> recent request timestamps
function rateLimited(uid){
  const now = Date.now();
  const arr = (_hits.get(uid) || []).filter(t => now - t < RATE_WINDOW_MS);
  arr.push(now);
  _hits.set(uid, arr);
  return arr.length > RATE_MAX;
}

export async function handler(event){
  if(event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  // 1) Only a signed-in user of this workspace may spend the API budget.
  const authHeader = event.headers.authorization || event.headers.Authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if(!token) return json(401, { error: "Please sign in first." });
  let claims;
  try{
    const res = await jwtVerify(token, JWKS, { issuer: ISSUER, audience: PROJECT_ID });
    claims = res.payload;
  }catch(e){
    return json(401, { error: "Your session isn't valid — sign in again." });
  }
  const uid = claims && claims.sub;
  if(!uid) return json(401, { error: "Your session isn't valid — sign in again." });   // a real Firebase token always carries a subject
  if(rateLimited(uid)) return json(429, { error: "You're going a bit fast — wait a moment and try again." });

  // 2) Build the Claude request from an allow-listed task.
  let body;
  try{ body = JSON.parse(event.body || "{}"); }catch(e){ return json(400, { error: "Bad request." }); }
  const spec = TASKS[body.task];
  if(!spec) return json(400, { error: "Unknown task." });
  const built = spec(body.payload || {});

  const key = process.env.ANTHROPIC_API_KEY;
  if(!key) return json(500, { error: "AI isn't configured yet (missing API key)." });

  // 3) Call Claude.
  try{
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: MODEL, max_tokens: built.maxTokens, system: built.system, messages: [{ role: "user", content: built.user }] })
    });
    const data = await r.json();
    if(!r.ok){ console.error("anthropic error", r.status, data && data.error); return json(502, { error: "The AI request failed — try again." }); }   // log detail server-side; don't leak upstream text to the browser
    const text = (data.content || []).filter(b => b && b.type === "text").map(b => b.text).join("").trim();
    return json(200, { text });
  }catch(e){
    return json(502, { error: "Couldn't reach the AI service — try again." });
  }
}
