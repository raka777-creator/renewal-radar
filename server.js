import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

// ---------- Config ----------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-in-production";
const DB_URL = process.env.DATABASE_URL;
if (!DB_URL) {
  console.error("DATABASE_URL is not set. Add it in your hosting dashboard.");
  process.exit(1);
}

const pool = new pg.Pool({
  connectionString: DB_URL,
  ssl: /localhost|127\.0\.0\.1/.test(DB_URL) ? false : { rejectUnauthorized: false },
});

await pool.query(`
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS renewals (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vendor TEXT NOT NULL,
  plan TEXT,
  amount NUMERIC(14,2) NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'INR',
  billing_cycle TEXT NOT NULL DEFAULT 'yearly',
  renewal_date DATE NOT NULL,
  auto_renews BOOLEAN NOT NULL DEFAULT true,
  notice_days INT NOT NULL DEFAULT 14,
  owner TEXT,
  notes TEXT,
  last_alert_for DATE,
  created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE renewals ADD COLUMN IF NOT EXISTS decision TEXT NOT NULL DEFAULT 'undecided';
ALTER TABLE users ADD COLUMN IF NOT EXISTS cal_token TEXT UNIQUE;
UPDATE users SET cal_token = md5(random()::text || id::text || clock_timestamp()::text) WHERE cal_token IS NULL;
`);

// ---------- Passwords and sessions (no extra libraries) ----------
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(pw, salt, 64).toString("hex");
}
function checkPw(pw, stored) {
  const [salt, h] = stored.split(":");
  const c = crypto.scryptSync(pw, salt, 64);
  const s = Buffer.from(h, "hex");
  return c.length === s.length && crypto.timingSafeEqual(c, s);
}
const sign = (v) => crypto.createHmac("sha256", SESSION_SECRET).update(v).digest("hex");
function makeCookie(userId) {
  const v = `${userId}.${Date.now() + 7 * 864e5}`;
  return `sid=${v}.${sign(v)}; HttpOnly; Path=/; Max-Age=${7 * 86400}; SameSite=Lax${BASE_URL.startsWith("https") ? "; Secure" : ""}`;
}
function readSession(req) {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return null;
  const [id, exp, sig] = m[1].split(".");
  if (!id || !exp || !sig) return null;
  const good = sign(`${id}.${exp}`);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  if (Date.now() > Number(exp)) return null;
  return Number(id);
}

// ---------- Renewal data helpers ----------
const CYCLES = ["monthly", "quarterly", "yearly"];
const CYCLE_MONTHS = { monthly: 1, quarterly: 3, yearly: 12 };
const DECISIONS = ["undecided", "keep", "cancel", "renegotiate"];
const COLS = `id, vendor, plan, amount::float8 AS amount, currency, billing_cycle,
  renewal_date::text AS renewal_date, auto_renews, notice_days, owner, notes, decision`;

function clean(b, partial) {
  const o = {};
  for (const k of ["vendor", "plan", "currency", "owner", "notes"]) {
    if (b[k] !== undefined) o[k] = b[k] === null ? null : String(b[k]).trim().slice(0, 500);
  }
  if (b.amount !== undefined) {
    const n = Number(b.amount);
    if (!Number.isFinite(n) || n < 0) throw new Error("amount must be a positive number");
    o.amount = n;
  }
  if (b.billing_cycle !== undefined) {
    if (!CYCLES.includes(b.billing_cycle)) throw new Error("billing_cycle must be monthly, quarterly or yearly");
    o.billing_cycle = b.billing_cycle;
  }
  if (b.renewal_date !== undefined) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(b.renewal_date) || isNaN(Date.parse(b.renewal_date)))
      throw new Error("renewal_date must look like 2026-12-31");
    o.renewal_date = b.renewal_date;
  }
  if (b.decision !== undefined) {
    if (!DECISIONS.includes(b.decision)) throw new Error("decision must be undecided, keep, cancel or renegotiate");
    o.decision = b.decision;
  }
  if (b.auto_renews !== undefined) o.auto_renews = b.auto_renews === true || b.auto_renews === "true";
  if (b.notice_days !== undefined) {
    const n = parseInt(b.notice_days, 10);
    if (!Number.isFinite(n) || n < 0 || n > 365) throw new Error("notice_days must be between 0 and 365");
    o.notice_days = n;
  }
  if (typeof o.currency === "string") {
    o.currency = o.currency.toUpperCase().slice(0, 8);
    if (!o.currency) delete o.currency;
  }
  if (!partial && !o.vendor) throw new Error("vendor is required");
  if (!partial && !o.renewal_date) throw new Error("renewal_date is required");
  if (partial && "vendor" in o && !o.vendor) throw new Error("vendor cannot be empty");
  return o;
}

async function listRenewals(userId) {
  const r = await pool.query(`SELECT ${COLS} FROM renewals WHERE user_id=$1 ORDER BY renewal_date ASC, id ASC`, [userId]);
  return r.rows;
}
async function createRenewal(userId, o) {
  const f = { billing_cycle: "yearly", currency: "INR", auto_renews: true, notice_days: 14, amount: 0, decision: "undecided", ...o };
  const r = await pool.query(
    `INSERT INTO renewals (user_id,vendor,plan,amount,currency,billing_cycle,renewal_date,auto_renews,notice_days,owner,notes,decision)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING ${COLS}`,
    [userId, f.vendor, f.plan, f.amount, f.currency, f.billing_cycle, f.renewal_date, f.auto_renews, f.notice_days, f.owner, f.notes, f.decision]
  );
  return r.rows[0];
}
const FIELDS = ["vendor", "plan", "amount", "currency", "billing_cycle", "renewal_date", "auto_renews", "notice_days", "owner", "notes", "decision"];
async function updateRenewal(userId, id, patch) {
  const vals = [userId, id];
  const sets = [];
  for (const f of FIELDS) {
    if (patch[f] !== undefined) {
      vals.push(patch[f]);
      sets.push(`${f}=$${vals.length}`);
    }
  }
  if (!sets.length) throw new Error("Nothing to update");
  sets.push("last_alert_for=NULL");
  const r = await pool.query(`UPDATE renewals SET ${sets.join(", ")} WHERE user_id=$1 AND id=$2 RETURNING ${COLS}`, vals);
  if (!r.rows[0]) throw new Error(`No renewal with id ${id}`);
  return r.rows[0];
}
async function deleteRenewal(userId, id) {
  const r = await pool.query("DELETE FROM renewals WHERE user_id=$1 AND id=$2 RETURNING id", [userId, id]);
  if (!r.rows[0]) throw new Error(`No renewal with id ${id}`);
}

const today = () => Date.parse(new Date().toISOString().slice(0, 10));
const daysUntil = (d) => Math.round((Date.parse(d) - today()) / 864e5);
// Active spend excludes renewals marked "cancel". Those count as money saved per year instead.
function summarize(rows) {
  const by = {};
  const r2 = (n) => Math.round(n * 100) / 100;
  for (const r of rows) {
    const c = (by[r.currency] ||= { currency: r.currency, monthly_total: 0, yearly_total: 0, saved_per_year: 0, active_count: 0, cancelled_count: 0 });
    const monthly = r.amount / CYCLE_MONTHS[r.billing_cycle];
    if (r.decision === "cancel") {
      c.saved_per_year += monthly * 12;
      c.cancelled_count++;
    } else {
      c.monthly_total += monthly;
      c.yearly_total += monthly * 12;
      c.active_count++;
    }
  }
  for (const c of Object.values(by)) {
    c.monthly_total = r2(c.monthly_total);
    c.yearly_total = r2(c.yearly_total);
    c.saved_per_year = r2(c.saved_per_year);
  }
  return Object.values(by);
}

// ---------- Calendar feed (.ics), works in Google Calendar, Outlook and Apple Calendar ----------
const RRULES = { monthly: "FREQ=MONTHLY", quarterly: "FREQ=MONTHLY;INTERVAL=3", yearly: "FREQ=YEARLY" };
const icsText = (s) => String(s ?? "").replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n");
const icsDate = (d) => d.replace(/-/g, "");
const shiftDate = (d, days) => new Date(Date.parse(d + "T00:00:00Z") + days * 864e5).toISOString().slice(0, 10);
function icsFold(line) {
  const out = [];
  while (line.length > 73) {
    out.push(line.slice(0, 73));
    line = " " + line.slice(73);
  }
  out.push(line);
  return out.join("\r\n");
}
function buildCalendar(rows) {
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Renewal Radar//EN",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    "X-WR-CALNAME:Renewal Radar",
    "X-PUBLISHED-TTL:PT1H",
  ];
  const event = (uid, date, summary, description, rrule) => {
    lines.push("BEGIN:VEVENT", `UID:${uid}`, `DTSTAMP:${stamp}`, `DTSTART;VALUE=DATE:${icsDate(date)}`,
      `DTEND;VALUE=DATE:${icsDate(shiftDate(date, 1))}`, `SUMMARY:${icsText(summary)}`, `DESCRIPTION:${icsText(description)}`);
    if (rrule) lines.push(`RRULE:${rrule}`);
    lines.push("TRANSP:TRANSPARENT", "END:VEVENT");
  };
  for (const r of rows) {
    const cost = `${r.currency} ${r.amount}`;
    const cancelled = r.decision === "cancel";
    const rrule = cancelled ? null : RRULES[r.billing_cycle];
    const details = [
      `${r.vendor}${r.plan ? " (" + r.plan + ")" : ""}: ${cost} per ${r.billing_cycle.replace("ly", "")}`,
      `Decision: ${r.decision}`,
      r.owner ? `Owner: ${r.owner}` : "",
      `Edit: ${BASE_URL}/app?edit=${r.id}`,
    ].filter(Boolean).join("\n");
    event(`rr-${r.id}-renew@renewal-radar`, r.renewal_date,
      cancelled ? `Cancel ${r.vendor} before it renews today` : `${r.vendor} renews (${cost})`, details, rrule);
    if (r.notice_days > 0) {
      const lead = {
        undecided: `Decide on ${r.vendor}: keep or cancel?`,
        keep: `Heads up: ${r.vendor}`,
        cancel: `Cancel ${r.vendor} now`,
        renegotiate: `Renegotiate ${r.vendor} now`,
      }[r.decision] || `${r.vendor} renews soon`;
      event(`rr-${r.id}-notice@renewal-radar`, shiftDate(r.renewal_date, -r.notice_days),
        `${lead} (renews in ${r.notice_days} days, ${cost})`, details, rrule);
    }
  }
  lines.push("END:VCALENDAR");
  return lines.map(icsFold).join("\r\n") + "\r\n";
}
const withDays = (r) => ({ ...r, days_left: daysUntil(r.renewal_date), edit_link: `${BASE_URL}/app?edit=${r.id}` });

// ---------- Email alerts (plain HTTP call to Resend; optional) ----------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
async function sendAlerts(onlyUserId) {
  if (!process.env.RESEND_API_KEY) return { sent: 0, note: "Email is not set up (RESEND_API_KEY missing)." };
  const params = [];
  let userFilter = "";
  if (onlyUserId) {
    params.push(onlyUserId);
    userFilter = " AND r.user_id=$1";
  }
  const dedupe = onlyUserId ? "TRUE" : "(r.last_alert_for IS NULL OR r.last_alert_for <> r.renewal_date)";
  const q = await pool.query(
    `SELECT r.id, r.vendor, r.amount::float8 AS amount, r.currency, r.renewal_date::text AS renewal_date, u.email
     FROM renewals r JOIN users u ON u.id = r.user_id
     WHERE r.auto_renews AND r.renewal_date >= CURRENT_DATE
       AND (r.renewal_date - CURRENT_DATE) <= r.notice_days AND ${dedupe}${userFilter}`,
    params
  );
  let sent = 0;
  for (const x of q.rows) {
    const days = daysUntil(x.renewal_date);
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: process.env.ALERT_FROM || "Renewal Radar <onboarding@resend.dev>",
        to: [x.email],
        subject: `${x.vendor} renews in ${days} day${days === 1 ? "" : "s"}`,
        html: `<p><b>${esc(x.vendor)}</b> auto-renews on <b>${esc(x.renewal_date)}</b> for <b>${esc(x.currency)} ${x.amount}</b>.</p>
               <p>Cancel or renegotiate before then. <a href="${BASE_URL}/app?edit=${x.id}">Open in Renewal Radar</a></p>`,
      }),
    });
    if (resp.ok) {
      await pool.query("UPDATE renewals SET last_alert_for=renewal_date WHERE id=$1", [x.id]);
      sent++;
    } else {
      console.error("Resend error:", await resp.text());
    }
  }
  return { sent };
}
setTimeout(() => sendAlerts().catch(console.error), 15000);
setInterval(() => sendAlerts().catch(console.error), 60 * 60 * 1000);

// ---------- MCP server (what Claude talks to) ----------
function buildMcp(user) {
  const server = new McpServer(
    { name: "renewal-radar", version: "1.0.0" },
    {
      instructions:
        "Renewal Radar tracks a company's software and service renewals. When the user shares an invoice, contract, receipt or email about a subscription, extract the vendor, plan, amount, currency, billing cycle and next renewal date and call add_renewal. Always give the user the edit_link from the result so they can review it. Dates must be YYYY-MM-DD. When the user decides to keep, cancel or renegotiate a renewal, call set_decision. Renewals marked cancel count as money saved. spend_summary also returns a calendar_feed link the user can add to Google Calendar, Outlook or Apple Calendar.",
    }
  );
  const ok = (obj) => ({ content: [{ type: "text", text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }] });
  const fail = (e) => ({ isError: true, content: [{ type: "text", text: `Error: ${e.message}` }] });
  const run = (fn) => async (args) => {
    try {
      return ok(await fn(args));
    } catch (e) {
      return fail(e);
    }
  };

  server.registerTool(
    "add_renewal",
    {
      title: "Add a renewal",
      description:
        "Save a subscription or contract renewal. Use after reading an invoice, contract or email. Returns the saved record and a link where the user can review and edit it.",
      inputSchema: {
        vendor: z.string().describe("Company or product, e.g. 'Notion'"),
        renewal_date: z.string().describe("Next renewal date, YYYY-MM-DD"),
        amount: z.number().optional().describe("Amount charged per billing cycle"),
        currency: z.string().optional().describe("3-letter code, e.g. INR, USD. Default INR"),
        billing_cycle: z.enum(["monthly", "quarterly", "yearly"]).optional().describe("Default yearly"),
        plan: z.string().optional().describe("Plan or tier name"),
        auto_renews: z.boolean().optional().describe("Does it renew automatically? Default true"),
        notice_days: z.number().int().optional().describe("Days before renewal to send an alert. Default 14"),
        owner: z.string().optional().describe("Person or team responsible"),
        notes: z.string().optional().describe("Cancellation terms, contract notes, anything useful"),
        decision: z.enum(["undecided", "keep", "cancel", "renegotiate"]).optional().describe("Default undecided"),
      },
    },
    run(async (a) => withDays(await createRenewal(user.id, clean(a, false))))
  );

  server.registerTool(
    "set_decision",
    {
      title: "Keep, cancel or renegotiate",
      description:
        "Record what the team decided about a renewal: keep, cancel, renegotiate, or undecided. Renewals marked cancel stop counting as spend and count as money saved per year. Get the id from list_renewals.",
      inputSchema: {
        id: z.number().int(),
        decision: z.enum(["undecided", "keep", "cancel", "renegotiate"]),
        reason: z.string().optional().describe("Short reason, saved into the notes"),
      },
    },
    run(async ({ id, decision, reason }) => {
      const row = await updateRenewal(user.id, id, { decision });
      if (reason) {
        const line = `Decision (${decision}): ${String(reason).trim().slice(0, 300)}`;
        await pool.query(
          "UPDATE renewals SET notes = CASE WHEN notes IS NULL OR notes = '' THEN $3 ELSE notes || E'\\n' || $3 END WHERE user_id=$1 AND id=$2",
          [user.id, id, line]
        );
        row.notes = row.notes ? row.notes + "\n" + line : line;
      }
      const saved = summarize(await listRenewals(user.id)).map((c) => ({ currency: c.currency, saved_per_year: c.saved_per_year }));
      return { ...withDays(row), total_saved_per_year: saved };
    })
  );

  server.registerTool(
    "list_renewals",
    {
      title: "List all renewals",
      description: "List every tracked renewal, soonest first, with days left and an edit link for each.",
      inputSchema: {},
    },
    run(async () => (await listRenewals(user.id)).map(withDays))
  );

  server.registerTool(
    "upcoming_renewals",
    {
      title: "Renewals coming up",
      description: "List renewals due within the next N days, soonest first.",
      inputSchema: { days: z.number().int().optional().describe("Look-ahead window in days. Default 30") },
    },
    run(async ({ days }) => {
      const n = days ?? 30;
      return (await listRenewals(user.id)).map(withDays).filter((r) => r.days_left >= 0 && r.days_left <= n);
    })
  );

  server.registerTool(
    "update_renewal",
    {
      title: "Update a renewal",
      description: "Change fields on an existing renewal. Get the id from list_renewals. Only send the fields that change.",
      inputSchema: {
        id: z.number().int(),
        vendor: z.string().optional(),
        renewal_date: z.string().optional().describe("YYYY-MM-DD"),
        amount: z.number().optional(),
        currency: z.string().optional(),
        billing_cycle: z.enum(["monthly", "quarterly", "yearly"]).optional(),
        plan: z.string().optional(),
        auto_renews: z.boolean().optional(),
        notice_days: z.number().int().optional(),
        owner: z.string().optional(),
        notes: z.string().optional(),
        decision: z.enum(["undecided", "keep", "cancel", "renegotiate"]).optional(),
      },
    },
    run(async ({ id, ...patch }) => withDays(await updateRenewal(user.id, id, clean(patch, true))))
  );

  server.registerTool(
    "delete_renewal",
    {
      title: "Delete a renewal",
      description: "Permanently remove a renewal by id. Confirm with the user first.",
      inputSchema: { id: z.number().int() },
    },
    run(async ({ id }) => {
      await deleteRenewal(user.id, id);
      return `Deleted renewal ${id}.`;
    })
  );

  server.registerTool(
    "spend_summary",
    {
      title: "Spend summary",
      description:
        "Active recurring spend per currency (monthly and yearly), money saved per year from cancelled renewals, the next 5 renewals, and the user's calendar feed link.",
      inputSchema: {},
    },
    run(async () => {
      const rows = await listRenewals(user.id);
      return {
        dashboard: `${BASE_URL}/app`,
        calendar_feed: `${BASE_URL}/calendar/${user.cal_token}.ics`,
        spend_by_currency: summarize(rows),
        next_five: rows.map(withDays).filter((r) => r.days_left >= 0).slice(0, 5),
      };
    })
  );

  return server;
}

// ---------- Web app ----------
const app = express();
app.use(express.json({ limit: "200kb" }));
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(400).json({ error: e.message });
  });

async function requireUser(req, res, next) {
  try {
    const id = readSession(req);
    if (!id) return res.status(401).json({ error: "Not logged in" });
    const r = await pool.query("SELECT id, email, token, cal_token FROM users WHERE id=$1", [id]);
    if (!r.rows[0]) return res.status(401).json({ error: "Not logged in" });
    req.user = r.rows[0];
    next();
  } catch (e) {
    next(e);
  }
}

app.get("/health", (req, res) => res.send("ok"));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/app", (req, res) => {
  if (!readSession(req)) return res.redirect("/");
  res.sendFile(path.join(__dirname, "app.html"));
});

app.post("/api/signup", wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error("Enter a valid email");
  if (password.length < 6) throw new Error("Password must be at least 6 characters");
  try {
    const r = await pool.query("INSERT INTO users (email, pw_hash, token, cal_token) VALUES ($1,$2,$3,$4) RETURNING id", [
      email,
      hashPw(password),
      crypto.randomBytes(24).toString("hex"),
      crypto.randomBytes(16).toString("hex"),
    ]);
    res.setHeader("Set-Cookie", makeCookie(r.rows[0].id));
    res.json({ ok: true });
  } catch (e) {
    if (e.code === "23505") throw new Error("That email is already registered. Log in instead.");
    throw e;
  }
}));

app.post("/api/login", wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const r = await pool.query("SELECT id, pw_hash FROM users WHERE email=$1", [email]);
  if (!r.rows[0] || !checkPw(String(req.body.password || ""), r.rows[0].pw_hash)) throw new Error("Wrong email or password");
  res.setHeader("Set-Cookie", makeCookie(r.rows[0].id));
  res.json({ ok: true });
}));

app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/me", requireUser, (req, res) =>
  res.json({
    email: req.user.email,
    mcp_url: `${BASE_URL}/mcp/${req.user.token}`,
    calendar_url: `${BASE_URL}/calendar/${req.user.cal_token}.ics`,
  })
);

// Calendar feed: a private link people add to their calendar app. No login, the secret in the link is the key.
app.get("/calendar/:file", async (req, res) => {
  try {
    const token = String(req.params.file).replace(/\.ics$/i, "");
    const u = await pool.query("SELECT id FROM users WHERE cal_token=$1", [token]);
    if (!u.rows[0]) return res.status(404).send("Calendar not found");
    res.set("Content-Type", "text/calendar; charset=utf-8");
    res.set("Content-Disposition", 'inline; filename="renewal-radar.ics"');
    res.set("Cache-Control", "no-cache");
    res.send(buildCalendar(await listRenewals(u.rows[0].id)));
  } catch (e) {
    console.error(e);
    res.status(500).send("Calendar error");
  }
});
app.get("/api/renewals", requireUser, wrap(async (req, res) => res.json({ renewals: await listRenewals(req.user.id) })));
app.post("/api/renewals", requireUser, wrap(async (req, res) => res.json(await createRenewal(req.user.id, clean(req.body, false)))));
app.put("/api/renewals/:id", requireUser, wrap(async (req, res) =>
  res.json(await updateRenewal(req.user.id, Number(req.params.id), clean(req.body, true)))
));
app.delete("/api/renewals/:id", requireUser, wrap(async (req, res) => {
  await deleteRenewal(req.user.id, Number(req.params.id));
  res.json({ ok: true });
}));
app.post("/api/send-alerts", requireUser, wrap(async (req, res) => res.json(await sendAlerts(req.user.id))));

// MCP endpoint: one secret link per customer. Stateless, works on any host.
app.post("/mcp/:token", async (req, res) => {
  try {
    const r = await pool.query("SELECT id, email, cal_token FROM users WHERE token=$1", [req.params.token]);
    if (!r.rows[0]) {
      return res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "Invalid connector link" }, id: null });
    }
    const server = buildMcp(r.rows[0]);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
  }
});
const notAllowed = (req, res) =>
  res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
app.get("/mcp/:token", notAllowed);
app.delete("/mcp/:token", notAllowed);

app.listen(PORT, () => console.log(`Renewal Radar running on ${BASE_URL} (port ${PORT})`));
