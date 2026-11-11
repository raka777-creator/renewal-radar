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
const COLS = `id, vendor, plan, amount::float8 AS amount, currency, billing_cycle,
  renewal_date::text AS renewal_date, auto_renews, notice_days, owner, notes`;

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
  const f = { billing_cycle: "yearly", currency: "INR", auto_renews: true, notice_days: 14, amount: 0, ...o };
  const r = await pool.query(
    `INSERT INTO renewals (user_id,vendor,plan,amount,currency,billing_cycle,renewal_date,auto_renews,notice_days,owner,notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING ${COLS}`,
    [userId, f.vendor, f.plan, f.amount, f.currency, f.billing_cycle, f.renewal_date, f.auto_renews, f.notice_days, f.owner, f.notes]
  );
  return r.rows[0];
}
const FIELDS = ["vendor", "plan", "amount", "currency", "billing_cycle", "renewal_date", "auto_renews", "notice_days", "owner", "notes"];
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
function summarize(rows) {
  const by = {};
  for (const r of rows) {
    const c = (by[r.currency] ||= { currency: r.currency, monthly_total: 0, yearly_total: 0, count: 0 });
    const monthly = r.amount / CYCLE_MONTHS[r.billing_cycle];
    c.monthly_total += monthly;
    c.yearly_total += monthly * 12;
    c.count++;
  }
  for (const c of Object.values(by)) {
    c.monthly_total = Math.round(c.monthly_total * 100) / 100;
    c.yearly_total = Math.round(c.yearly_total * 100) / 100;
  }
  return Object.values(by);
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
        "Renewal Radar tracks a company's software and service renewals. When the user shares an invoice, contract, receipt or email about a subscription, extract the vendor, plan, amount, currency, billing cycle and next renewal date and call add_renewal. Always give the user the edit_link from the result so they can review it. Dates must be YYYY-MM-DD.",
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
      },
    },
    run(async (a) => withDays(await createRenewal(user.id, clean(a, false))))
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
      description: "Total recurring spend per currency (monthly and yearly equivalent) plus the next 5 renewals.",
      inputSchema: {},
    },
    run(async () => {
      const rows = await listRenewals(user.id);
      return {
        dashboard: `${BASE_URL}/app`,
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
    const r = await pool.query("SELECT id, email, token FROM users WHERE id=$1", [id]);
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
    const r = await pool.query("INSERT INTO users (email, pw_hash, token) VALUES ($1,$2,$3) RETURNING id", [
      email,
      hashPw(password),
      crypto.randomBytes(24).toString("hex"),
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
  res.json({ email: req.user.email, mcp_url: `${BASE_URL}/mcp/${req.user.token}` })
);
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
    const r = await pool.query("SELECT id, email FROM users WHERE token=$1", [req.params.token]);
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
