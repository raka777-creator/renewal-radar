# Renewal Radar

Track software and vendor renewals straight from Claude. Claude reads your invoices and contracts and does all the thinking. This app stores the data, lets a person review and edit it, and emails alerts before an auto-renewal hits. **There is no AI inside this app: no AI keys, no AI libraries, no AI cost.**

- **Live app:** `https://renewal-radar-msgh.onrender.com`
- **Test login:** `demo@renewalradar.app` / `RenewalDemo2026`

## Connect it to Claude (2 minutes)

You need a Claude plan that supports custom connectors.

1. Open the live app and log in with the test login above.
2. At the top of the dashboard, click **Copy** under "Connect to Claude". That link is the private MCP link for this account.
3. In Claude, open **Settings**, then **Connectors**, then **Add custom connector**.
4. Name it `Renewal Radar`, paste the link, choose **No sign-in** under Authentication, and save. (Menu names can vary slightly by plan and app version.)
5. Start a new chat and make sure the Renewal Radar connector is switched on.

The MCP link looks like `https://<your-app>/mcp/<private-token>`. It uses Streamable HTTP and needs no other login.

## Try it

Type any of these in Claude:

- "Add Notion to Renewal Radar: Team plan, $96 a year, renews on 2026-12-20. Alert me 30 days before."
- "Here's an invoice from Figma [paste text or attach]. Save it as a renewal."
- "What renews in the next 60 days?"
- "How much do we spend on subscriptions per month?"
- "Move the Notion renewal to 2027-01-05."
- "We don't use Zoom any more. Mark it as cancel." (watch "Saved per year" go up)
- "How much have we saved, and what's my calendar link?"
- "Search my Gmail for subscription receipts and add them all." (needs the Gmail connector in Claude)

Claude replies with a link. Open it to see the record in the app, edit any field, and save.

## What Claude can do (MCP tools)

| Tool | What it does |
|---|---|
| `add_renewal` | Saves a renewal read from an invoice, contract or message |
| `list_renewals` | Lists everything, soonest first |
| `upcoming_renewals` | Renewals due in the next N days |
| `update_renewal` | Changes fields on a renewal |
| `delete_renewal` | Removes a renewal |
| `set_decision` | Marks a renewal keep, cancel or renegotiate (cancel counts as money saved) |
| `spend_summary` | Active spend, money saved per year, next five renewals, calendar link |

## What the app does that Claude can't

- Stays live and keeps your data after the chat ends
- Gives a person a dashboard to review and edit what Claude created
- Tracks keep / cancel / renegotiate decisions and shows money saved per year
- Publishes a private calendar feed: every renewal and its decision reminder appear in Google Calendar, Outlook or Apple Calendar and stay in sync
- Emails a reminder before each auto-renewal (hourly check, one email per renewal date; needs a Resend key)

## Tech

Node.js, Express, Postgres, the official MCP SDK. Email uses a plain HTTP call to Resend. Search the code for `openai` or `anthropic`: there are no matches.
