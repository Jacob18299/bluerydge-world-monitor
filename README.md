# Bluerydge World Monitor

**Live site: https://bluerydge-world-monitor.pages.dev**

A real-time global threat dashboard. It brings live cyber-security, vulnerability,
geopolitical, defence and infrastructure signals together on one interactive map,
with a regional risk index, a breaking-news ticker and an AI assistant.

## Features

- **Live data, refreshed every 15 minutes:** a scheduled Cloudflare Worker pulls public feeds
  (CISA KEV, NVD, The Hacker News, BleepingComputer, CISA and ACSC advisories, GDELT,
  OpenSky air traffic), normalises them and geolocates each event onto the map.
- **Historical memory:** every run is stored in a Cloudflare D1 (SQL) database, and raw
  snapshots are archived to Cloudflare R2 object storage.
- **Insight notes:** the Worker compares new events with 14–31 days of history and flags
  recurring incidents, regional clusters and air-traffic build-ups against a baseline.
- **AI assistant:** a chat panel backed by Cloudflare Workers AI (Llama 3.3 70B).
- **Fails safely:** if the live feed is ever unavailable, the dashboard falls back to
  built-in sample data, so it never shows a broken page.

## How it's built

| Part | Technology | Location |
| --- | --- | --- |
| Dashboard | Single self-contained HTML/React page on Cloudflare Pages | `index.html` (deployed from `dist/`) |
| Data collector and API | Cloudflare Worker with a cron trigger | `worker/src/index.js` |
| Database schema | Cloudflare D1 (SQLite) | `worker/migrations/0001_init.sql` |
| Config | Wrangler | `worker/wrangler.jsonc` |

### API endpoints (Worker)

- `GET /api/signals`: current events, vulnerabilities and regional risk scores
- `GET /api/sources`: health of each data feed
- `GET /api/insights`: events that carry an insight note
- `POST /api/assistant`: AI assistant chat

## Deploying

```sh
# Dashboard
cp index.html dist/index.html
npx wrangler pages deploy dist --project-name bluerydge-world-monitor --branch main

# Worker
cd worker && npx wrangler deploy
```

Everything runs on Cloudflare's free tier.
