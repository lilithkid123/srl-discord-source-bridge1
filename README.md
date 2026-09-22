# SillyTavern SRL Discord Bridge

A small self-hosted Cloudflare Worker used by SRL to save selected Discord messages into the user's local resource library and, when the user explicitly asks, check a saved Discord source for updates.

The Bridge is intentionally isolated from the SRL application. Each user deploys their own Worker and D1 database in their own Cloudflare account.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https%3A%2F%2Fgithub.com%2Fjixiangruyi117%2FSillyTavern-SRL-Discord-Bridge)

## What it does

```text
Discord Message Context Command
  → your Cloudflare Worker
  → short-lived one-time D1 handoff
  → your local SRL

User taps “检查更新” in SRL
  → your Cloudflare Worker
  → bounded read-only Discord API check
  → comparison / confirmation happens in your local SRL
```

The Worker:

- verifies Discord interaction signatures with Ed25519;
- accepts only the selected message from the Message Context Command;
- stores the normalized capture in D1 under a high-entropy one-time token;
- expires handoffs after a short TTL;
- allows the handoff to be consumed once by SRL;
- performs a bounded, read-only source check only when SRL explicitly requests one;
- does not persist source-refresh responses in D1;
- does not act as a permanent Discord archive.

For a thread/forum source, the refresh read is intentionally bounded and only returns messages relevant to SRL's source model: the starter, messages from the starter author, Bot/Webhook messages, and already-saved message IDs. It does not silently archive arbitrary participant comments.

A user-installed Message Command can save the interaction snapshot even when this Bot is not a member of that community. Automatic refresh is different: it uses `DISCORD_BOT_TOKEN`, so the Bot must be in the guild and able to view the source channel. When that access is absent, the Worker reports the source as temporarily uncheckable instead of claiming that the post was deleted. SRL then uses manual refresh for that source: running the same Message Command again updates the existing local source instead of creating a duplicate.

## Required values

Cloudflare deployment asks for the Discord values belonging to **your own Discord App**:

- `DISCORD_APPLICATION_ID`
- `DISCORD_PUBLIC_KEY`
- `DISCORD_BOT_TOKEN` — store this as a secret
- `SRL_WEB_URL` — optional; useful when opening SRL as a web app / PWA

The D1 binding name is fixed to `DB`.

## Routes

- `POST /interactions` — Discord Interactions Endpoint
- `GET /health` — connection check used by SRL
- `GET /setup/status` — checks the real Discord Message Command registration
- `POST /setup/register` — registers the `保存到资源库` Message Context Command
- `POST /source/read` — authenticated, bounded, read-only source check used by SRL
- `POST /source/messages/check` — checks a bounded batch of explicitly saved message IDs
- `GET /handoff/:token` — one-time SRL handoff
- `GET /open/:token` — opens SRL with the handoff token

Users normally do not need to type these routes. SRL derives them automatically from the Worker root URL.

## Deploy without GitHub / GitLab

SRL also provides a browser-only Cloudflare deployment guide. It generates a Quick Editor version from this same Worker source and adds idempotent D1 schema initialization, so users without a Git account do not need Wrangler or manual SQL.

## Privacy boundary

This repository contains no SRL library data, no Discord credentials and no user content. Credentials are supplied by each user to their own Cloudflare deployment. Discord Message Context Command payloads are kept only long enough to complete the one-time handoff to the user's local SRL. Source-refresh reads are initiated by the user, returned directly to SRL, and are not stored by the Bridge.

## Development

```bash
npm ci
npm run typecheck
```

For a normal Wrangler deployment:

```bash
npm run deploy
```

The deploy script applies D1 migrations and then deploys the Worker.

For automatic deployment, connect this repository to the Worker with Cloudflare Workers Builds,
use `main` as the production branch, `npm run typecheck` as the build command, and
`npm run deploy` as the deploy command. Keep non-production branch deployments disabled unless
you explicitly need preview Workers. Discord credentials remain Cloudflare secrets and must never
be committed to Git.

The production Worker is `srl-discord-source-bridge` at
`https://srl-discord-source-bridge.z3013461603.workers.dev` and follows this repository's `main`
branch through Cloudflare Workers Builds.
