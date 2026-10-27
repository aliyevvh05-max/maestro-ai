# MAESTRO AI — deployment checklist

The animated frontend is retained. Authentication is Google-only. Each new Google account receives one free AI image; further generations require a paid package. OpenAI image generation runs on the server so visitors never enter or see your API key. Paddle handles checkout and verified payment webhooks.

Packages: Starter $9 / 20 credits, Pro $29 / 100 credits, Studio $49 / 500 credits.

## Run locally
1. Use Node.js 20.18+.
2. Copy `.env.example` to `.env` and set a random `JWT_SECRET` (32+ characters).
3. Add `OPENAI_API_KEY`, Google OAuth credentials, Paddle credentials and the three Paddle price IDs.
4. Run `npm install`, then `npm start` and open `http://localhost:3000`.

## Render setup
- Build command: `npm install`
- Start command: `npm start`
- Attach a persistent disk and set `DATA_DIR` to the disk mount path (for example `/var/data`). Without a persistent disk, SQLite data may be lost during redeploys/restarts.
- Set `BASE_URL` to the exact public HTTPS URL and set `NODE_ENV=production`.
- Set `JWT_SECRET`, `OPENAI_API_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, and all three `PADDLE_PRICE_*` values.
- Google Cloud OAuth authorized redirect URI: `BASE_URL/api/auth/google/callback`.
- Configure Paddle webhook URL `BASE_URL/api/webhook/paddle` and subscribe to `transaction.completed`.
- To accept **card payments only**, configure the payment methods in your Paddle checkout settings accordingly; the server redirects to Paddle and never collects card details itself.
- Use `PADDLE_ENV=sandbox` and sandbox credentials while testing. Switch to production only after checkout and webhook tests pass.

## Before launch
- Test Google sign-in, one free generation, blocked second free generation, all three checkout products, webhook verification and credit granting.
- Never commit `.env`, API keys, OAuth secrets, or Paddle webhook secrets.
- Terms, Privacy and Refund pages include the support contact and Instagram profile.
- SQLite and generated images are stored on the server; use a persistent disk and monitor database size.


Support contact: maestroaisupport@gmail.com
Instagram: https://www.instagram.com/maestro.ai.design/

New Google-authenticated accounts receive exactly one free generation credit. Existing account balances are intentionally not overwritten during deploy, so paid credits are not erased. If an existing test account shows 3 credits, inspect that account in the persistent database or its old browser-local test session before changing it.
