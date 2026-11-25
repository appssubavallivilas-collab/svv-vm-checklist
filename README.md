# VM Checklist (C&B) – <client>
Visual Merchandising checklist app, powered by Consulting & Beyond.

Stack: Google Sheet (database) → Google Cloud service account → Cloudflare Worker (API, R2 photos) → GitHub (source, deploy).

- `public/index.html` the app
- `src/worker.js` API (login, bootstrap, audits, rows, actions, photos)
- `sheet/schema.csv` tabs and columns; the template workbook is VM_Checklist_DB_Template.xlsx
- Secrets are never in this repo: set them with `npx wrangler secret put <NAME>` (see the Cloudflare guide).

Run locally: copy `.dev.vars.example` to `.dev.vars`, fill it, `npm install && npm run dev`.
Owner: C&B delivery lead. Status: starter – `index.html` still uses browser storage until its data layer is switched to `/api/*`.
