# ZECO Factory CRM – Node.js version (black & red, starts empty)

Khata, bill, gate pass, cheques, reports, users. No npm install needed – no packages at all.

## Needs
- Node.js 22.5 or newer (download the LTS from nodejs.org)

## Run
Open this folder in VS Code, open the terminal (Ctrl + `) and run:

    node server.js

Open http://localhost:3000

## First login
Username `superadmin`. The password is in `data/FIRST_PASSWORD.txt` (created on the first visit).
Log in, set a new password – the file is then deleted.
Forgot it?  `node scripts/reset-admin.js`

## Bill
Type a party name in the Bill tab. If the name is new, saving the bill creates the party and writes the bill into its khata automatically (no need to add the party first). After saving, the party's khata opens.

## Notes
- Data is stored in `data/crm.db` – back it up.
- Other port:  `PORT=4000 node server.js`  (Windows PowerShell: `$env:PORT=4000; node server.js`)
- Open from other devices on the same network:  `HOST=0.0.0.0 node server.js`
- Behind HTTPS / a proxy set `COOKIE_SECURE=1` (and `TRUST_PROXY=1`).
- The first time you run it, Node may print "SQLite is an experimental feature" – this is normal.

## Putting it online (Render / any Node host)
- Start command: `node server.js` (no build step, no npm install).
- Environment variables: `NODE_VERSION=22`, `SUPERADMIN_PASSWORD` (8+ characters, letters and numbers), `COOKIE_SECURE=1`, `TRUST_PROXY=1`.
- Keep the database on a persistent disk and set `DATA_DIR` to the disk's path. Without a disk the data is erased on every restart.
- Never upload `data/`, `.env` or passwords to GitHub (`.gitignore` already skips them).
