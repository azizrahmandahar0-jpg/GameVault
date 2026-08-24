# GameVault — Full Stack

A complete local/full-stack marketplace for manually published Free Fire / PUBG Mobile IDs.

## Features
- Public storefront: only IDs published by admin appear.
- Each listing supports title, game, level, rank, price, stock, full description, image and video.
- Buyer order form.
- Admin login.
- Admin dashboard with listing CRUD and order status management.
- SQLite database.
- Image/video uploads using Multer.
- Session-based admin authentication.
- No real payment processing or game credentials are stored by default.

## Run
1. Install Node.js 18+.
2. Open this folder in a terminal.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

## Default admin
- Username: `admin`
- Password: `admin123`

Change these before deployment by setting:
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `SESSION_SECRET`

Example:
```bash
ADMIN_USERNAME=myadmin ADMIN_PASSWORD=strong-password SESSION_SECRET=long-random-secret npm start
```

## Production notes
Use HTTPS, a reverse proxy, a strong session secret, a real admin password, backups, and a proper payment provider if you later add payments. Do not put game passwords or recovery codes in public listing descriptions.

## Admin credentials upgrade

The upgraded version includes an **Admin Login Settings** panel.

1. Start the website with `npm start`.
2. Open `http://localhost:3000`.
3. Open **Admin** and log in.
4. In **Admin Login Settings**, enter the new username, your current password, and (optionally) a new password twice.
5. Click **Save Login Settings**. You will be logged out automatically and must log in again with the new credentials.

Password is stored as a salted scrypt hash in the SQLite database; the plain password is not stored.

Default credentials for a fresh install remain:
- Username: `admin`
- Password: `admin123`

If you already have an existing `data/gamevault.db`, the upgrade keeps the existing admin settings when the new settings table is created.
