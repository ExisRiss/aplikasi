# Login API

Backend login sederhana untuk Pterodactyl. Database **SQLite bawaan Node.js** (`node:sqlite`) — tanpa `npm install` module native, jadi tidak gagal compile di container. Data tersimpan di `data/users.db`.

## Struktur (PENTING)

File wajib berada di **root** container (`/home/container`), bukan di dalam folder:

```
/home/container/
├── package.json
├── .env
├── src/
│   └── server.js
└── data/          (dibuat otomatis)
```

Startup panel memakai `npm start` → `node src/server.js`.

## Instalasi di panel

1. Upload `package.json`, `src/server.js`, `.env` ke root files.
2. Start server — panel otomatis `npm install` lalu jalan.
3. API aktif di port alokasi server (default `.env`: `4154`).

Akun admin dibuat otomatis dari `ADMIN_USERNAME` / `ADMIN_PASSWORD` di `.env` saat pertama jalan. **Ganti password setelah login lewat `/change-password`.**

## Endpoint

- `GET /health`
- `POST /register` — `{ "username", "email", "password" }` (password min 8)
- `POST /login` — `{ "username", "password" }`
- `GET /me` — header `Authorization: Bearer TOKEN`
- `POST /change-password` — header token + `{ "old_password", "new_password" }`

Contoh:

```bash
curl -X POST http://nodedanzyypanelprivate12.pterocloud.my.id:4154/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"PASSWORD_ADMIN"}'
```
