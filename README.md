# B CHAT

## Features

- User authentication with signup and login
- End-to-end encrypted messaging using RSA-OAEP and AES-GCM
- Offline caching for messages and users
- Rich chat UI with support for:
  - text messages
  - photo attachments
  - voice messages
  - group chats
- AI assistant chat endpoint
- Status updates and ads
- User presence and last-seen status
- Supabase fallback support for auth and profile data
- PWA-ready frontend with install prompt support
- Admin dashboard endpoint and admin message handling
- Local SQLite backend storage via `better-sqlite3` (planned)

## Project Structure

- `index.html` — main frontend app shell
- `app.js` — legacy frontend entrypoint
- `js/` — modular frontend helpers and utilities
- `go.css` — app styles
- `backend/` — Express backend server and database code
- `frontend/` — dedicated frontend folder for future static assets and build output

## Notes

- The backend currently uses Express and is designed to migrate from JSON file storage to SQLite.
- Supabase is included as an optional cloud auth/data provider.
- The `frontend/` folder is reserved for future build outputs or separate frontend packaging.
