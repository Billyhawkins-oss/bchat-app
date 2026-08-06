# B CHAT

## Overview

B CHAT is a browser-based chat application with a static frontend and an Express backend. It supports user authentication, direct and group messaging, media attachments, status updates, ads, notifications, and optional Supabase PostgreSQL storage with SQLite fallback.

## Features

- User signup, login, and token-based authentication
- Normal user and admin message handling
- Direct chat and group chat support
- Text messages, photo attachments, voice messages
- Message reactions and message reply support
- Status updates and ads
- Notifications endpoints
- User presence tracking and last-seen status updates
- Supabase PostgreSQL as primary database storage
- SQLite fallback when Supabase env vars are not configured

## Project Structure

- `index.html` — main frontend entrypoint
- `admin.html` — admin dashboard page
- `app.js` — frontend application logic
- `go.css` — app styles
- `backend/` — Express backend server and database adapter
  - `backend/server.js` — API routes and auth logic
  - `backend/db.js` — database adapter for Supabase and SQLite
  - `backend/db-sqlite.js` — SQLite fallback implementation
  - `backend/scripts/migrate-sqlite-to-supabase.js` — migration script for moving SQLite data into Supabase
  - `backend/.env` — local environment variables for Supabase configuration
- `supabase-schema.sql` — Supabase database schema and indexes

## Setup

1. Install backend dependencies:

```bash
cd backend
npm install
```

2. Create `backend/.env` with your Supabase credentials:

```env
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=
```

3. Start the backend server:

```bash
cd backend
npm start
```

The backend will use Supabase when both `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are provided. When those env vars are missing, it falls back to local SQLite.

## Backend scripts

- `npm start` — starts the Express backend
- `npm run migrate-sqlite-to-supabase` — migrates existing SQLite data into Supabase

## Notes

- Do not commit `backend/.env` or other `.env` files to version control.
- The backend serves the frontend as static files and exposes the API under `/api/*`.
- Supabase is the intended production database, with SQLite kept only for local fallback/testing.
