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

## Real-time Voice & Video Calls

B CHAT supports real peer-to-peer voice and video calls over WebRTC.

- The frontend uses `RTCPeerConnection` with public Google STUN servers for NAT traversal (no key required).
- Call signaling (SDP offers/answers + ICE candidates) is relayed through the backend's
  in-memory `/api/calls` endpoints, which the two browsers poll every ~1–2s — no WebSocket needed.
- Incoming calls appear as a native ring with **Accept** / **Decline** buttons.
- Mute, speaker, and flip-camera controls work during a call, and completed calls leave a
  short log message in the conversation.

> **Note:** Calls are ephemeral on the backend, so a call in progress will drop if the server
> restarts. For calls to work across browsers/devices, the frontend's origin must be listed in
> the backend's `ALLOWED_ORIGINS` (or `FRONTEND_ORIGIN`) env vars so CORS allows the polling.

## AI Assistant

The in-app **B AI** assistant works in two modes:

- **Online (default, no key needed):** the backend `/api/ai/chat` route calls the keyless
  [Pollinations](https://github.com/pollinations/pollinations) text API.
- **Online (optional, higher quality/limits):** set a `GEMINI_API_KEY` and the backend will
  call Google Gemini instead of Pollinations.
- **Offline / on any upstream failure:** the frontend automatically falls back to its
  built-in offline assistant (math, jokes, riddles, quotes, translations, etc.).

Optional environment variables:

```env
GEMINI_API_KEY=          # set to use Gemini instead of Pollinations
GEMINI_MODEL=            # optional, default gemini-1.5-flash
AI_MODEL=                # optional, Pollinations model (default openai)
```

Image generation is handled client-side via Pollinations' keyless image API (`image.pollinations.ai`).

## Backend scripts

- `npm start` — starts the Express backend
- `npm run migrate-sqlite-to-supabase` — migrates existing SQLite data into Supabase

## Notes

- Do not commit `backend/.env` or other `.env` files to version control.
- The backend serves the frontend as static files and exposes the API under `/api/*`.
- Supabase is the intended production database, with SQLite kept only for local fallback/testing.
