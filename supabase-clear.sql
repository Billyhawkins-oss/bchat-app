-- ═══════════════════════════════════════════════════════
-- B CHAT — Clear all user data (users + messages + statuses)
-- Run this in your Supabase SQL Editor to wipe the database
-- so users can sign up fresh during development.
-- ═══════════════════════════════════════════════════════

-- WARNING: This deletes ALL data permanently! and cannot be undone. Make sure you have backups if needed.

-- 1. Delete all messages
DELETE FROM messages;

-- 2. Delete all statuses
DELETE FROM statuses;

-- 3. Delete all ads / announcements
DELETE FROM ads;

-- 4. Delete all analytics events
DELETE FROM analytics_events;

-- 5. Delete all users (they will sign up fresh)
DELETE FROM users;

-- 6. (Optional) Reset sequences if using them
-- Not needed for standard Supabase setup

-- Done. All data has been cleared.