-- ==========================================
-- B CHAT FULL SCHEMA (Supabase PostgreSQL)
-- ==========================================
-- Run this entire file in your Supabase SQL Editor
-- Then set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your backend environment
-- ==========================================

create table if not exists public.users (
  id text primary key,
  username text unique not null,
  email text unique not null,
  display_name text not null,
  avatar text,
  role text not null default 'user',
  code text unique not null,
  created_at timestamptz not null default now(),
  password_hash text not null,
  is_online boolean not null default false,
  last_seen timestamptz,
  e2ee_public_key text,
  security_questions jsonb not null default '[]',
  device_ids jsonb not null default '[]',
  bio text not null default ''
);

create index if not exists users_username_idx on public.users(username);
create index if not exists users_email_idx on public.users(email);

create table if not exists public.messages (
  id text primary key,
  type text not null default 'text',
  sender text not null,
  receiver text,
  group_id text,
  text text,
  photo text,
  voice_data text,
  voice_duration text,
  created_at timestamptz not null default now(),
  is_read boolean not null default false,
  chat_id text,
  forwarded boolean not null default false,
  sender_name text,
  email text,
  reply_to text,
  reactions jsonb
);

create index if not exists messages_sender_receiver_idx on public.messages(sender, receiver);
create index if not exists messages_sender_idx on public.messages(sender);
create index if not exists messages_receiver_idx on public.messages(receiver);
create index if not exists messages_created_at_idx on public.messages(created_at);
create index if not exists messages_chat_id_idx on public.messages(chat_id);
create index if not exists messages_group_id_idx on public.messages(group_id);

create table if not exists public.statuses (
  id text primary key,
  username text not null,
  text text,
  photo text,
  time timestamptz not null default now()
);

create index if not exists statuses_username_idx on public.statuses(username);

create table if not exists public.ads (
  id text primary key,
  username text not null,
  title text not null,
  text text,
  photo text,
  time timestamptz not null default now()
);

create index if not exists ads_username_idx on public.ads(username);

create table if not exists public.groups (
  id text primary key,
  title text not null,
  members jsonb not null default '[]',
  created_by text not null,
  created_at timestamptz not null default now()
);

create index if not exists groups_created_by_idx on public.groups(created_by);
create index if not exists groups_members_gin_idx on public.groups using gin (members);

create table if not exists public.notifications (
  id text primary key,
  title text not null,
  text text,
  created_at timestamptz not null default now()
);

create index if not exists notifications_created_at_idx on public.notifications(created_at);
