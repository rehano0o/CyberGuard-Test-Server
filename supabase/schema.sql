-- CyberGuard Test Server schema. Run in the SQL Editor of a NEW, separate Supabase project.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text,
  created_at timestamptz not null default now()
);
create table if not exists public.security_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  event_type text not null check (event_type in ('LOGIN_SUCCESS','FAILED_LOGIN','LOGOUT','TEST_REQUEST','BLOCKED_LOGIN')),
  target text not null,
  description text,
  severity text not null check (severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
  source text not null default 'LOCAL_CLIENT',
  created_at timestamptz not null default now()
);
create index if not exists idx_events_user on public.security_events(user_id);
create index if not exists idx_events_created on public.security_events(created_at desc);
create index if not exists idx_events_type on public.security_events(event_type);

-- Auto-create a profile whenever an Auth user is created.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, email, display_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)));
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
-- Backfill users created before this script ran.
insert into public.profiles(id, email, display_name)
  select id, email, split_part(email,'@',1) from auth.users on conflict do nothing;

-- Row Level Security
alter table public.profiles enable row level security;
alter table public.security_events enable row level security;

create policy "own profile" on public.profiles for select to authenticated using (auth.uid() = id);
create policy "own events" on public.security_events for select to authenticated using (auth.uid() = user_id);
-- Logged-in users may only add events for themselves, and only these types.
create policy "insert own events" on public.security_events for insert to authenticated
  with check (auth.uid() = user_id and event_type in ('LOGIN_SUCCESS','LOGOUT','TEST_REQUEST'));
-- No update/delete policies exist, so events are append-only from the frontend. Privileges are also revoked:
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
revoke all on public.security_events from anon, authenticated;
grant select, insert on public.security_events to authenticated;

-- Failed logins happen BEFORE authentication, so anon cannot insert directly. This function can ONLY
-- create FAILED_LOGIN rows. It links the row to a user if the email belongs to a known profile.
create or replace function public.log_failed_login(p_email text, p_source text) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid;
begin
  select id into uid from public.profiles where lower(email) = lower(coalesce(p_email,'')) limit 1;
  insert into public.security_events(user_id, event_type, target, description, severity, source)
  values (uid, 'FAILED_LOGIN', '/login', 'Failed authentication attempt.', 'MEDIUM',
          left(coalesce(nullif(p_source,''),'LOCAL_CLIENT'), 64));
end $$;
revoke all on function public.log_failed_login(text,text) from public;
grant execute on function public.log_failed_login(text,text) to anon, authenticated;

-- Used by the dashboard "Test Activity" button as a real database round trip.
create or replace function public.server_time() returns timestamptz
language sql stable as $$ select now() $$;
revoke all on function public.server_time() from public, anon;
grant execute on function public.server_time() to authenticated;

