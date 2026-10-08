-- ACM Certificate Portal production schema.
create extension if not exists pgcrypto;

create table if not exists public.acm_certificates (
  id uuid primary key default gen_random_uuid(),
  student_name text not null check (char_length(trim(student_name)) between 2 and 160),
  certificate_code text unique not null check (certificate_code ~ '^ACM-[A-Z2-9]{4}-[A-Z2-9]{4}$'),
  status text not null default 'ACTIVE' check (status in ('ACTIVE', 'REVOKED')),
  created_at timestamptz not null default now(),
  download_count integer not null default 0 check (download_count >= 0),
  last_downloaded_at timestamptz
);

alter table public.acm_certificates enable row level security;
revoke all on public.acm_certificates from anon, authenticated;

-- RLS decides which authenticated rows are allowed; these grants allow the
-- authenticated role to reach the table so the policies can evaluate.
grant select, insert, update on public.acm_certificates to authenticated;

drop policy if exists "admins can read ACM certificates" on public.acm_certificates;
drop policy if exists "admins can create ACM certificates" on public.acm_certificates;
drop policy if exists "admins can update ACM certificates" on public.acm_certificates;
drop function if exists public.get_acm_certificate(text);
drop function if exists public.record_acm_download(uuid);
drop function if exists public.record_acm_download(text);
drop function if exists public.acm_admin_list(text);
drop function if exists public.acm_admin_create(text, text, text);
drop function if exists public.acm_admin_revoke(text, uuid, text);

create policy "admins can read ACM certificates" on public.acm_certificates for select to authenticated
using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
create policy "admins can create ACM certificates" on public.acm_certificates for insert to authenticated
with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
create policy "admins can update ACM certificates" on public.acm_certificates for update to authenticated
using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

create or replace function public.get_acm_certificate(p_code text)
returns table (student_name text, status text)
language sql security definer set search_path = public
as $$ select student_name, status from public.acm_certificates where certificate_code = upper(trim(p_code)) limit 1; $$;
revoke all on function public.get_acm_certificate(text) from public;
grant execute on function public.get_acm_certificate(text) to anon, authenticated;

create or replace function public.record_acm_download(p_code text)
returns void language sql security definer set search_path = public
as $$ update public.acm_certificates set download_count = download_count + 1, last_downloaded_at = now() where certificate_code = upper(trim(p_code)) and status = 'ACTIVE'; $$;
revoke all on function public.record_acm_download(text) from public;
grant execute on function public.record_acm_download(text) to anon, authenticated;

-- After creating the admin in Authentication > Users, set its role once:
-- update auth.users set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"admin"}'::jsonb where id = 'ADMIN-USER-UUID';
