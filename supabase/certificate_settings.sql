-- Global ACM certificate text settings.
create table if not exists public.certificate_settings (
  id text primary key default 'global' check (id = 'global'),
  name_font_size numeric not null default 54 check (name_font_size between 12 and 300),
  name_font_family text not null default 'Georgia',
  name_font_weight text not null default '700',
  name_color text not null default '#075a3a',
  name_align text not null default 'center' check (name_align in ('left', 'center', 'right')),
  name_x numeric not null default 0.5 check (name_x between 0 and 1),
  name_y numeric not null default 0.43 check (name_y between 0 and 1),
  name_rotation numeric not null default 0,
  name_letter_spacing numeric not null default 0,
  name_line_height numeric not null default 1,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id)
);

alter table public.certificate_settings enable row level security;
revoke all on public.certificate_settings from anon, authenticated;
grant select on public.certificate_settings to anon, authenticated;
grant insert, update on public.certificate_settings to authenticated;

drop policy if exists "public can read certificate settings" on public.certificate_settings;
drop policy if exists "admins can create certificate settings" on public.certificate_settings;
drop policy if exists "admins can update certificate settings" on public.certificate_settings;

create policy "public can read certificate settings"
on public.certificate_settings for select to anon, authenticated
using (true);

create policy "admins can create certificate settings"
on public.certificate_settings for insert to authenticated
with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

create policy "admins can update certificate settings"
on public.certificate_settings for update to authenticated
using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

insert into public.certificate_settings (id)
values ('global')
on conflict (id) do nothing;
