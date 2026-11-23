-- مواهب وفن: إعداد قاعدة البيانات (يُشغَّل مرة واحدة في SQL Editor)
-- يُنشئ الجداول وقواعد الحماية. لا يحتوي أي بيانات.

-- ١) المشرفون
create table public.admins (
  user_id uuid primary key references auth.users on delete cascade
);
alter table public.admins enable row level security;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- ٢) ملفات الموهوبين
create table public.talents (
  id text primary key default gen_random_uuid()::text,
  owner uuid not null default auth.uid() references auth.users on delete cascade,
  name text not null check (char_length(name) between 2 and 40),
  city text not null check (char_length(city) <= 40),
  cat text not null check (char_length(cat) <= 20),
  age text not null check (age in ('kid','teen','youth','adult')),
  skill text not null check (char_length(skill) <= 50),
  descr text not null check (char_length(descr) <= 400),
  level text check (char_length(level) <= 20),
  contact text default '' check (char_length(contact) <= 60),
  av jsonb check (pg_column_size(av) < 120000),
  chal boolean not null default false,
  guard boolean not null default false,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);

-- ٣) الأعمال
create table public.works (
  id text primary key default gen_random_uuid()::text,
  talent_id text not null references public.talents on delete cascade,
  owner uuid not null default auth.uid() references auth.users on delete cascade,
  title text not null check (char_length(title) <= 40),
  img text check (char_length(img) < 400000),
  art jsonb,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);

-- ٤) الطلبات والتعاون
create table public.reqs (
  id text primary key default gen_random_uuid()::text,
  owner uuid not null default auth.uid() references auth.users on delete cascade,
  type text not null check (type in ('req','collab')),
  title text not null check (char_length(title) <= 70),
  cat text not null check (char_length(cat) <= 20),
  city text not null check (char_length(city) <= 40),
  descr text not null check (char_length(descr) <= 300),
  pay text check (char_length(pay) <= 30),
  due date,
  from_name text check (char_length(from_name) <= 40),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);

-- ٥) طلبات استضافة الجهات (يراها المشرف وصاحب الطلب فقط)
create table public.hosts (
  id text primary key default gen_random_uuid()::text,
  owner uuid not null default auth.uid() references auth.users on delete cascade,
  name text not null check (char_length(name) <= 60),
  kind text check (char_length(kind) <= 30),
  city text check (char_length(city) <= 40),
  cat text check (char_length(cat) <= 20),
  idea text check (char_length(idea) <= 80),
  created_at timestamptz not null default now()
);

-- ٦) الإعجاب والاهتمام وتسجيل الحضور والانضمام للقروبات
create table public.reactions (
  kind text not null check (kind in ('likes','interest','rsvp','joins')),
  target text not null check (char_length(target) <= 60),
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  created_at timestamptz not null default now(),
  primary key (kind, target, user_id)
);

-- ٧) إعدادات المنصة
create table public.settings (
  key text primary key,
  value jsonb not null
);

alter table public.talents   enable row level security;
alter table public.works     enable row level security;
alter table public.reqs      enable row level security;
alter table public.hosts     enable row level security;
alter table public.reactions enable row level security;
alter table public.settings  enable row level security;

-- ٨) غير المشرف: كل إضافة تبدأ «بانتظار المراجعة»، وأي تعديل على المحتوى يعيدها للمراجعة
create or replace function public.guard_status() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if tg_op = 'INSERT' then
      new.status := 'pending';
      new.owner := auth.uid();
    else
      new.owner := old.owner;
      if (to_jsonb(new) - 'av' - 'status') is distinct from (to_jsonb(old) - 'av' - 'status') then
        new.status := 'pending';
      else
        new.status := old.status;
      end if;
    end if;
  end if;
  return new;
end $$;

create trigger talents_guard before insert or update on public.talents for each row execute function public.guard_status();
create trigger works_guard   before insert or update on public.works   for each row execute function public.guard_status();
create trigger reqs_guard    before insert or update on public.reqs    for each row execute function public.guard_status();

-- ٩) ملفات الأطفال: موافقة ولي الأمر، ولا وسيلة تواصل، ولا صورة شخصية
create or replace function public.guard_kids() returns trigger
language plpgsql as $$
begin
  if new.age = 'kid' then
    new.guard := true;
    new.contact := '';
    if new.av ? 'img' then new.av := null; end if;
  end if;
  return new;
end $$;
create trigger talents_kids before insert or update on public.talents for each row execute function public.guard_kids();

-- ١٠) قواعد القراءة والكتابة
create policy "admins read own" on public.admins for select to authenticated using (user_id = auth.uid());

create policy "talents read" on public.talents for select using (status = 'approved' or owner = auth.uid() or public.is_admin());
create policy "talents add"  on public.talents for insert to authenticated with check (owner = auth.uid() or public.is_admin());
create policy "talents edit" on public.talents for update to authenticated using (owner = auth.uid() or public.is_admin());
create policy "talents del"  on public.talents for delete to authenticated using (owner = auth.uid() or public.is_admin());

create policy "works read" on public.works for select using (status = 'approved' or owner = auth.uid() or public.is_admin());
create policy "works add"  on public.works for insert to authenticated with check (
  public.is_admin() or (owner = auth.uid() and exists (select 1 from public.talents t where t.id = talent_id and t.owner = auth.uid())));
create policy "works edit" on public.works for update to authenticated using (owner = auth.uid() or public.is_admin());
create policy "works del"  on public.works for delete to authenticated using (owner = auth.uid() or public.is_admin());

create policy "reqs read" on public.reqs for select using (status = 'approved' or owner = auth.uid() or public.is_admin());
create policy "reqs add"  on public.reqs for insert to authenticated with check (owner = auth.uid() or public.is_admin());
create policy "reqs edit" on public.reqs for update to authenticated using (owner = auth.uid() or public.is_admin());
create policy "reqs del"  on public.reqs for delete to authenticated using (owner = auth.uid() or public.is_admin());

create policy "hosts read" on public.hosts for select to authenticated using (owner = auth.uid() or public.is_admin());
create policy "hosts add"  on public.hosts for insert to authenticated with check (owner = auth.uid());
create policy "hosts del"  on public.hosts for delete to authenticated using (public.is_admin());

create policy "reactions read" on public.reactions for select using (true);
create policy "reactions add"  on public.reactions for insert to authenticated with check (user_id = auth.uid());
create policy "reactions del"  on public.reactions for delete to authenticated using (user_id = auth.uid());

create policy "settings read"  on public.settings for select using (true);
create policy "settings write" on public.settings for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- ١١) صلاحيات الوصول من الموقع (الإتاحة التلقائية معطّلة، فنحددها هنا)
grant usage on schema public to anon, authenticated;
grant select on public.talents, public.works, public.reqs, public.reactions, public.settings to anon, authenticated;
grant insert, update, delete on public.talents, public.works, public.reqs, public.reactions, public.settings to authenticated;
grant select, insert, delete on public.hosts to authenticated;
grant select on public.admins to authenticated;
grant execute on function public.is_admin() to anon, authenticated;
