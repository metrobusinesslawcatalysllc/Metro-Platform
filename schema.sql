-- Supabase/PostgreSQL schema for the Metro Platform.
-- Financial balances and positions are simulated application data, not bank or broker custody.

create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create type public.platform_role as enum (
  'SUPER_MASTER',
  'ADMIN_OWNER',
  'SUB_ADMIN',
  'MANAGER',
  'CLIENT'
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  role public.platform_role not null default 'CLIENT',
  parent_id uuid references public.profiles (id) on delete restrict,
  email text,
  created_at timestamptz not null default now(),
  constraint profiles_not_own_parent check (parent_id is distinct from id)
);

create unique index profiles_single_super_master
  on public.profiles (role)
  where role = 'SUPER_MASTER';
create index profiles_parent_id_idx on public.profiles (parent_id);

create table public.accounts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete restrict,
  account_type text not null
    check (account_type in ('CHECKING', 'SAVINGS', 'BROKERAGE')),
  currency text not null
    check (currency ~ '^[A-Z]{3}$'),
  balance numeric(20, 8) not null default 0
    check (balance >= 0),
  status text not null default 'ACTIVE'
    check (status in ('ACTIVE', 'INACTIVE', 'CLOSED')),
  created_at timestamptz not null default now(),
  constraint accounts_id_owner_unique unique (id, owner_id)
);

create index accounts_owner_id_idx on public.accounts (owner_id);

create table public.positions (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete restrict,
  account_id uuid not null,
  symbol text not null check (length(symbol) between 1 and 32),
  quantity numeric(24, 8) not null check (quantity <> 0),
  average_entry_price numeric(24, 8) not null check (average_entry_price > 0),
  updated_at timestamptz not null default now(),
  constraint positions_account_owner_fk
    foreign key (account_id, owner_id)
    references public.accounts (id, owner_id)
    on delete restrict
);

create index positions_owner_id_idx on public.positions (owner_id);
create index positions_account_id_idx on public.positions (account_id);

create table public.deposit_vaults (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete restrict,
  asset text not null check (length(asset) between 2 and 12),
  network text not null check (length(network) between 2 and 32),
  deposit_address text not null check (length(deposit_address) between 8 and 256),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint deposit_vaults_owner_asset_network_unique
    unique (owner_id, asset, network)
);

create index deposit_vaults_owner_id_idx on public.deposit_vaults (owner_id);

-- Audit trail for simulated, same-owner account transfers.
create table public.transfers (
  id uuid primary key default gen_random_uuid(),
  initiated_by uuid not null references public.profiles (id) on delete restrict,
  source_account_id uuid not null,
  destination_account_id uuid not null,
  amount numeric(20, 8) not null check (amount > 0),
  currency text not null check (currency ~ '^[A-Z]{3}$'),
  idempotency_key uuid not null,
  created_at timestamptz not null default now(),
  constraint transfers_distinct_accounts
    check (source_account_id <> destination_account_id),
  constraint transfers_idempotency_unique
    unique (initiated_by, idempotency_key),
  constraint transfers_source_account_fk
    foreign key (source_account_id, initiated_by)
    references public.accounts (id, owner_id)
    on delete restrict,
  constraint transfers_destination_account_fk
    foreign key (destination_account_id, initiated_by)
    references public.accounts (id, owner_id)
    on delete restrict
);

create index transfers_initiated_by_created_at_idx
  on public.transfers (initiated_by, created_at desc);

create or replace function private.can_access_profile(target_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  with recursive descendants(id) as (
    select p.id
    from public.profiles as p
    where p.id = (select auth.uid())

    union

    select child.id
    from public.profiles as child
    join descendants as parent on child.parent_id = parent.id
  )
  select exists (
    select 1
    from public.profiles as actor
    where actor.id = (select auth.uid())
      and (
        actor.role = 'SUPER_MASTER'
        or exists (select 1 from descendants where id = target_id)
      )
  );
$$;

create or replace function private.current_profile_role()
returns public.platform_role
language sql
stable
security definer
set search_path = ''
as $$
  select p.role
  from public.profiles as p
  where p.id = (select auth.uid())
  limit 1;
$$;

revoke all on function private.can_access_profile(uuid) from public, anon;
revoke all on function private.current_profile_role() from public, anon;
grant execute on function private.can_access_profile(uuid) to authenticated;
grant execute on function private.current_profile_role() to authenticated;

create or replace function private.validate_profile_hierarchy()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  parent_role public.platform_role;
begin
  if new.role = 'SUPER_MASTER' then
    if new.parent_id is not null then
      raise exception 'SUPER_MASTER cannot have a parent';
    end if;
  elsif new.role = 'CLIENT' and new.parent_id is null then
    -- Newly registered users remain unassigned until a trusted operator onboards them.
    null;
  else
    if new.parent_id is null then
      raise exception 'This role requires a parent in the role hierarchy';
    end if;

    select p.role
      into parent_role
      from public.profiles as p
      where p.id = new.parent_id;

    if not found then
      raise exception 'Profile parent does not exist';
    end if;

    if not (
      (new.role = 'ADMIN_OWNER' and parent_role = 'SUPER_MASTER')
      or (new.role = 'SUB_ADMIN' and parent_role = 'ADMIN_OWNER')
      or (new.role = 'MANAGER' and parent_role = 'SUB_ADMIN')
      or (new.role = 'CLIENT' and parent_role = 'MANAGER')
    ) then
      raise exception 'Invalid parent role for profile role %', new.role;
    end if;
  end if;

  if tg_op = 'UPDATE' and new.parent_id is not null then
    if exists (
      with recursive ancestors(id) as (
        select new.parent_id
        union
        select p.parent_id
        from public.profiles as p
        join ancestors as a on p.id = a.id
        where p.parent_id is not null
      )
      select 1 from ancestors where id = new.id
    ) then
      raise exception 'Profile hierarchy cannot contain a cycle';
    end if;
  end if;

  return new;
end;
$$;

revoke all on function private.validate_profile_hierarchy() from public, anon, authenticated;

create trigger profiles_validate_hierarchy
  before insert or update on public.profiles
  for each row execute function private.validate_profile_hierarchy();

create or replace function private.create_client_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email, 'CLIENT')
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke all on function private.create_client_profile() from public, anon, authenticated;

create trigger on_auth_user_created_profile
  after insert on auth.users
  for each row execute function private.create_client_profile();

create or replace function public.transfer_between_accounts(
  p_source_account_id uuid,
  p_destination_account_id uuid,
  p_amount numeric,
  p_idempotency_key uuid
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  actor_id uuid := (select auth.uid());
  source_account public.accounts%rowtype;
  destination_account public.accounts%rowtype;
  existing_transfer public.transfers%rowtype;
  transfer_id uuid;
begin
  if actor_id is null then
    raise exception 'Authentication is required';
  end if;

  if p_source_account_id is null
     or p_destination_account_id is null
     or p_source_account_id = p_destination_account_id
     or p_idempotency_key is null
     or p_amount is null
     or p_amount <= 0
     or p_amount <> trunc(p_amount, 8)
     or p_amount >= 1000000000000 then
    raise exception 'Invalid transfer request';
  end if;

  -- Serialize retries with the same key before checking or changing balances.
  perform pg_advisory_xact_lock(
    hashtextextended(actor_id::text || ':' || p_idempotency_key::text, 0)
  );

  select t.*
    into existing_transfer
    from public.transfers as t
    where t.initiated_by = actor_id
      and t.idempotency_key = p_idempotency_key;

  if found then
    if existing_transfer.source_account_id <> p_source_account_id
       or existing_transfer.destination_account_id <> p_destination_account_id
       or existing_transfer.amount <> p_amount then
      raise exception 'Idempotency key was already used for a different transfer';
    end if;
    return existing_transfer.id;
  end if;

  -- Lock both accounts in deterministic order to avoid transfer deadlocks.
  perform a.id
    from public.accounts as a
    where a.id in (p_source_account_id, p_destination_account_id)
      and a.owner_id = actor_id
    order by a.id
    for update;

  select a.*
    into source_account
    from public.accounts as a
    where a.id = p_source_account_id
      and a.owner_id = actor_id;

  select a.*
    into destination_account
    from public.accounts as a
    where a.id = p_destination_account_id
      and a.owner_id = actor_id;

  if source_account.id is null or destination_account.id is null then
    raise exception 'Both accounts must belong to the authenticated user';
  end if;

  if source_account.status <> 'ACTIVE' or destination_account.status <> 'ACTIVE' then
    raise exception 'Both accounts must be active';
  end if;

  if source_account.currency <> destination_account.currency then
    raise exception 'Transfers between different currencies are not supported';
  end if;

  if source_account.balance < p_amount then
    raise exception 'Insufficient balance';
  end if;

  update public.accounts
    set balance = balance - p_amount
    where id = source_account.id;

  update public.accounts
    set balance = balance + p_amount
    where id = destination_account.id;

  insert into public.transfers (
    initiated_by,
    source_account_id,
    destination_account_id,
    amount,
    currency,
    idempotency_key
  )
  values (
    actor_id,
    p_source_account_id,
    p_destination_account_id,
    p_amount,
    source_account.currency,
    p_idempotency_key
  )
  returning id into transfer_id;

  return transfer_id;
end;
$$;

revoke all on function public.transfer_between_accounts(uuid, uuid, numeric, uuid)
  from public, anon;
grant execute on function public.transfer_between_accounts(uuid, uuid, numeric, uuid)
  to authenticated;

alter table public.profiles enable row level security;
alter table public.profiles force row level security;
alter table public.accounts enable row level security;
alter table public.accounts force row level security;
alter table public.positions enable row level security;
alter table public.positions force row level security;
alter table public.deposit_vaults enable row level security;
alter table public.deposit_vaults force row level security;
alter table public.transfers enable row level security;
alter table public.transfers force row level security;

create policy profiles_select_in_scope
  on public.profiles for select to authenticated
  using ((select private.can_access_profile(id)));

create policy accounts_select_in_scope
  on public.accounts for select to authenticated
  using ((select private.can_access_profile(owner_id)));

create policy positions_select_in_scope
  on public.positions for select to authenticated
  using ((select private.can_access_profile(owner_id)));

create policy deposit_vaults_select_in_scope
  on public.deposit_vaults for select to authenticated
  using ((select private.can_access_profile(owner_id)));

create policy deposit_vaults_write_admin_scope
  on public.deposit_vaults for all to authenticated
  using (
    (select private.current_profile_role()) in ('SUPER_MASTER', 'ADMIN_OWNER')
    and (select private.can_access_profile(owner_id))
  )
  with check (
    (select private.current_profile_role()) in ('SUPER_MASTER', 'ADMIN_OWNER')
    and (select private.can_access_profile(owner_id))
  );

create policy transfers_select_in_scope
  on public.transfers for select to authenticated
  using ((select private.can_access_profile(initiated_by)));

revoke all on public.profiles, public.accounts, public.positions,
  public.deposit_vaults, public.transfers from anon, authenticated;

grant select on public.profiles, public.accounts, public.positions,
  public.deposit_vaults, public.transfers to authenticated;
grant insert, update, delete on public.deposit_vaults to authenticated;
grant all on public.profiles, public.accounts, public.positions,
  public.deposit_vaults, public.transfers to service_role;
