-- VIEWPAY Supabase schema. Run in Supabase SQL Editor.
-- Enable pgcrypto for secure one-time activation-code hashing.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  phone text,
  account_code text unique not null default ('VP-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,10))),
  role text not null default 'advertiser' check (role in ('advertiser','admin')),
  account_status text not null default 'pending' check (account_status in ('pending','active','suspended')),
  available_balance numeric(12,2) not null default 0 check (available_balance >= 0),
  pending_balance numeric(12,2) not null default 0 check (pending_balance >= 0),
  total_paid numeric(12,2) not null default 0 check (total_paid >= 0),
  total_verified_views bigint not null default 0 check (total_verified_views >= 0),
  registration_fee_refunded boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.activation_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash text unique not null,
  intended_user uuid references auth.users(id) on delete set null,
  expires_at timestamptz not null,
  redeemed_by uuid references auth.users(id),
  redeemed_at timestamptz,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.view_submissions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  claimed_views integer not null check (claimed_views between 20 and 10000),
  verified_views integer check (verified_views between 20 and 10000),
  evidence_path text not null,
  notes text,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  admin_note text,
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.withdrawal_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  amount numeric(12,2) not null check (amount > 0),
  phone text not null,
  status text not null default 'pending' check (status in ('pending','paid','rejected')),
  admin_note text,
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.support_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  sender_role text not null default 'advertiser' check (sender_role in ('advertiser','admin')),
  message text not null check (char_length(message) between 1 and 4000),
  created_at timestamptz not null default now()
);

create table if not exists public.ledger (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  entry_type text not null check (entry_type in ('earning','withdrawal','registration_refund','adjustment')),
  amount numeric(12,2) not null,
  reference_id uuid,
  description text not null,
  created_at timestamptz not null default now()
);

-- Create profile automatically on signup.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public as $$
begin
 insert into public.profiles(id,full_name,phone)
 values(new.id, coalesce(new.raw_user_meta_data->>'full_name',''), coalesce(new.raw_user_meta_data->>'phone',''));
 return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from public.profiles where id=auth.uid() and role='admin');
$$;

alter table public.profiles enable row level security;
alter table public.activation_codes enable row level security;
alter table public.view_submissions enable row level security;
alter table public.withdrawal_requests enable row level security;
alter table public.support_messages enable row level security;
alter table public.ledger enable row level security;

-- Profiles: users can view their own profile and update only contact/profile fields.
drop policy if exists "profile select own or admin" on public.profiles;
create policy "profile select own or admin" on public.profiles for select to authenticated
using (id=auth.uid() or public.is_admin());
drop policy if exists "profile update own" on public.profiles;
create policy "profile update own" on public.profiles for update to authenticated
using (id=auth.uid()) with check (id=auth.uid() and role='advertiser'
 and account_status in ('pending','active','suspended')
 and available_balance >= 0 and pending_balance >= 0
 and total_paid >= 0 and total_verified_views >= 0);
-- Do not grant client updates to sensitive columns; use column-level grants.
revoke update on public.profiles from authenticated;
grant update(full_name,phone) on public.profiles to authenticated;

drop policy if exists "codes admin only" on public.activation_codes;
create policy "codes admin only" on public.activation_codes for select to authenticated using(public.is_admin());

drop policy if exists "submissions read own or admin" on public.view_submissions;
create policy "submissions read own or admin" on public.view_submissions for select to authenticated using(user_id=auth.uid() or public.is_admin());
drop policy if exists "submissions insert own active" on public.view_submissions;
create policy "submissions insert own active" on public.view_submissions for insert to authenticated with check(user_id=auth.uid() and status='pending' and verified_views is null and exists(select 1 from public.profiles p where p.id=auth.uid() and p.account_status='active'));
revoke update, delete on public.view_submissions from authenticated;

drop policy if exists "withdrawals read own or admin" on public.withdrawal_requests;
create policy "withdrawals read own or admin" on public.withdrawal_requests for select to authenticated using(user_id=auth.uid() or public.is_admin());
drop policy if exists "withdrawals insert own active" on public.withdrawal_requests;
create policy "withdrawals insert own active" on public.withdrawal_requests for insert to authenticated with check(user_id=auth.uid() and status='pending' and exists(select 1 from public.profiles p where p.id=auth.uid() and p.account_status='active' and p.available_balance>=amount));
revoke update, delete on public.withdrawal_requests from authenticated;

drop policy if exists "messages participant read" on public.support_messages;
create policy "messages participant read" on public.support_messages for select to authenticated using(user_id=auth.uid() or public.is_admin());
drop policy if exists "messages participant insert" on public.support_messages;
create policy "messages participant insert" on public.support_messages for insert to authenticated with check(
 sender_id=auth.uid() and (user_id=auth.uid() or public.is_admin()) and
 ((public.is_admin() and sender_role='admin') or (not public.is_admin() and sender_role='advertiser' and user_id=auth.uid()))
);
revoke update, delete on public.support_messages from authenticated;

drop policy if exists "ledger own or admin" on public.ledger;
create policy "ledger own or admin" on public.ledger for select to authenticated using(user_id=auth.uid() or public.is_admin());
revoke insert, update, delete on public.ledger from authenticated;

-- Private screenshot bucket. Users can upload only under their own auth UID folder.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('view-evidence','view-evidence',false,5242880,array['image/jpeg','image/png','image/webp'])
on conflict(id) do nothing;
drop policy if exists "evidence upload own folder" on storage.objects;
create policy "evidence upload own folder" on storage.objects for insert to authenticated
with check(bucket_id='view-evidence' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "evidence read owner or admin" on storage.objects;
create policy "evidence read owner or admin" on storage.objects for select to authenticated
using(bucket_id='view-evidence' and ((storage.foldername(name))[1]=auth.uid()::text or public.is_admin()));

-- Redeem a one-time code. Code is hashed; raw code is never stored.
create or replace function public.redeem_activation_code(p_code text)
returns boolean language plpgsql security definer set search_path=public as $$
declare c public.activation_codes%rowtype;
begin
 if auth.uid() is null then raise exception 'Sign in required'; end if;
 select * into c from public.activation_codes
 where code_hash=encode(digest(upper(trim(p_code)),'sha256'),'hex')
 for update;
 if not found or c.redeemed_at is not null or c.expires_at<now()
    or (c.intended_user is not null and c.intended_user<>auth.uid()) then
   raise exception 'Invalid, expired, or already-used activation code';
 end if;
 update public.activation_codes set redeemed_by=auth.uid(),redeemed_at=now() where id=c.id;
 update public.profiles set account_status='active' where id=auth.uid() and account_status='pending';
 if not found then raise exception 'Account cannot be activated'; end if;
 return true;
end; $$;

create or replace function public.admin_generate_activation_code(p_valid_days integer default 7)
returns text language plpgsql security definer set search_path=public as $$
declare raw_code text;
begin
 if not public.is_admin() then raise exception 'Admin access required'; end if;
 if p_valid_days<1 or p_valid_days>30 then raise exception 'Validity must be 1–30 days'; end if;
 raw_code='VP-'||upper(substr(encode(gen_random_bytes(8),'hex'),1,12));
 insert into public.activation_codes(code_hash,expires_at,created_by)
 values(encode(digest(raw_code,'sha256'),'hex'),now()+make_interval(days=>p_valid_days),auth.uid());
 return raw_code;
end; $$;

-- Approving views credits earnings only once; first payout refund is handled at payout time.
create or replace function public.admin_review_submission(p_submission_id uuid,p_approve boolean,p_verified_views integer default 0,p_note text default '')
returns void language plpgsql security definer set search_path=public as $$
declare s public.view_submissions%rowtype; earn numeric(12,2);
begin
 if not public.is_admin() then raise exception 'Admin access required'; end if;
 select * into s from public.view_submissions where id=p_submission_id for update;
 if not found or s.status<>'pending' then raise exception 'Submission not found or already reviewed'; end if;
 if p_approve and (p_verified_views<20 or p_verified_views>10000 or p_verified_views>s.claimed_views) then raise exception 'Invalid verified view count'; end if;
 if p_approve then
  earn=p_verified_views*2;
  update public.profiles set pending_balance=pending_balance+earn,total_verified_views=total_verified_views+p_verified_views where id=s.user_id;
  insert into public.ledger(user_id,entry_type,amount,reference_id,description)
  values(s.user_id,'earning',earn,s.id,'Verified advertising views; pending payout review');
 end if;
 update public.view_submissions set status=case when p_approve then 'approved' else 'rejected' end,
 verified_views=case when p_approve then p_verified_views else null end,
 admin_note=p_note,reviewed_by=auth.uid(),reviewed_at=now() where id=s.id;
end; $$;

-- Withdrawal approval: reserve available funds at request creation via atomic RPC is preferred.
-- This trigger atomically reserves funds when a withdrawal is requested.
create or replace function public.reserve_withdrawal()
returns trigger language plpgsql security definer set search_path=public as $$
begin
 update public.profiles set available_balance=available_balance-new.amount
 where id=new.user_id and account_status='active' and available_balance>=new.amount;
 if not found then raise exception 'Insufficient available balance or inactive account'; end if;
 return new;
end; $$;
drop trigger if exists reserve_withdrawal_before_insert on public.withdrawal_requests;
create trigger reserve_withdrawal_before_insert before insert on public.withdrawal_requests
for each row execute function public.reserve_withdrawal();

create or replace function public.admin_review_withdrawal(p_request_id uuid,p_approve boolean,p_note text default '')
returns void language plpgsql security definer set search_path=public as $$
declare w public.withdrawal_requests%rowtype;
begin
 if not public.is_admin() then raise exception 'Admin access required'; end if;
 select * into w from public.withdrawal_requests where id=p_request_id for update;
 if not found or w.status<>'pending' then raise exception 'Request not found or already reviewed'; end if;
 if p_approve then
  update public.profiles set total_paid=total_paid+w.amount where id=w.user_id;
  insert into public.ledger(user_id,entry_type,amount,reference_id,description)
  values(w.user_id,'withdrawal',-w.amount,w.id,'Withdrawal marked paid: '||coalesce(p_note,''));
  update public.withdrawal_requests set status='paid' where id=w.id;
 else
  update public.profiles set available_balance=available_balance+w.amount where id=w.user_id;
  update public.withdrawal_requests set status='rejected' where id=w.id;
 end if;
 update public.withdrawal_requests set admin_note=p_note,reviewed_by=auth.uid(),reviewed_at=now() where id=w.id;
end; $$;

-- Release pending earnings to available balance only through an admin-controlled payout workflow.
create or replace function public.admin_release_pending(p_user_id uuid,p_amount numeric)
returns void language plpgsql security definer set search_path=public as $$
begin
 if not public.is_admin() then raise exception 'Admin access required'; end if;
 if p_amount<=0 then raise exception 'Amount must be positive'; end if;
 update public.profiles set pending_balance=pending_balance-p_amount,available_balance=available_balance+p_amount
 where id=p_user_id and pending_balance>=p_amount;
 if not found then raise exception 'Insufficient pending balance'; end if;
 insert into public.ledger(user_id,entry_type,amount,description)
 values(p_user_id,'adjustment',p_amount,'Verified earnings released to available balance');
end; $$;

grant execute on function public.redeem_activation_code(text) to authenticated;
grant execute on function public.admin_generate_activation_code(integer) to authenticated;
grant execute on function public.admin_review_submission(uuid,boolean,integer,text) to authenticated;
grant execute on function public.admin_review_withdrawal(uuid,boolean,text) to authenticated;
grant execute on function public.admin_release_pending(uuid,numeric) to authenticated;

-- Table privileges required by the Supabase client; RLS above still controls each row.
grant select on public.profiles to authenticated;
grant update(full_name,phone) on public.profiles to authenticated;
grant select on public.activation_codes to authenticated;
grant select, insert on public.view_submissions to authenticated;
grant select, insert on public.withdrawal_requests to authenticated;
grant select, insert on public.support_messages to authenticated;
grant select on public.ledger to authenticated;

-- IMPORTANT: Promote your own account to admin manually after signing up:
-- update public.profiles set role='admin' where id=(select id from auth.users where email='YOUR_ADMIN_EMAIL');
-- Do this only in the Supabase SQL editor as project owner.
