create table profiles ( id uuid primary key, email text );
alter table profiles enable row level security;
create policy "own profile" on profiles for select using ( auth.uid() = id );
create table todos ( id serial primary key, user_id uuid, content text );
alter table todos enable row level security;
create policy "own todos" on todos for all using ( auth.uid() = user_id );
