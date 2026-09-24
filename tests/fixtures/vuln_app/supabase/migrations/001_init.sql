create table profiles ( id uuid primary key, email text, is_admin boolean );
create table todos ( id serial primary key, user_id uuid, content text );
-- FAUTE : aucune activation de RLS sur ces tables
