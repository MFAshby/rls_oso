--drop function if exists oso_is_allowed cascade;
drop table public.comments cascade;
drop user foo;

create extension rls_oso;

-- Setup a sample table to work with, with some data.
CREATE TABLE public.comments (
    url text NOT NULL,
    author text NOT NULL,
    comment text NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL
);

insert into public.comments (url, author, comment, ts) values
('https://mfashby.net/foo', 'martin', 'hereis a comment!', '2022-12-27 22:08:34.139495+00'),
('foo', 'martin',  'hereis a comment!', '2022-12-27 22:47:33.977449+00'),
('foo', 'martin', 'I have something to say you know', '2022-12-27 23:21:46.542678+00'),
('foo', 'martin', 'I have something to say you know', '2022-12-27 23:21:49.283261+00'),
('foo', 'foo', 'foo! foo, foo. Foo.', '2022-12-27 23:25:49.283261+00');

CREATE INDEX idx_comments_url ON public.comments USING btree (url);

-- setup row level security policies.
-- these should be uniform
-- in fact there should be a function to do generate these
alter table public.comments enable row level security;

drop policy if exists comments_authz_insert on comments;
create policy comments_authz_insert on comments
for insert
with check (
    -- could be 'current_user' if you want to use postgres users, 
    -- but typically you don't have a postgres user per system end-user (if you are doing something like a web application)
    oso_is_allowed(current_setting('virt.vuser', true), (url,author,comment,ts)::comments, 'create')
);

drop policy if exists comments_authz_select on comments;
create policy comments_authz_select on comments 
    for select
using (
    oso_is_allowed(current_setting('virt.vuser', true), (url,author,comment,ts)::comments, 'read')
);

drop policy if exists comments_authz_update on comments;
create policy comments_authz_update on comments
for update
using (
    oso_is_allowed(current_setting('virt.vuser', true), (url,author,comment,ts)::comments, 'update')
);

drop policy if exists comments_authz_delete on comments;
create policy comments_authz_delete on comments 
    for delete
using (
    oso_is_allowed(current_setting('virt.vuser', true), (url,author,comment,ts)::comments, 'delete')
);

-- Create a test (non-super) user and grant some permissions
create user foo;
grant select,insert,update,delete on comments to foo;

-- login as foo \c rls_oso foo
-- set virt.vuser='martin'; -- set our session-level virtual user.
-- select * from comments;
-- insert into comments values ('foo', 'foo', 'foo comment', now());
-- update comments set comment = comment || '... and then some' where author = 'foo';
-- delete from comments where author = 'foo';