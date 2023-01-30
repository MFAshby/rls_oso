drop table if exists comments cascade;
drop user if exists foo;

-- Setup a sample table to work with, with some data.
CREATE TABLE comments (
    url text NOT NULL,
    author text NOT NULL,
    comment text NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL
);

insert into comments (url, author, comment, ts) values
('https://mfashby.net/foo', 'martin', 'hereis a comment!', '2022-12-27 22:08:34.139495+00'),
('foo', 'martin',  'hereis a comment!', '2022-12-27 22:47:33.977449+00'),
('foo', 'martin', 'I have something to say you know', '2022-12-27 23:21:46.542678+00'),
('foo', 'martin', 'I have something to say you know', '2022-12-27 23:21:49.283261+00'),
('foo', 'foo', 'foo! foo, foo. Foo.', '2022-12-27 23:25:49.283261+00');

CREATE INDEX idx_comments_url ON comments USING btree (url);

create extension rls_oso;
select oso_configure_rls('comments');
insert into oso_rules (rule, ord) values
    ('allow("admin", _action, _object: comments);', 0),
    ('allow(subject, "insert", object: comments) if object.author = subject;', 1),
    ('allow(subject, "update", object: comments) if object.author = subject;', 2),
    ('allow(subject, "delete", object: comments) if object.author = subject;', 3),
    ('allow(_subject, "select", _object: comments)', 4);

-- Create a test (non-super) user and grant some permissions
create user foo;
grant select,insert,update,delete on comments to foo;

-- login as foo \c rls_oso foo
-- set virt.vuser='martin'; -- set our session-level virtual user.
-- select * from comments;
-- insert into comments values ('foo', 'foo', 'foo comment', now());
-- update comments set comment = comment || '... and then some' where author = 'foo';
-- delete from comments where author = 'foo';