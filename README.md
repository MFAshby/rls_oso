# status

this is a work-in-progress, proof-of-concept only. Do not use this code as-is, it will not work.

# rls_oso

Plugin to use [Oso](https://docs.osohq.com/) authorization library in postgres' [row level security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) policies.

## how to

You need Rust and Cargo installed, and [pgx](https://github.com/tcdi/pgx).

Build and start a local postgres with `cargo pgx run`

Run the SQL in rls.sql to see the effect of row level security policies.

## what next

relations? an important part of security policies is relationship between subject and object. 

but 
