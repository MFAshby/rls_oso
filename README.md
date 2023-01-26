# rls_oso

Plugin to use [Oso](https://docs.osohq.com/) authorization library in postgres' [row level security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) policies.

## how to

You need Rust and Cargo installed, and [pgx](https://github.com/tcdi/pgx).

Build and start a local postgres with `cargo pgx run`

Run the SQL in rls.sql to see the effect of row level security policies.