# db-doctor

Diagnoses why a database connection fails and writes a **redacted Markdown report** you can share.

Checks in order: **DNS → TCP (firewall) → Protocol/TLS → Login + test query**, and explains the first failure.
Works with any database (Postgres, MySQL/MariaDB, SQL Server, MongoDB, Redis, Oracle, SQLite; others get the network/TLS checks).

## Run

```bash
python3 db_doctor.py                       # interactive: asks for everything
python3 db_doctor.py --url "<connection string from your app/.env/appsettings.json>"
python3 db_doctor.py --config db.json --error "paste the error your app showed"
```

Accepts URL style (`postgresql://user@host:5432/db?sslmode=require`), JDBC (`jdbc:sqlserver://...`),
and .NET style (`Server=host,1433;Database=db;User Id=me;Password=...`).

Password: asked with hidden input, or set `DB_PASSWORD`. It is never printed or saved.

## Share

The report (`db-doctor-report-<time>.md`) is safe to send. Add `--redact-host --redact-user` to mask those too.

## Optional: test the login step

The network checks need nothing extra. To also test login, install the driver for your database:
`psycopg[binary]` (Postgres), `pymysql` (MySQL), `pymssql` or `pyodbc` (SQL Server), `pymongo`, `oracledb`.
Redis and SQLite need nothing.
