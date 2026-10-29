#!/usr/bin/env python3
"""
db_doctor.py - layered database connection diagnostics with a shareable, redacted report.

Works with any database. Checks each layer in order and explains the first one that breaks:
    Config -> DNS -> TCP (network/firewall) -> Protocol/TLS -> Login + test query

Only the Python standard library is required. If a database driver is installed
(psycopg, pymysql, pymongo, pyodbc, oracledb, ...) it is used for the login step.

Usage:
    python3 db_doctor.py                                   # interactive: asks questions
    python3 db_doctor.py --url "postgresql://user@host:5432/mydb?sslmode=require"
    python3 db_doctor.py --url "Server=tcp:host,1433;Database=mydb;User Id=me;Encrypt=true"
    python3 db_doctor.py --type mysql --host db.example.com --user app --database shop
    python3 db_doctor.py --config db.json --error "paste the error your app showed"

The password is asked for with hidden input (or read from DB_PASSWORD / the URL).
It is never printed or written to the report.
"""
import argparse
import datetime
import getpass
import importlib.util
import ipaddress
import json
import os
import pathlib
import platform
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request

VERSION = "1.0"

DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "mssql": 1433, "mongodb": 27017,
                 "redis": 6379, "oracle": 1521, "sqlite": None}
ALIASES = {"postgres": "postgresql", "pg": "postgresql", "psql": "postgresql", "cockroachdb": "postgresql",
           "mariadb": "mysql", "sqlserver": "mssql", "azuresql": "mssql", "mongo": "mongodb",
           "mongodb+srv": "mongodb", "rediss": "redis", "sqlite3": "sqlite"}
DRIVERS = {"postgresql": ["psycopg", "psycopg2"], "mysql": ["pymysql", "mysql.connector"],
           "mssql": ["pymssql", "pyodbc"], "mongodb": ["pymongo"], "oracle": ["oracledb"],
           "redis": ["(built-in)"], "sqlite": ["sqlite3"]}
PIP_NAMES = {"psycopg": "psycopg[binary]", "psycopg2": "psycopg2-binary", "pymysql": "pymysql",
             "mysql.connector": "mysql-connector-python", "pymssql": "pymssql", "pyodbc": "pyodbc",
             "pymongo": "pymongo", "oracledb": "oracledb"}
PORT_GUESS = {5432: "postgresql", 3306: "mysql", 1433: "mssql", 27017: "mongodb", 6379: "redis", 1521: "oracle"}
LIBPQ_KEYS = {"sslmode", "sslrootcert", "sslcert", "sslkey", "sslcrl", "options", "application_name",
              "target_session_attrs", "gssencmode", "channel_binding", "krbsrvname", "service"}
SECRET_KEY_RE = re.compile(r"pass|pwd|secret|token|apikey|api_key|credential", re.I)

PASS, FAIL, WARN, SKIP, INFO = "PASS", "FAIL", "WARN", "SKIP", "INFO"
ICONS = {PASS: "✅", FAIL: "❌", WARN: "⚠️", SKIP: "⏭️", INFO: "ℹ️"}


# ---------------------------------------------------------------- target parsing

class Target:
    def __init__(self):
        self.type = None
        self.host = None
        self.port = None
        self.user = None
        self.password = None
        self.database = None
        self.params = {}
        self.url = None
        self.srv = False
        self.tls = False
        self.path = None
        self.notes = []
        self.source = "command-line flags"


def split_hostport(s, t):
    s = s.strip()
    if s.lower().startswith("tcp:"):
        s = s[4:]
    if "\\" in s:
        s, inst = s.split("\\", 1)
        t.notes.append(f"SQL Server named instance '{inst}' - these often use a dynamic port and need "
                       "the SQL Browser service (UDP 1434); prefer an explicit port.")
    if s.startswith("["):
        h, _, r = s[1:].partition("]")
        return h, int(r[1:]) if r.startswith(":") and r[1:] else None
    if "," in s:
        h, p = s.rsplit(",", 1)
        return h, int(p)
    if s.count(":") == 1:
        h, p = s.split(":")
        return h, int(p) if p else None
    return s, None


def parse_url(url, t):
    if url.lower().startswith("jdbc:"):
        url = url[5:]
    scheme, rest = url.split("://", 1)
    scheme = scheme.lower()
    t.srv = scheme == "mongodb+srv"
    t.tls = scheme in ("rediss", "mongodb+srv")
    base = scheme if t.srv else scheme.split("+")[0]
    t.type = ALIASES.get(base, base)
    rest, _, query = rest.partition("?")
    t.params = dict(urllib.parse.parse_qsl(query))
    if ";" in rest:  # jdbc:sqlserver://host:1433;databaseName=x;encrypt=true
        rest, kvs = rest.split(";", 1)
        for part in kvs.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                t.params[k.strip()] = v.strip()
    netloc, _, path = rest.partition("/")
    userinfo, _, hostlist = netloc.rpartition("@")
    if userinfo:
        u, _, p = userinfo.partition(":")
        t.user = urllib.parse.unquote(u) or None
        t.password = urllib.parse.unquote(p) or None
    hosts = [h for h in hostlist.split(",") if h]
    if hosts:
        t.host, t.port = split_hostport(hosts[0], t)
        if len(hosts) > 1:
            t.notes.append(f"Connection string lists {len(hosts)} hosts; only the first is tested.")
    if t.type == "sqlite":
        t.path = urllib.parse.unquote(path)
    else:
        t.database = urllib.parse.unquote(path) or None


def parse_kv_string(s, t):
    """ADO.NET / ODBC / Npgsql style: Server=host,1433;Database=db;User Id=me;Password=..."""
    keymap = {"server": "host", "data source": "host", "host": "host", "address": "host", "addr": "host",
              "network address": "host", "port": "port", "database": "database", "initial catalog": "database",
              "dbname": "database", "user id": "user", "uid": "user", "user": "user", "username": "user",
              "user name": "user", "password": "password", "pwd": "password"}
    raw_keys = set()
    for part in s.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        raw_keys.add(k.lower())
        field = keymap.get(k.lower())
        if field == "host":
            t.host, port = split_hostport(v, t)
            t.port = t.port or port
        elif field == "port":
            t.port = int(v)
        elif field:
            setattr(t, field, v)
        else:
            t.params[k] = v
    if t.port in PORT_GUESS:
        t.type = PORT_GUESS[t.port]
    elif "host" in raw_keys or "username" in raw_keys:
        t.type = "postgresql"  # Npgsql style
    else:
        t.type = "mssql"
    t.notes.append(f"Database type guessed as '{t.type}' from the connection string; use --type to override.")


def pull_params(t):
    """Move user/password/database that arrive as query parameters into proper fields."""
    for k in list(t.params):
        lk = k.lower()
        if lk in ("user", "username", "uid", "user id"):
            v = t.params.pop(k)
            t.user = t.user or v
        elif lk in ("password", "pwd"):
            v = t.params.pop(k)
            t.password = t.password or v
        elif lk in ("database", "databasename", "dbname", "initial catalog"):
            v = t.params.pop(k)
            t.database = t.database or v


def wants_tls(t):
    p = {k.lower(): str(v).lower() for k, v in t.params.items()}
    if t.tls:
        return p.get("tls", p.get("ssl")) != "false"
    return (p.get("sslmode") in ("require", "verify-ca", "verify-full")
            or p.get("ssl-mode") in ("required", "verify_ca", "verify_identity")
            or any(p.get(k) in ("true", "1", "yes", "required", "mandatory", "strict")
                   for k in ("ssl", "tls", "encrypt", "usessl", "usetls")))


def ask(prompt, default=None):
    suffix = f" [{default}]" if default else ""
    v = input(f"  {prompt}{suffix}: ").strip()
    return v or default


def build_target(args):
    cfg = {}
    if args.config:
        with open(os.path.expanduser(args.config)) as f:
            cfg = json.load(f)

    def pick(name):
        v = getattr(args, name, None)
        return v if v not in (None, "") else cfg.get(name)

    t = Target()
    url = pick("url")
    if url:
        t.source = "--url" if args.url else f"config file {args.config}"
    for env in ("DB_URL", "DATABASE_URL"):
        if not url and not pick("host") and os.environ.get(env):
            url, t.source = os.environ[env], f"{env} environment variable"
    interactive = sys.stdin.isatty()

    if not url and not pick("host") and interactive:
        print("No connection details given - answer a few questions (press Enter to skip any).\n")
        url = ask("Paste a connection string/URL, or press Enter to fill in fields")
        t.source = "interactive prompt"
        if not url:
            cfg["type"] = ask(f"Database type ({', '.join(DEFAULT_PORTS)}, or other)")
            if (cfg["type"] or "").lower() in ("sqlite", "sqlite3"):
                cfg["database"] = ask("Path to the .db file")
            else:
                cfg["host"] = ask("Host (hostname or IP)")
                ttype = ALIASES.get((cfg["type"] or "").lower(), (cfg["type"] or "").lower())
                cfg["port"] = ask("Port", DEFAULT_PORTS.get(ttype))
                cfg["database"] = ask("Database name")
                cfg["user"] = ask("Username")
                if (ask("Require SSL/TLS? (y/n)", "n") or "n").lower().startswith("y"):
                    cfg["params"] = {"ssl": "true", "sslmode": "require"} if ttype == "postgresql" else {"ssl": "true"}

    if url:
        if "://" in url:
            parse_url(url, t)
        elif "=" in url:
            parse_kv_string(url, t)
        else:
            raise ValueError("Connection string not recognised: expected scheme://... or Key=Value;Key=Value")
        t.url = url

    for field in ("type", "host", "user", "database"):
        v = pick(field)
        if v:
            setattr(t, field, str(v))
    if pick("port"):
        t.port = int(pick("port"))
    t.params.update({str(k): str(v) for k, v in (cfg.get("params") or {}).items()})
    for kv in args.param or []:
        k, _, v = kv.partition("=")
        t.params[k] = v
    pull_params(t)

    if t.type:
        t.type = ALIASES.get(t.type.lower(), t.type.lower())
    elif t.port in PORT_GUESS:
        t.type = PORT_GUESS[t.port]
    if t.type == "sqlite":
        t.path = t.path or t.database
    if t.port is None and t.type in DEFAULT_PORTS:
        t.port = DEFAULT_PORTS[t.type]

    if args.password:
        t.password = args.password
        t.notes.append("Password was passed with --password (it may be saved in shell history; prefer the prompt).")
    elif os.environ.get("DB_PASSWORD"):
        t.password = os.environ["DB_PASSWORD"]
    elif not t.password and interactive and not args.no_auth and t.type != "sqlite":
        t.password = getpass.getpass("  Password (hidden; Enter for none): ") or None

    if interactive and t.source == "interactive prompt" and not (args.error or args.error_file):
        args.error = ask("Paste the error message your app showed (optional)")
    return t


def validate(t):
    problems = []
    if not t.type:
        problems.append("Database type is unknown - pass --type (e.g. postgresql, mysql, mssql, mongodb, redis, oracle).")
    if t.type == "sqlite":
        if not t.path:
            problems.append("SQLite needs a file path (--database /path/to/file.db).")
        return problems
    if not t.host:
        problems.append("Host is missing (--host).")
    if not t.port and not t.srv:
        problems.append("Port is missing and there is no default for this type (--port).")
    return problems


# ---------------------------------------------------------------- redaction

def mask_ip(ip):
    if ":" in ip:
        return ip.split(":")[0] + ":****"
    parts = ip.split(".")
    return f"{parts[0]}.x.x.x"


def mask_host(host):
    try:
        ipaddress.ip_address(host)
        return mask_ip(host)
    except ValueError:
        pass
    labels = host.split(".")
    keep = 3 if len(labels) > 3 else 1
    hidden = [lab[:2] + "***" for lab in labels[:-keep]] or [labels[0][:2] + "***"]
    return ".".join(hidden + labels[-keep:]) if len(labels) > 1 else hidden[0]


class Redactor:
    def __init__(self, t, redact_host, redact_user):
        self.redact_host = redact_host
        self.pairs = []
        if t.password:
            for s in {t.password, urllib.parse.quote(t.password, safe=""), urllib.parse.quote_plus(t.password)}:
                self.pairs.append((s, "****"))
        if redact_user and t.user:
            self.pairs.append((t.user, t.user[:1] + "***"))
        if redact_host and t.host:
            self.add_host(t.host)
        home = os.path.expanduser("~")
        if home and home != "/":
            self.pairs.append((home, "~"))

    def add_host(self, host):
        if self.redact_host:
            self.pairs.append((host, mask_host(host)))

    def add_ip(self, ip):
        if self.redact_host and not ipaddress.ip_address(ip.split("%")[0]).is_private:
            self.pairs.append((ip, mask_ip(ip)))

    def __call__(self, text):
        text = str(text)
        for s, r in sorted(self.pairs, key=lambda p: -len(p[0])):
            text = text.replace(s, r)
        text = re.sub(r"(?i)\b(password|pwd)\s*=\s*[^;&\s]+", r"\1=****", text)
        text = re.sub(r"//([^:/@\s]+):[^@/\s]+@", r"//\1:****@", text)
        return text


# ---------------------------------------------------------------- report

class Row:
    def __init__(self, step, status, detail, hint, ms):
        self.step, self.status, self.detail, self.hint, self.ms = step, status, detail, hint, ms


class Report:
    def __init__(self, redact):
        self.rows = []
        self.redact = redact
        self.connected = False

    def add(self, step, status, detail, hint=None, ms=None):
        self.rows.append(Row(step, status, detail, hint, ms))
        timing = f" ({ms} ms)" if ms is not None else ""
        print(self.redact(f"[{status}] {step:<9} {detail}{timing}"))
        if hint:
            print(self.redact(f"{'':17}-> {hint}"))


def elapsed(start):
    return int((time.monotonic() - start) * 1000)


# ---------------------------------------------------------------- checks

def check_dns(t, rep, red):
    if t.srv:
        if not has_module("dns.resolver"):
            rep.add("DNS", WARN, "mongodb+srv:// needs an SRV lookup, which requires the 'dnspython' package.",
                    hint="Run: python3 -m pip install dnspython   (network checks skipped until then)")
            return None
        import dns.resolver
        start = time.monotonic()
        try:
            answers = sorted(dns.resolver.resolve(f"_mongodb._tcp.{t.host}", "SRV"), key=lambda r: r.priority)
        except Exception as e:
            rep.add("DNS", FAIL, f"SRV lookup for _mongodb._tcp.{t.host} failed: {e}",
                    hint="Cluster hostname is wrong or the cluster was deleted/paused.")
            return None
        targets = [(str(a.target).rstrip("."), a.port) for a in answers]
        for h, _ in targets:
            red.add_host(h)
        rep.add("DNS", PASS, f"SRV record lists {len(targets)} servers: "
                + ", ".join(f"{h}:{p}" for h, p in targets), ms=elapsed(start))
        t.host, t.port = targets[0]

    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(t.host, t.port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        rep.add("DNS", FAIL, f"Could not resolve hostname '{t.host}': {e.strerror or e}",
                hint="The hostname is misspelled, only resolvable on a private network/VPN you aren't "
                     "connected to, or the server/instance no longer exists.")
        return None
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    for ip in ips:
        red.add_ip(ip)
    rep.add("DNS", PASS, f"{t.host} -> {', '.join(ips)}", ms=elapsed(start))
    addrs = [ipaddress.ip_address(ip.split("%")[0]) for ip in ips]
    if any(a.is_private and not a.is_loopback for a in addrs):
        rep.add("DNS", INFO, "Host resolves to a private IP address.",
                hint="Private IPs are only reachable from the same network: office/VPN, the same cloud VPC, "
                     "or through a bastion/jump host. Being on the public internet is not enough.")
    return infos


def check_tcp(t, infos, timeout, rep, public_ip):
    failures = []
    for fam, stype, proto, _, addr in infos[:4]:
        s = socket.socket(fam, stype, proto)
        s.settimeout(timeout)
        start = time.monotonic()
        try:
            s.connect(addr)
            rep.add("TCP", PASS, f"Port {addr[1]} on {addr[0]} is open (connected from local address "
                    f"{s.getsockname()[0]})", ms=elapsed(start))
            return addr[0], addr[1]
        except socket.timeout:
            failures.append((addr[0], "timed out"))
        except ConnectionRefusedError:
            failures.append((addr[0], "connection refused"))
        except OSError as e:
            failures.append((addr[0], e.strerror or str(e)))
        finally:
            s.close()

    kinds = {f[1] for f in failures}
    if kinds == {"timed out"}:
        hint = (f"Traffic is being silently dropped: almost always a firewall, cloud security group / network "
                f"ACL, or IP allowlist. Ask the admin to allow your public IP ({public_ip or 'see Environment'}) "
                f"on port {t.port}, and check whether a VPN is required.")
    elif kinds == {"connection refused"}:
        hint = (f"The machine is reachable but nothing is listening on port {t.port}: wrong port, the database "
                "service is stopped, or it only listens on localhost (Postgres listen_addresses / "
                "MySQL bind-address).")
    else:
        hint = "No network route to the host. Check your internet/VPN connection and that the IP is correct."
    rep.add("TCP", FAIL, f"Cannot connect to port {t.port}: "
            + "; ".join(f"{ip} {why}" for ip, why in failures) + f" (timeout {timeout}s)", hint=hint)
    return None


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed the connection")
        buf += chunk
    return buf


def tls_handshake(raw, host, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=host)


def cert_hint(reason):
    r = reason.lower()
    if "self signed" in r or "self-signed" in r:
        return ("The server uses a self-signed or private-CA certificate. Get the CA certificate (e.g. the AWS RDS / "
                "Azure CA bundle) and point the driver at it (sslrootcert / ssl-ca / tlsCAFile). For testing only, "
                "sslmode=require or TrustServerCertificate=true skips verification.")
    if "local issuer" in r:
        return ("This machine doesn't trust the certificate's issuer. With python.org Python on macOS, run "
                "'Install Certificates.command' from the Python folder. Otherwise the server uses a private CA - "
                "get its CA bundle.")
    if "mismatch" in r or "match" in r:
        return ("The certificate isn't issued for the hostname you used. Connect using the exact hostname on the "
                "certificate (not an IP address or alias).")
    if "expired" in r:
        return "The server's certificate has expired - the server admin must renew it."
    return "Certificate could not be verified. Drivers set to 'require' / TrustServerCertificate skip this check."


def tls_check(prepare, host, rep):
    start = time.monotonic()
    try:
        ss = tls_handshake(prepare(), host, verify=True)
        cert = ss.getpeercert() or {}
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        rep.add("TLS", PASS, f"{ss.version()} handshake OK, certificate trusted and matches host. Issuer: "
                f"{issuer.get('organizationName') or issuer.get('commonName', '?')}; expires "
                f"{cert.get('notAfter', '?')}", ms=elapsed(start))
        ss.close()
    except ssl.SSLCertVerificationError as e:
        reason = e.verify_message or str(e)
        try:
            ss = tls_handshake(prepare(), host, verify=False)
            detail = f"Encryption works ({ss.version()}), but the certificate check failed: {reason}"
            ss.close()
        except Exception:
            detail = f"Certificate check failed: {reason}"
        rep.add("TLS", WARN, detail, hint=cert_hint(reason), ms=elapsed(start))
    except Exception as e:
        rep.add("TLS", FAIL, f"TLS handshake failed: {e.__class__.__name__}: {e}",
                hint="The server may not use TLS on this port, may need a different TLS version, or a proxy is "
                     "interfering. Check whether TLS should be enabled for this connection at all.")


PG_SSL_REQUEST = struct.pack("!II", 8, 80877103)


def probe_postgres(t, conn, rep):
    start = time.monotonic()
    s = conn()
    try:
        s.sendall(PG_SSL_REQUEST)
        reply = s.recv(1)
    finally:
        s.close()
    if reply == b"S":
        rep.add("Protocol", PASS, "Server answered as PostgreSQL and supports SSL/TLS", ms=elapsed(start))

        def prepare():
            sock = conn()
            sock.sendall(PG_SSL_REQUEST)
            if sock.recv(1) != b"S":
                sock.close()
                raise ConnectionError("server declined SSL on retry")
            return sock
        tls_check(prepare, t.host, rep)
    elif reply == b"N":
        if wants_tls(t):
            rep.add("Protocol", FAIL, "Server answered as PostgreSQL but has SSL disabled, and your settings require SSL.",
                    hint="Either remove sslmode=require from the connection, or ask the DBA to enable SSL on the server.")
        else:
            rep.add("Protocol", PASS, "Server answered as PostgreSQL (SSL not enabled on server - traffic is "
                    "unencrypted)", ms=elapsed(start))
    elif not reply:
        rep.add("Protocol", FAIL, "Server closed the connection immediately.",
                hint="This port may not be PostgreSQL, or a proxy/pooler in front of it is rejecting this client.")
    else:
        rep.add("Protocol", WARN, f"Unexpected reply {reply!r} - this port may not be PostgreSQL.",
                hint="Check the port number; another service may be listening there.")


MYSQL_PRELOGIN_HINTS = {
    1130: "MySQL does not allow this user/host combination. The DBA must create or GRANT the user for your "
          "client host/IP (e.g. 'user'@'%' or 'user'@'<your ip>').",
    1129: "Your host is blocked after too many failed connections. The DBA must run FLUSH HOSTS (or "
          "mysqladmin flush-hosts).",
    1040: "The server has reached its maximum number of connections.",
}


def probe_mysql(t, conn, rep):
    start = time.monotonic()
    s = conn()
    try:
        hdr = recv_exact(s, 4)
        payload = recv_exact(s, int.from_bytes(hdr[:3], "little"))
    except socket.timeout:
        rep.add("Protocol", WARN, "Port is open but no MySQL greeting was received.",
                hint="This port may not be MySQL/MariaDB (wrong port), or a proxy is holding the connection.")
        return
    except OSError as e:
        rep.add("Protocol", FAIL, f"Server closed the connection before greeting: {e}",
                hint="The server may be rejecting your IP, or this port isn't MySQL/MariaDB.")
        return
    finally:
        s.close()
    if payload[:1] == b"\xff":
        code = int.from_bytes(payload[1:3], "little")
        msg = payload[3:].decode("utf-8", "replace")
        rep.add("Protocol", FAIL, f"Server rejected the connection before login - error {code}: {msg}",
                hint=MYSQL_PRELOGIN_HINTS.get(code, "See the MySQL error code above."))
    elif payload[:1] == b"\x0a":
        version, _, rest = payload[1:].partition(b"\0")
        caps = int.from_bytes(rest[13:15], "little") if len(rest) >= 15 else 0
        ssl_ok = bool(caps & 0x0800)
        rep.add("Protocol", PASS, f"MySQL-compatible server, version {version.decode(errors='replace')}; "
                f"TLS supported: {'yes' if ssl_ok else 'no'}", ms=elapsed(start))
        if wants_tls(t) and not ssl_ok:
            rep.add("TLS", FAIL, "Your settings require TLS but the server does not support it.",
                    hint="Disable SSL in the connection settings, or ask the DBA to enable TLS on the server.")
    else:
        rep.add("Protocol", WARN, f"Unexpected greeting {payload[:16]!r} - this port may not be MySQL.")


def probe_redis(t, conn, rep):
    if t.tls:
        tls_check(conn, t.host, rep)
        return
    start = time.monotonic()
    s = conn()
    try:
        s.sendall(b"PING\r\n")
        line = s.recv(256).decode(errors="replace").strip()
    except socket.timeout:
        line = ""
    finally:
        s.close()
    if line.startswith("+PONG"):
        rep.add("Protocol", PASS, "Redis responded - no password required.", ms=elapsed(start))
    elif "NOAUTH" in line:
        rep.add("Protocol", PASS, "Redis responded - authentication required.", ms=elapsed(start))
    elif "DENIED" in line:
        rep.add("Protocol", FAIL, f"Redis refused: {line[:160]}",
                hint="Redis is in protected mode: it only accepts localhost connections until a password or "
                     "bind address is configured on the server.")
    elif not line:
        rep.add("Protocol", WARN, "No reply to PING.",
                hint="The server may require TLS (use rediss://), or this port isn't Redis.")
    else:
        rep.add("Protocol", WARN, f"Unexpected reply: {line[:120]}")


def check_protocol(t, addr, timeout, rep):
    def conn():
        return socket.create_connection(addr, timeout=timeout)

    if t.type == "postgresql":
        probe_postgres(t, conn, rep)
    elif t.type == "mysql":
        probe_mysql(t, conn, rep)
    elif t.type == "redis":
        probe_redis(t, conn, rep)
    elif t.type == "mssql":
        rep.add("TLS", INFO, "SQL Server negotiates encryption inside its own protocol (TDS); it is checked "
                "during the login step.")
    elif wants_tls(t):
        tls_check(conn, t.host, rep)
    elif t.type in DEFAULT_PORTS:
        rep.add("Protocol", INFO, f"No low-level probe for {t.type}; the login step will confirm the protocol.")
    else:
        s = conn()
        s.settimeout(2)
        try:
            banner = s.recv(120)
        except socket.timeout:
            banner = b""
        finally:
            s.close()
        rep.add("Protocol", INFO, f"Server greeting: {banner!r}" if banner else
                "Server waits for the client to speak first (normal for most databases).")


# ---------------------------------------------------------------- login

def c_psycopg(t, timeout):
    import psycopg
    kw = dict(host=t.host, port=t.port, user=t.user, password=t.password, dbname=t.database,
              connect_timeout=timeout, **{k: v for k, v in t.params.items() if k in LIBPQ_KEYS})
    with psycopg.connect(**{k: v for k, v in kw.items() if v is not None}) as c:
        return c.execute("select version()").fetchone()[0]


def c_psycopg2(t, timeout):
    import psycopg2
    kw = dict(host=t.host, port=t.port, user=t.user, password=t.password, dbname=t.database,
              connect_timeout=timeout, **{k: v for k, v in t.params.items() if k in LIBPQ_KEYS})
    c = psycopg2.connect(**{k: v for k, v in kw.items() if v is not None})
    try:
        cur = c.cursor()
        cur.execute("select version()")
        return cur.fetchone()[0]
    finally:
        c.close()


def c_pymysql(t, timeout):
    import pymysql
    c = pymysql.connect(host=t.host, port=t.port, user=t.user, password=t.password or "", database=t.database,
                        connect_timeout=timeout, ssl=ssl.create_default_context() if wants_tls(t) else None)
    try:
        with c.cursor() as cur:
            cur.execute("select version()")
            return cur.fetchone()[0]
    finally:
        c.close()


def c_mysql_connector(t, timeout):
    import mysql.connector
    kw = dict(host=t.host, port=t.port, user=t.user, password=t.password or "", database=t.database,
              connection_timeout=timeout)
    c = mysql.connector.connect(**{k: v for k, v in kw.items() if v is not None})
    try:
        cur = c.cursor()
        cur.execute("select version()")
        return cur.fetchone()[0]
    finally:
        c.close()


def c_pymssql(t, timeout):
    import pymssql
    c = pymssql.connect(server=t.host, port=str(t.port), user=t.user, password=t.password,
                        database=t.database or "", login_timeout=timeout)
    try:
        cur = c.cursor()
        cur.execute("select @@version")
        return cur.fetchone()[0].splitlines()[0]
    finally:
        c.close()


def c_pyodbc(t, timeout):
    import pyodbc
    drivers = [d for d in pyodbc.drivers() if "SQL Server" in d]
    if not drivers:
        raise RuntimeError("pyodbc is installed but no 'ODBC Driver for SQL Server' is - install msodbcsql18")
    p = {k.lower(): v for k, v in t.params.items()}
    parts = {"DRIVER": "{%s}" % drivers[-1], "SERVER": f"{t.host},{t.port}", "DATABASE": t.database,
             "UID": t.user, "PWD": "{%s}" % t.password.replace("}", "}}") if t.password else None,
             "Encrypt": p.get("encrypt", "yes"), "TrustServerCertificate": p.get("trustservercertificate", "no")}
    c = pyodbc.connect(";".join(f"{k}={v}" for k, v in parts.items() if v), timeout=timeout)
    try:
        return c.cursor().execute("select @@version").fetchone()[0].splitlines()[0]
    finally:
        c.close()


def c_pymongo(t, timeout):
    import pymongo
    kw = {"serverSelectionTimeoutMS": timeout * 1000, "connectTimeoutMS": timeout * 1000}
    if t.user:
        kw["username"] = t.user
    if t.password:
        kw["password"] = t.password
    if t.url and t.url.lower().startswith("mongodb"):
        c = pymongo.MongoClient(t.url, **kw)
    else:
        c = pymongo.MongoClient(host=t.host, port=t.port, tls=wants_tls(t), **kw)
    try:
        c[t.database or "admin"].command("ping")
        return "MongoDB " + c.server_info().get("version", "?")
    finally:
        c.close()


def c_oracledb(t, timeout):
    import oracledb
    c = oracledb.connect(user=t.user, password=t.password, dsn=f"{t.host}:{t.port}/{t.database or ''}",
                         tcp_connect_timeout=timeout)
    try:
        c.cursor().execute("select 1 from dual").fetchone()
        return "Oracle " + c.version
    finally:
        c.close()


def c_redis(t, timeout):
    s = socket.create_connection((t.host, t.port), timeout=timeout)
    if t.tls:
        s = tls_handshake(s, t.host, verify=True)
    f = s.makefile("rb")

    def cmd(*parts):
        s.sendall(("*%d\r\n" % len(parts) + "".join(f"${len(p.encode())}\r\n{p}\r\n" for p in parts)).encode())
        line = f.readline().decode(errors="replace").rstrip("\r\n")
        if line.startswith("-"):
            raise RuntimeError(line[1:])
        if line.startswith("$") and line != "$-1":
            return f.read(int(line[1:]) + 2).decode(errors="replace")
        return line[1:]

    try:
        if t.password:
            cmd("AUTH", t.user, t.password) if t.user else cmd("AUTH", t.password)
        if t.database:
            cmd("SELECT", t.database)
        cmd("PING")
        m = re.search(r"redis_version:(\S+)", cmd("INFO", "server"))
        return "Redis " + (m.group(1) if m else "?")
    finally:
        s.close()


CONNECTORS = {"psycopg": c_psycopg, "psycopg2": c_psycopg2, "pymysql": c_pymysql,
              "mysql.connector": c_mysql_connector, "pymssql": c_pymssql, "pyodbc": c_pyodbc,
              "pymongo": c_pymongo, "oracledb": c_oracledb, "(built-in)": c_redis}

AUTH_HINTS = [
    (r"no pg_hba\.conf entry",
     "PostgreSQL's pg_hba.conf has no rule allowing this user/database from your IP (or without SSL). The DBA "
     "must add one, or try sslmode=require."),
    (r"role .* does not exist|user .* does not exist",
     "That username doesn't exist on this server."),
    (r"password authentication failed|access denied for user|login failed for user|authentication failed|"
     r"invalid username/password|wrongpass|ora-01017|bad auth",
     "Wrong username or password (or the user doesn't exist / is locked). Double-check both, and watch for "
     "special characters in the password that need URL-encoding in connection strings."),
    (r"database .* does not exist|unknown database|cannot open database|ora-12514",
     "The database (or Oracle service) name is wrong or doesn't exist on this server."),
    (r"not allowed to connect", "This MySQL user isn't permitted from your host - the DBA needs to GRANT it for your IP or '%'."),
    (r"caching_sha2_password|authentication plugin|auth_gssapi",
     "Authentication method mismatch: upgrade the driver, or ask the DBA which auth plugin the user uses."),
    (r"too many connections|remaining connection slots|max_connections",
     "The server has hit its connection limit; something is leaking or holding connections."),
    (r"noauth|requirepass", "The server requires a password but none was sent."),
    (r"permission denied|not authorized|access to database denied",
     "Login worked but this user lacks permission on the database/query. The DBA must grant access."),
    (r"certificate|ssl|tls|encrypt",
     "TLS/SSL mismatch: check sslmode / Encrypt / TrustServerCertificate settings, or obtain the server's CA certificate."),
    (r"timeout|timed out", "Login timed out: the server is reachable but slow or overloaded, or a proxy is dropping traffic."),
]


def auth_hint(msg):
    for pattern, hint in AUTH_HINTS:
        if re.search(pattern, msg, re.I):
            return hint
    return "Share the exact error above with the database admin."


def has_module(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def check_login(t, timeout, rep):
    candidates = DRIVERS.get(t.type)
    if not candidates:
        rep.add("Login", SKIP, f"No login test available for type '{t.type}'.")
        return
    available = [m for m in candidates if m == "(built-in)" or has_module(m)]
    if not available:
        rep.add("Login", SKIP, f"No Python driver for {t.type} is installed, so login wasn't tested.",
                hint=f"To test login too, run: python3 -m pip install {PIP_NAMES[candidates[0]]}   then re-run.")
        return
    driver = available[0]
    start = time.monotonic()
    try:
        version = CONNECTORS[driver](t, timeout)
    except Exception as e:
        msg = f"{e.__class__.__name__}: {e}".strip()
        rep.add("Login", FAIL, f"Login failed using {driver}: {msg}", hint=auth_hint(msg), ms=elapsed(start))
        return
    rep.add("Login", PASS, f"Logged in as '{t.user or '(none)'}' to database '{t.database or '(default)'}' and ran a "
            f"test query via {driver}. Server: {version}", ms=elapsed(start))
    rep.connected = True


def check_sqlite(t, rep):
    import sqlite3
    path = os.path.abspath(os.path.expanduser(t.path))
    if not os.path.exists(path):
        rep.add("File", FAIL, f"File not found: {path}",
                hint=f"SQLite silently creates a new EMPTY database when the file is missing, which looks like "
                     f"'no such table'. Relative paths resolve from the app's working directory (here: "
                     f"{os.getcwd()}) - use an absolute path.")
        return
    folder = os.path.dirname(path)
    rep.add("File", PASS, f"{path} exists ({os.path.getsize(path):,} bytes); readable: "
            f"{os.access(path, os.R_OK)}, writable: {os.access(path, os.W_OK)}, folder writable: "
            f"{os.access(folder, os.W_OK)}",
            hint=None if os.access(folder, os.W_OK) else
            "The folder isn't writable; SQLite needs that for its journal/WAL files when writing.")
    start = time.monotonic()
    try:
        con = sqlite3.connect(pathlib.Path(path).as_uri() + "?mode=ro", uri=True, timeout=2)
        tables = con.execute("select count(*) from sqlite_master where type='table'").fetchone()[0]
        con.close()
    except sqlite3.DatabaseError as e:
        rep.add("Open", FAIL, f"Could not read the database: {e}",
                hint="The file isn't a SQLite database, is corrupted, or is locked by another process.")
        return
    rep.add("Open", PASS, f"Opened read-only with SQLite {sqlite3.sqlite_version}; {tables} table(s).",
            ms=elapsed(start))
    rep.connected = True
    if tables == 0:
        rep.add("Open", WARN, "The database has no tables.",
                hint="This may be the wrong file, or migrations/schema setup haven't been run.")


# ---------------------------------------------------------------- environment & output

def environment(no_public_ip):
    env = {"OS": f"{platform.system()} {platform.release()} ({platform.machine()})",
           "Python": sys.version.split()[0]}
    public_ip = None
    if no_public_ip:
        env["Public IP"] = "not checked (--no-public-ip)"
    else:
        try:
            public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=4).read().decode().strip()
            env["Public IP"] = f"{public_ip} (what internet-facing firewalls/allowlists see)"
        except Exception as e:
            env["Public IP"] = f"could not determine ({e.__class__.__name__})"
    proxies = {k: re.sub(r"//[^@/]+@", "//****@", v) for k, v in os.environ.items()
               if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    env["Proxy settings"] = ", ".join(f"{k}={v}" for k, v in proxies.items()) or "none"
    try:
        tunnels = [n for _, n in socket.if_nameindex() if re.match(r"(utun|tun|tap|ppp|wg|ipsec|gpd|zt)", n)]
        env["Tunnel interfaces"] = (", ".join(tunnels) or "none") + \
            (" (macOS always has a few utun; extra ones usually mean a VPN)" if sys.platform == "darwin" else "")
    except (AttributeError, OSError):
        pass
    found = [m for mods in DRIVERS.values() for m in mods if m != "(built-in)" and has_module(m)]
    env["Installed DB drivers"] = ", ".join(found) or "none"
    return env, public_ip


def verdict(rep):
    fails = [r for r in rep.rows if r.status == FAIL]
    if fails:
        f = fails[0]
        return f"Connection fails at the {f.step} step. {f.hint or f.detail}"
    if rep.connected:
        return ("Connection WORKS from this machine with these settings. If the application still fails, the problem "
                "is most likely in the app's own configuration (compare host, port, database, user, SSL options) or "
                "in the environment it runs in (different machine, container, or network).")
    if any(r.status == WARN for r in rep.rows):
        return "No hard failures, but there are warnings below, and login was not fully confirmed."
    return "Network path looks OK, but login was not tested (see the Login step)."


def render_markdown(t, rep, env, user_error, summary):
    now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    params = {k: ("****" if SECRET_KEY_RE.search(k) else v) for k, v in t.params.items()}
    target = [("Database type", t.type), ("Settings came from", t.source)]
    if t.type == "sqlite":
        target.append(("File", t.path))
    else:
        target += [("Host", t.host), ("Port", t.port), ("Database", t.database or "(default)"),
                   ("User", t.user or "(none)"), ("Password", "provided (hidden)" if t.password else "not provided"),
                   ("TLS/SSL requested", "yes" if wants_tls(t) else "no")]
    if params:
        target.append(("Extra options", ", ".join(f"{k}={v}" for k, v in params.items())))

    out = ["# Database connection diagnostic report",
           f"_Generated {now} by db_doctor.py v{VERSION}. Passwords are never included._",
           "## Summary", f"**{summary}**",
           "## Target", "| Setting | Value |\n|---|---|\n" + "\n".join(f"| {k} | {v} |" for k, v in target)]
    if t.notes:
        out.append("\n".join(f"- {n}" for n in t.notes))
    out.append("## Checks\nEach check depends on the previous one. The first ❌ is where the connection breaks.")
    for r in rep.rows:
        timing = f" · {r.ms} ms" if r.ms is not None else ""
        block = f"**{ICONS[r.status]} {r.step} - {r.status}**{timing}  \n{r.detail}"
        if r.hint:
            block += f"\n> **Likely cause / next step:** {r.hint}"
        out.append(block)
    out.append("## Client environment\n" + "\n".join(f"- **{k}:** {v}" for k, v in env.items()))
    if user_error:
        out.append("## Error seen in the application\n```\n" + user_error.strip() + "\n```")
    return rep.redact("\n\n".join(out)) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Diagnose database connection problems and write a shareable, "
                                             "redacted report.")
    ap.add_argument("--url", help="connection string: scheme://user@host:port/db?opts, JDBC, or Key=Value;... style")
    ap.add_argument("--type", help="postgresql, mysql, mssql, mongodb, redis, oracle, sqlite (or anything else)")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--user")
    ap.add_argument("--database", help="database name (or file path for sqlite)")
    ap.add_argument("--password", help="discouraged: visible in shell history. Use the prompt or DB_PASSWORD.")
    ap.add_argument("--param", action="append", metavar="KEY=VALUE", help="extra option, e.g. sslmode=require (repeatable)")
    ap.add_argument("--config", help="JSON file with any of: url, type, host, port, user, database, params")
    ap.add_argument("--error", help="the error message your app showed (included in the report)")
    ap.add_argument("--error-file", help="file containing the app's error/log output")
    ap.add_argument("--timeout", type=int, default=5, help="seconds per network step (default 5)")
    ap.add_argument("--no-auth", action="store_true", help="skip the login step (no password needed)")
    ap.add_argument("--no-public-ip", action="store_true", help="don't look up this machine's public IP")
    ap.add_argument("--redact-host", action="store_true", help="partially mask the hostname and public IPs in output")
    ap.add_argument("--redact-user", action="store_true", help="mask the username in output")
    ap.add_argument("--out", help="report file path (default: db-doctor-report-<time>.md in current folder)")
    args = ap.parse_args()

    try:
        t = build_target(args)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        sys.exit(f"Could not read connection settings: {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nCancelled.")
    problems = validate(t)
    if problems:
        sys.exit("Missing information:\n  - " + "\n  - ".join(problems))

    red = Redactor(t, args.redact_host, args.redact_user)
    rep = Report(red)
    user_error = args.error
    if args.error_file:
        with open(os.path.expanduser(args.error_file), errors="replace") as f:
            user_error = f.read()[-8000:]

    print(red(f"\ndb-doctor: checking {t.type} "
              + (f"file {t.path}" if t.type == "sqlite" else f"at {t.host}:{t.port or '(srv)'}") + "\n"))
    env, public_ip = environment(args.no_public_ip)

    try:
        if t.type == "sqlite":
            check_sqlite(t, rep)
        else:
            infos = check_dns(t, rep, red)
            addr = check_tcp(t, infos, args.timeout, rep, public_ip) if infos else None
            if addr:
                try:
                    check_protocol(t, addr, args.timeout, rep)
                except Exception as e:
                    rep.add("Protocol", WARN, f"Probe error: {e.__class__.__name__}: {e}")
                if args.no_auth:
                    rep.add("Login", SKIP, "Skipped (--no-auth).")
                else:
                    check_login(t, args.timeout, rep)
    except KeyboardInterrupt:
        rep.add("Aborted", INFO, "Stopped by user.")

    summary = verdict(rep)
    out_path = args.out or f"db-doctor-report-{datetime.datetime.now():%Y%m%d-%H%M%S}.md"
    with open(out_path, "w") as f:
        f.write(render_markdown(t, rep, env, user_error, summary))
    print(red(f"\nSummary: {summary}"))
    print(f"\nReport saved to {os.path.abspath(out_path)} - safe to share (password removed).")
    if not (args.redact_host or args.redact_user):
        print("Tip: add --redact-host / --redact-user to also mask the hostname and username before sharing.")
    sys.exit(0 if rep.connected or not any(r.status == FAIL for r in rep.rows) else 1)


if __name__ == "__main__":
    main()
