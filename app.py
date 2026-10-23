#!/usr/bin/env python3
"""پنل ساده توزیع کانفیگ v2ray برای دو اپراتور.

راه‌اندازی:   python app.py init      (ساخت/تغییر نام کاربری و رمز ادمین)
اجرا:         gunicorn -w 2 -b 127.0.0.1:8000 app:app
"""
import base64
import functools
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
import uuid as _uuid
import ssl
import urllib.error
import urllib.request
import urllib.parse
from http.cookiejar import CookieJar
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", os.path.join(BASE, "data"))
os.makedirs(DATA, mode=0o700, exist_ok=True)
DB_PATH = os.path.join(DATA, "app.db")
KEY_PATH = os.path.join(DATA, "secret.key")
A = "/" + os.environ.get("ADMIN_PATH", "admin").strip("/")   # آدرس پنل ادمین
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"  # پشت HTTPS باید 1 باشد
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def load_secret():
    if not os.path.exists(KEY_PATH):
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(KEY_PATH) as f:
        return f.read().strip()


SECRET = os.environ.get("SECRET_KEY") or load_secret()  # روی هاست‌های موقت حتماً SECRET_KEY بدهید

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET,
    SESSION_COOKIE_NAME="__Host-s" if COOKIE_SECURE else "s",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Strict",
    MAX_CONTENT_LENGTH=64 * 1024,
)
if os.environ.get("BEHIND_PROXY") == "1":  # پشت nginx
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

DUMMY_HASH = generate_password_hash("dummy-password")

# ----------------------------------------------------------------- دیتابیس


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    create table if not exists settings(k text primary key, v text);
    create table if not exists users(
        id integer primary key autoincrement, name text not null,
        code_hash text unique not null, active integer default 1,
        expires_at integer, created integer, last_login integer);
    create table if not exists attempts(ip text, kind text, ts integer);
    create index if not exists ix_att on attempts(ip, kind, ts);
    """)
    if "uuid" not in [r[1] for r in c.execute("pragma table_info(users)")]:
        c.execute("alter table users add column uuid text")
    c.commit()
    c.close()
    os.chmod(DB_PATH, 0o600)


def get_setting(k, default=None):
    r = db().execute("select v from settings where k=?", (k,)).fetchone()
    return json.loads(r["v"]) if r else default


def set_setting(k, v):
    db().execute("insert into settings(k,v) values(?,?) "
                 "on conflict(k) do update set v=excluded.v", (k, json.dumps(v)))
    db().commit()


# ------------------------------------------------------- تبدیل کانفیگ

N_OPS = 4
EMPTY_OP = {"name": "", "scheme": "vless", "id": "", "address": "", "port": "", "remark": ""}
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
_XRAY = ["type", "security", "encryption", "flow", "sni", "host", "path", "mode", "fp", "alpn",
         "ech", "pbk", "sid", "spx", "serviceName", "authority", "headerType", "seed",
         "extra", "fm", "insecure", "allowInsecure"]
KNOWN = {  # فیلدهایی که همیشه نمایش داده می‌شوند (اگر در لینک نباشند خالی می‌مانند)
    "vless": _XRAY,
    "trojan": _XRAY,
    "vmess": ["net", "type", "host", "path", "tls", "sni", "alpn", "fp", "scy", "aid"],
    "ss": ["plugin", "type", "security", "sni", "host", "path"],
}
LONG_KEYS = {"extra", "fm", "ech", "alpn", "path", "pbk"}


def split_hostport(hp):
    if hp.startswith("["):
        h, _, rest = hp[1:].partition("]")
        return h, rest[1:] if rest.startswith(":") else ""
    if ":" in hp:
        h, p = hp.rsplit(":", 1)
        return h, p
    return hp, ""


def join_hostport(h, p):
    if ":" in h and not h.startswith("["):
        h = "[" + h + "]"
    return f"{h}:{p}" if p else h


def norm_op(o):
    d = dict(EMPTY_OP)
    d.update({k: str(o.get(k, "")) for k in EMPTY_OP if k != "scheme"})
    d["scheme"] = o.get("scheme") if o.get("scheme") in KNOWN else "vless"
    d["params"] = {str(k): str(v) for k, v in (o.get("params") or {}).items()}
    return d


def get_ops():
    saved = list(get_setting("ops", []))
    saved += [{}] * (N_OPS - len(saved))
    return [norm_op(o) for o in saved[:N_OPS]]


def parse_link(link):
    """لینک را به فیلدهای جدا تبدیل می‌کند (فیلدهای ناموجود خالی می‌مانند)."""
    link = (link or "").strip()
    if "\n" in link or "://" not in link:
        raise ValueError("یک لینک کامل در یک خط وارد کنید")
    scheme = link.split("://", 1)[0].lower()
    if scheme not in KNOWN:
        raise ValueError("فقط vmess / vless / trojan / ss پشتیبانی می‌شود")
    if scheme == "vmess":
        raw = link[8:].strip()
        try:
            j = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
            assert isinstance(j, dict)
        except Exception:
            raise ValueError("vmess نامعتبر است")
        params = {k: str(j.get(k, "")) for k in KNOWN["vmess"]}
        for k, v in j.items():
            if k not in params and k not in ("v", "ps", "add", "port", "id") and KEY_RE.match(str(k)):
                params[str(k)] = str(v)
        return {"scheme": "vmess", "id": str(j.get("id", "")), "address": str(j.get("add", "")),
                "port": str(j.get("port", "")), "remark": str(j.get("ps", "")), "params": params}
    u = urlsplit(link)
    userinfo, at, hp = u.netloc.rpartition("@")
    if not at:
        raise ValueError("فرمت لینک پشتیبانی نمی‌شود")
    host, port = split_hostport(hp)
    params = {k: "" for k in KNOWN[scheme]}
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        if KEY_RE.match(k):
            params[k] = v
    return {"scheme": scheme, "id": userinfo, "address": host, "port": port,
            "remark": unquote(u.fragment), "params": params}


def build_link(c):
    """از فیلدها لینک نهایی می‌سازد؛ فیلدهای خالی در لینک نمی‌آیند."""
    if not c["id"] or not c["address"]:
        raise ValueError("مشخصات ناقص است (UUID و Address لازم‌اند)")
    if c["scheme"] == "vmess":
        j = {"v": "2", "ps": c["remark"], "add": c["address"], "port": c["port"], "id": c["id"]}
        j.update({k: v for k, v in c["params"].items() if v != ""})
        out = json.dumps(j, ensure_ascii=False, separators=(",", ":"))
        return "vmess://" + base64.b64encode(out.encode()).decode()
    q = [(k, v) for k, v in c["params"].items() if v != ""]
    return urlunsplit((c["scheme"], f"{c['id']}@{join_hostport(c['address'], c['port'])}", "",
                       urlencode(q, quote_via=quote), quote(c["remark"])))


def field_keys(op):
    base = KNOWN[op["scheme"]]
    return base + [k for k in op["params"] if k not in base]


def read_op(form, i, old):
    old = norm_op(old)
    c = dict(old)
    pre = f"op{i}_"
    for k in ("name", "id", "address", "port", "remark"):
        c[k] = (form.get(pre + k) or "").strip()
    if c["address"] and not HOST_RE.match(c["address"]):
        raise ValueError("Address نامعتبر است")
    if c["port"] and not (c["port"].isdigit() and 1 <= int(c["port"]) <= 65535):
        raise ValueError("پورت نامعتبر است")
    if c["id"] and (len(c["id"]) > 300 or re.search(r"[\s@/?#]", c["id"])):
        raise ValueError("UUID / رمز نامعتبر است")
    if len(c["remark"]) > 80 or "\n" in c["remark"] or len(c["name"]) > 40:
        raise ValueError("نام یا Remark نامعتبر است")
    params = {k: (form.get(f"{pre}p_{k}") or "").strip() for k in field_keys(old)}
    nk, nv = (form.get(pre + "newk") or "").strip(), (form.get(pre + "newv") or "").strip()
    if nk:
        if not KEY_RE.match(nk):
            raise ValueError("نام فیلد جدید نامعتبر است")
        params[nk] = nv
    if any(len(v) > 4000 for v in params.values()):
        raise ValueError("یکی از مقادیر خیلی طولانی است")
    c["params"] = params
    return c


def build_configs(uid=None):
    res = []
    for i, op in enumerate(get_ops()):
        try:
            link, err = build_link(dict(op, id=uid or op["id"])), None
        except ValueError as e:
            link, err = "", str(e)
        res.append({"name": op["name"] or f"اپراتور {i + 1}", "link": link, "err": err, "empty": not (op["address"] or op["id"])})
    return res


# ---------------------------------------------------------------- امنیت


def client_ip():
    return request.remote_addr or "?"


def blocked(kind, limit, window=900):
    n = db().execute("select count(*) from attempts where ip=? and kind=? and ts>?",
                     (client_ip(), kind, int(time.time()) - window)).fetchone()[0]
    return n >= limit


def record_fail(kind):
    now = int(time.time())
    db().execute("insert into attempts values(?,?,?)", (client_ip(), kind, now))
    db().execute("delete from attempts where ts<?", (now - 86400,))
    db().commit()
    time.sleep(0.4)


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def code_hash(code):
    return hmac.new(SECRET.encode(), code.encode(), hashlib.sha256).hexdigest()


def norm_code(s):
    return re.sub(r"[^A-Za-z0-9]", "", s or "").upper()


def gen_code():
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(16))
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def user_valid(u):
    return bool(u and u["active"] and (not u["expires_at"] or u["expires_at"] > time.time()))


@app.before_request
def pre():
    g.nonce = secrets.token_urlsafe(16)
    if request.method == "POST":
        tok, sent = session.get("csrf", ""), request.form.get("csrf", "")
        if not tok or not hmac.compare_digest(tok.encode(), sent.encode()):
            abort(400)


@app.context_processor
def ctx():
    return {"csrf": csrf, "nonce": g.get("nonce", ""), "A": A}


@app.after_request
def headers(r):
    n = g.get("nonce", "")
    r.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'nonce-{n}'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    r.headers["X-Robots-Tag"] = "noindex, nofollow"
    if COOKIE_SECURE:
        r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r


def admin_required(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not session.get("admin") or time.time() - session.get("at", 0) > 7200:
            session.pop("admin", None)
            return redirect(A + "/login")
        return f(*a, **k)
    return w


# ------------------------------------------------------------ بخش کاربران


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if blocked("user", 8):
            flash("تلاش بیش از حد. ۱۵ دقیقه بعد دوباره امتحان کنید.", "err")
            return render_template("index.html"), 429
        code = norm_code(request.form.get("code"))
        u = None
        if len(code) >= 10:
            u = db().execute("select * from users where code_hash=?",
                             (code_hash(code),)).fetchone()
        if user_valid(u):
            session.clear()
            session["uid"], session["ut"] = u["id"], int(time.time())
            db().execute("update users set last_login=? where id=?", (int(time.time()), u["id"]))
            db().commit()
            return redirect("/configs")
        record_fail("user")
        flash("کد نامعتبر است.", "err")
    return render_template("index.html")


@app.route("/configs")
def configs():
    uid = session.get("uid")
    u = db().execute("select * from users where id=?", (uid,)).fetchone() if uid else None
    if not user_valid(u) or time.time() - session.get("ut", 0) > 43200:
        session.clear()
        return redirect("/")
    return render_template("configs.html", name=u["name"], cfgs=build_configs(u["uuid"]))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


# -------------------------------------------------------------- بخش ادمین


@app.route(A + "/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if blocked("admin", 5):
            flash("تلاش بیش از حد. ۱۵ دقیقه بعد دوباره امتحان کنید.", "err")
            return render_template("admin_login.html"), 429
        cred = get_setting("admin")
        user_ok = bool(cred) and hmac.compare_digest(
            cred["user"].encode(), (request.form.get("u") or "").encode())
        pw_ok = check_password_hash(cred["hash"] if cred else DUMMY_HASH,
                                    request.form.get("p") or "")
        if cred and user_ok and pw_ok:
            session.clear()
            session["admin"], session["at"] = True, int(time.time())
            return redirect(A)
        record_fail("admin")
        flash("نام کاربری یا رمز اشتباه است.", "err")
    return render_template("admin_login.html")


@app.route(A + "/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(A + "/login")


def field_rows(op):
    rows = []
    for k in field_keys(op):
        v = op["params"].get(k, "")
        rows.append((k, v, k in LONG_KEYS or len(v) > 50))
    return rows


@app.route(A)
@admin_required
def admin_home():
    users = db().execute("select * from users order by id desc").fetchall()
    ops = get_ops()
    return render_template("admin.html", users=users, ops=ops,
                           rows=[field_rows(o) for o in ops], cfgs=build_configs(),
                           now=int(time.time()))


@app.route(A + "/op/<int:i>/<action>", methods=["POST"])
@admin_required
def op_action(i, action):
    if not 0 <= i < N_OPS or action not in ("parse", "save", "copy"):
        abort(404)
    ops = get_ops()
    try:
        if action == "parse":
            c = parse_link(request.form.get("link"))
            c["name"] = ops[i]["name"]
            ops[i] = norm_op(c)
        elif action == "save":
            ops[i] = read_op(request.form, i, ops[i])
        else:  # copy از اپراتور دیگر
            c = norm_op(ops[0])
            c["name"] = ops[i]["name"]
            ops[i] = c
    except ValueError as e:
        flash(str(e), "err")
        return redirect(A)
    set_setting("ops", ops)
    flash("ذخیره شد.", "ok")
    return redirect(A)


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


# ------------------------------------------------------------ اتصال به 3x-ui (فقط خواندن)
_xui_cache = {"t": 0, "v": None}


def _xui_call(opener, base, method, path, form=None):
    h = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest",
         "User-Agent": "Mozilla/5.0 (compatible; V2rayPanel/1.0)"}
    if os.environ.get("XUI_TOKEN"):
        h["Authorization"] = "Bearer " + os.environ["XUI_TOKEN"]
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(base + path, data=body, method=method, headers=h)
    try:
        with opener.open(req, timeout=6) as r:
            raw = r.read(8_000_000)
    except urllib.error.HTTPError as e:
        try:
            snip = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", e.read(3000).decode("utf-8", "replace"))).strip()[:150]
        except Exception:
            snip = ""
        cf = " (از Cloudflare)" if "cloudflare" in str(e.headers.get("Server", "")).lower() else ""
        raise RuntimeError(f"HTTP {e.code} از {path}{cf}" + (f" — {snip}" if snip else ""))
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"اتصال به 3x-ui ممکن نیست: {getattr(e, 'reason', e)}")
    try:
        return json.loads(raw)
    except ValueError:
        raise RuntimeError(f"پاسخ نامعتبر از {path} (آدرس یا مسیر پایه اشتباه است؟)")


def xui_clients():
    """همه کلاینت‌های 3x-ui را می‌خواند (کش ۱۵ ثانیه‌ای)."""
    now = time.time()
    if _xui_cache["v"] is not None and now - _xui_cache["t"] < 15:
        return _xui_cache["v"]
    base = os.environ.get("XUI_URL", "").rstrip("/")
    if not base:
        raise RuntimeError("XUI_URL تنظیم نشده است")
    ctx = ssl._create_unverified_context() if os.environ.get("XUI_VERIFY", "1") != "1" else None
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()),
                                         urllib.request.HTTPSHandler(context=ctx))
    if not os.environ.get("XUI_TOKEN"):
        u, p = os.environ.get("XUI_USER"), os.environ.get("XUI_PASS")
        if not (u and p):
            raise RuntimeError("XUI_TOKEN یا XUI_USER و XUI_PASS را تنظیم کنید")
        r = _xui_call(opener, base, "POST", "/login", {"username": u, "password": p})
        if not r.get("success"):
            raise RuntimeError("ورود به 3x-ui ناموفق: " + str(r.get("msg", ""))[:100])
    try:
        r = _xui_call(opener, base, "GET", "/panel/api/inbounds/list")
    except RuntimeError as e:
        if "HTTP 404" not in str(e):
            raise
        r = _xui_call(opener, base, "POST", "/panel/inbound/list", {})
    if not r.get("success"):
        raise RuntimeError("3x-ui: " + str(r.get("msg", ""))[:100])
    out = []
    for ib in r.get("obj") or []:
        try:
            cfg = ib.get("settings") or {}
            clients = (json.loads(cfg) if isinstance(cfg, (str, bytes)) else cfg).get("clients") or ib.get("clients") or []
        except (ValueError, TypeError, AttributeError):
            continue
        stats = {s.get("email"): s for s in (ib.get("clientStats") or []) if isinstance(s, dict)}
        for c in clients:
            if not isinstance(c, dict):
                continue
            st = stats.get(c.get("email"), {})
            out.append({
                "uuid": str(c.get("id") or c.get("password") or ""),
                "email": str(c.get("email") or ""),
                "name": str(c.get("comment") or c.get("email") or ""),
                "enable": bool(c.get("enable", True)) and bool(st.get("enable", True)),
                "used": int(st.get("up") or 0) + int(st.get("down") or 0),
                "total": int(c.get("totalGB") or st.get("total") or 0),
                "expiry": int(c.get("expiryTime") or st.get("expiryTime") or 0),
                "inbound": str(ib.get("remark") or ib.get("id") or ""),
                "protocol": str(ib.get("protocol") or ""),
            })
    _xui_cache.update(t=now, v=out)
    return out


@app.route(A + "/xui")
@admin_required
def admin_xui():
    err, rows, missing = None, [], []
    try:
        clients = xui_clients()
    except RuntimeError as e:
        clients, err = [], str(e)
    mine = {(r["uuid"] or "").lower(): r["name"]
            for r in db().execute("select name, uuid from users")}
    now_ms = int(time.time() * 1000)
    for c in clients:
        if c["total"] > 0 and c["used"] >= c["total"]:
            state = "اتمام حجم"
        elif c["expiry"] > 0 and c["expiry"] < now_ms:
            state = "منقضی"
        elif not c["enable"]:
            state = "غیرفعال"
        else:
            state = "فعال"
        if c["expiry"] > 0:
            exp = time.strftime("%Y-%m-%d", time.localtime(c["expiry"] / 1000))
        elif c["expiry"] < 0:
            exp = f"{round(-c['expiry'] / 86400000)} روز پس از اولین اتصال"
        else:
            exp = "نامحدود"
        used = f"{c['used'] / 2**30:.2f} / " + (f"{c['total'] / 2**30:.0f} GB" if c["total"] else "نامحدود")
        rows.append(dict(c, state=state, exp=exp, usedtxt=used,
                         inpanel=c["uuid"].lower() in mine))
    have = {c["uuid"].lower() for c in clients}
    if clients:
        missing = [n for u, n in mine.items() if u and u not in have]
    return render_template("xui.html", err=err, rows=rows, missing=missing,
                           n_ok=sum(r["state"] == "فعال" for r in rows),
                           n_out=sum(not r["inpanel"] for r in rows))


@app.route(A + "/user_add", methods=["POST"])
@admin_required
def user_add():
    days = (request.form.get("days") or "").strip()
    exp = int(time.time()) + int(days) * 86400 if days.isdigit() and int(days) > 0 else None
    ok, errs = 0, []
    for ln in (request.form.get("users") or "").splitlines()[:200]:
        parts = [p for p in re.split(r"[\s,;]+", ln.strip()) if p]
        if not parts:
            continue
        last = parts[-1]
        has_id = bool(UUID_RE.match(last))
        if not has_id and len(last) >= 30:
            errs.append(f"UUID نامعتبر: {last[:40]}")
            continue
        name = " ".join(parts[:-1] if has_id else parts)[:60]
        if not name:
            errs.append(f"نام ندارد: {ln[:40]}")
            continue
        uid = last.lower() if has_id else str(_uuid.uuid4())
        try:
            db().execute("insert into users(name,uuid,code_hash,expires_at,created) values(?,?,?,?,?)",
                         (name, uid, code_hash(norm_code(uid)), exp, int(time.time())))
            ok += 1
        except sqlite3.IntegrityError:
            errs.append(f"UUID تکراری: {name}")
    db().commit()
    if ok:
        flash(f"{ok} کاربر اضافه شد. UUID هر کاربر را در جدول پایین ببینید و روی سرور هم تعریف کنید.", "ok")
    for e in errs:
        flash(e, "err")
    if not ok and not errs:
        flash("چیزی وارد نشد.", "err")
    return redirect(A)


@app.route(A + "/user/<int:uid>/<action>", methods=["POST"])
@admin_required
def user_action(uid, action):
    d = db()
    if action == "toggle":
        d.execute("update users set active=1-active where id=?", (uid,))
    elif action == "delete":
        d.execute("delete from users where id=?", (uid,))
    else:
        abort(404)
    d.commit()
    return redirect(A)


# ---------------------------------------------------------------- قالب‌ها

T = {}
T["xui.html"] = """{% extends "base.html" %}{% block body %}
<div class="card"><b>وضعیت UUIDها در 3x-ui</b>
<a href="{{ A }}"><button type="button" class="s">بازگشت</button></a>
<a href="{{ A }}/xui"><button type="button">بروزرسانی</button></a></div>
{% if err %}<div class="msg err">{{ err }}</div>
<div class="card"><small>برای اتصال، در فایل سرویس XUI_URL و (XUI_TOKEN یا XUI_USER و XUI_PASS) را تنظیم کنید.</small></div>
{% else %}
<div class="card"><small>{{ rows|length }} کلاینت — فعال: {{ n_ok }} — در پنل تعریف نشده: {{ n_out }}</small>
<input id="q" placeholder="جستجوی نام یا UUID">
<div style="overflow-x:auto"><table id="t">
<tr><th>نام (کامنت)</th><th>UUID</th><th>وضعیت</th><th>مصرف</th><th>انقضا</th><th>اینباند</th><th>در پنل</th></tr>
{% for r in rows %}<tr><td>{{ r.name }}{% if r.email and r.email != r.name %}<br><small>{{ r.email }}</small>{% endif %}</td>
<td class="u">{{ r.uuid }}</td><td>{{ r.state }}</td><td>{{ r.usedtxt }}</td><td>{{ r.exp }}</td><td>{{ r.inbound }}</td>
<td>{{ '✓' if r.inpanel else '✗' }}</td></tr>{% endfor %}
</table></div></div>
{% if missing %}<div class="card"><b>کاربران پنل که UUIDشان در 3x-ui نیست</b><br>{{ missing|join('، ') }}</div>{% endif %}
<script nonce="{{ nonce }}">
document.getElementById('q').oninput=function(){var v=this.value.toLowerCase();
document.querySelectorAll('#t tr').forEach(function(r,i){if(i)r.style.display=r.textContent.toLowerCase().indexOf(v)<0?'none':''})};
</script>{% endif %}{% endblock %}"""
T["base.html"] = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{% block title %}پنل{% endblock %}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap">
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel2:#0d1425;--text:#edf2ff;--muted:#a5b1ca;--border:#293550;--accent:#7c9cff;--accent2:#98b0ff;--good:#69d6a2;--bad:#ff929b}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(ellipse at top,#172448 0%,var(--bg) 52%) fixed;color:var(--text);font-family:"Vazirmatn",Tahoma,sans-serif;line-height:1.7}
.w{width:min(920px,calc(100% - 28px));margin:34px auto}
.eyebrow{color:var(--accent);font-size:.88rem;font-weight:700;letter-spacing:.04em}
.card{margin:18px 0;padding:clamp(16px,3vw,26px);background:rgba(18,26,45,.94);border:1px solid var(--border);border-radius:18px;box-shadow:0 16px 44px rgba(0,0,0,.18);overflow-x:auto}
h2,h3{margin:0 0 12px;font-size:1.15rem}
label{display:block;margin:10px 0 8px;font-weight:600}
input,textarea{display:block;width:100%;margin:0 0 10px;padding:12px 14px;border:1px solid #354463;border-radius:12px;background:var(--panel2);color:#e6edff;font:inherit}
textarea{direction:ltr;text-align:left;font:13px/1.8 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;resize:vertical}
input:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:2px}
input:disabled{opacity:.6}
::placeholder{color:#6f7d9c}
button{display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:10px;padding:10px 17px;font:inherit;font-weight:700;color:#0a1230;background:var(--accent);cursor:pointer;transition:transform .12s ease,background .12s ease}
button:hover{transform:translateY(-1px);background:var(--accent2)}
button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
button.s{color:var(--text);background:#26334f;border:1px solid #3b4a6b}
button.s:hover{background:#304060}
button.d{color:#ffd9dd;background:#4a2430;border:1px solid #7a3a4a}
button.d:hover{background:#5b2c3a}
.msg{padding:12px 14px;border-radius:12px;margin:12px 0;word-break:break-all;border:1px solid}
.ok{color:var(--good);background:rgba(105,214,162,.1);border-color:rgba(105,214,162,.35)}
.err{color:var(--bad);background:rgba(255,146,155,.1);border-color:rgba(255,146,155,.35)}
table{width:100%;border-collapse:collapse;font-size:.88rem}
td,th{padding:8px 6px;border-bottom:1px solid var(--border);text-align:right}
th{color:var(--muted);font-weight:600}
form.i{display:inline}
.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0 10px}
.w2{grid-column:1/-1}
hr{border:0;border-top:1px solid var(--border);margin:14px 0}
small{color:var(--muted)}
.u{direction:ltr;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;word-break:break-all}
td.u{white-space:nowrap;word-break:normal}
@media(max-width:560px){.w{margin:22px auto}}
@media(prefers-reduced-motion:reduce){button{transition:none}button:hover{transform:none}}
</style></head><body><div class="w"><div class="eyebrow">VLESS · پنل کانفیگ</div>
{% with m = get_flashed_messages(with_categories=true) %}{% for c,t in m %}<div class="msg {{ c }}">{{ t }}</div>{% endfor %}{% endwith %}
{% block body %}{% endblock %}</div></body></html>"""

T["index.html"] = """{% extends "base.html" %}{% block body %}
<div class="card"><h2>ورود</h2><form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf() }}">
<label>UUID کانفیگ شما</label><input name="code" dir="ltr" required autofocus>
<button>ورود</button></form></div>{% endblock %}"""

T["configs.html"] = """{% extends "base.html" %}{% block body %}
<div class="card"><b>سلام {{ name }}</b>
<form method="post" action="/logout" class="i"><input type="hidden" name="csrf" value="{{ csrf() }}"> <button class="s">خروج</button></form></div>
{% for c in cfgs if not c.empty %}<div class="card"><h3>{{ c.name }}</h3>
{% if c.err %}<div class="msg err">{{ c.err }}</div>{% else %}
<textarea id="c{{ loop.index }}" rows="4" readonly>{{ c.link }}</textarea>
<button data-copy="c{{ loop.index }}">کپی</button>{% endif %}</div>{% endfor %}{% if cfgs|rejectattr("empty")|list|length == 0 %}<div class="card">هنوز کانفیگی برای شما تعریف نشده است.</div>{% endif %}
<script nonce="{{ nonce }}">
document.querySelectorAll('[data-copy]').forEach(function(b){b.onclick=function(){
var t=document.getElementById(b.dataset.copy);t.select();
try{navigator.clipboard.writeText(t.value)}catch(e){document.execCommand('copy')}
b.textContent='کپی شد'}});
</script>{% endblock %}"""

T["admin_login.html"] = """{% extends "base.html" %}{% block body %}
<div class="card"><h2>ورود ادمین</h2><form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf() }}">
<label>نام کاربری</label><input name="u" dir="ltr" required>
<label>رمز عبور</label><input name="p" type="password" dir="ltr" required>
<button>ورود</button></form></div>{% endblock %}"""

T["admin.html"] = """{% extends "base.html" %}{% block body %}
<div class="card"><b>پنل مدیریت</b>
<a href="{{ A }}/xui"><button type="button" class="s">وضعیت 3x-ui</button></a>
<form method="post" action="{{ A }}/logout" class="i"><input type="hidden" name="csrf" value="{{ csrf() }}"> <button class="s">خروج</button></form></div>

{% for i in range(ops|length) %}{% set op = ops[i] %}
<div class="card"><h3>اپراتور {{ i+1 }}{% if op.name %} — {{ op.name }}{% endif %}</h3>

<form method="post" action="{{ A }}/op/{{ i }}/parse"><input type="hidden" name="csrf" value="{{ csrf() }}">
<label>لینک کانفیگ را اینجا بچسبانید</label>
<textarea name="link" rows="3" placeholder="vless://..."></textarea>
<button>تجزیه و پر کردن فیلدها</button></form>
<hr>
<form method="post" action="{{ A }}/op/{{ i }}/save"><input type="hidden" name="csrf" value="{{ csrf() }}">
<div class="g">
<div><label>نام نمایشی (برای کاربر)</label><input name="op{{ i }}_name" value="{{ op.name }}"></div>
<div><label>Remark (نام کانفیگ)</label><input name="op{{ i }}_remark" value="{{ op.remark }}"></div>
<div><label>پروتکل</label><input dir="ltr" value="{{ op.scheme }}" disabled></div>
<div><label>UUID / Password</label><input dir="ltr" name="op{{ i }}_id" value="{{ op.id }}"></div>
<div><label>Address</label><input dir="ltr" name="op{{ i }}_address" value="{{ op.address }}"></div>
<div><label>Port</label><input dir="ltr" name="op{{ i }}_port" value="{{ op.port }}"></div>
{% for k,v,long in rows[i] %}<div class="{{ 'w2' if long }}"><label>{{ k }}</label>
{% if long %}<textarea name="op{{ i }}_p_{{ k }}" rows="3">{{ v }}</textarea>{% else %}<input dir="ltr" name="op{{ i }}_p_{{ k }}" value="{{ v }}">{% endif %}</div>{% endfor %}
<div><label>فیلد جدید: نام</label><input dir="ltr" name="op{{ i }}_newk"></div>
<div><label>فیلد جدید: مقدار</label><input dir="ltr" name="op{{ i }}_newv"></div>
</div>
<small>فیلد خالی در لینک نهایی قرار نمی‌گیرد.</small><br>
<button>ذخیره</button></form>
{% if i > 0 %}<form method="post" action="{{ A }}/op/{{ i }}/copy" class="i"><input type="hidden" name="csrf" value="{{ csrf() }}"><button class="s">کپی همه فیلدها از اپراتور ۱</button></form>{% endif %}

<label>لینک نهایی</label>
{% if cfgs[i].err %}<div class="msg err">{{ cfgs[i].err }}</div>{% else %}<textarea rows="3" readonly>{{ cfgs[i].link }}</textarea>{% endif %}
</div>{% endfor %}

<div class="card"><h3>افزودن کاربر</h3>
<form method="post" action="{{ A }}/user_add" autocomplete="off"><input type="hidden" name="csrf" value="{{ csrf() }}">
<label>هر خط یک کاربر: «نام UUID» (اگر UUID ننویسید، خودکار ساخته می‌شود)</label>
<textarea name="users" rows="5" placeholder="ali 7e2009ee-9be3-4011-899d-784aeeda1a4b"></textarea>
<label>مدت اعتبار (روز، اختیاری)</label><input name="days" dir="ltr">
<button>افزودن</button></form>
<small>همین UUID باید روی سرور (inbound) هم تعریف شده باشد.</small></div>

<div class="card"><h3>کاربران ({{ users|length }})</h3><table>
<tr><th>نام</th><th>UUID</th><th>وضعیت</th><th>انقضا</th><th>آخرین ورود</th><th></th></tr>
{% for u in users %}<tr><td>{{ u.name }}</td><td class="u">{{ u.uuid or '-' }}</td>
<td>{% if not u.active %}غیرفعال{% elif u.expires_at and u.expires_at < now %}منقضی{% else %}فعال{% endif %}</td>
<td>{{ (u.expires_at|int|timestamp) if u.expires_at else '-' }}</td>
<td>{{ (u.last_login|int|timestamp) if u.last_login else '-' }}</td>
<td>{% for a,l,c in (('toggle','فعال/غیرفعال','s'),('delete','حذف','d')) %}
<form method="post" action="{{ A }}/user/{{ u.id }}/{{ a }}" class="i"><input type="hidden" name="csrf" value="{{ csrf() }}"><button class="{{ c }}">{{ l }}</button></form> {% endfor %}</td></tr>{% endfor %}
</table></div>{% endblock %}"""

app.jinja_env.loader = DictLoader(T)
app.jinja_env.filters["timestamp"] = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t))

init_db()


def bootstrap_admin():
    """اگر ADMIN_USER و ADMIN_PASS در متغیرهای محیطی باشند، ادمین را می‌سازد/به‌روز می‌کند."""
    u, p = os.environ.get("ADMIN_USER"), os.environ.get("ADMIN_PASS")
    if not u or not p:
        return
    if len(p) < 12:
        print("ADMIN_PASS باید حداقل ۱۲ کاراکتر باشد؛ نادیده گرفته شد.", file=sys.stderr)
        return
    with app.app_context():
        cred = get_setting("admin")
        if not cred or cred["user"] != u or not check_password_hash(cred["hash"], p):
            set_setting("admin", {"user": u, "hash": generate_password_hash(p)})


bootstrap_admin()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        user = input("نام کاربری ادمین: ").strip()
        pw = getpass.getpass("رمز عبور (حداقل ۱۲ کاراکتر): ")
        if not user or len(pw) < 12 or pw != getpass.getpass("تکرار رمز: "):
            sys.exit("نام کاربری خالی، رمز کوتاه یا تکرار نادرست.")
        with app.app_context():
            set_setting("admin", {"user": user, "hash": generate_password_hash(pw)})
        print("ادمین ذخیره شد.")
    else:
        print("دستور: python app.py init   |   اجرا: gunicorn -w 2 -b 127.0.0.1:8000 app:app")
