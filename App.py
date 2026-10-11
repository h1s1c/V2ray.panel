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
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

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

EMPTY_OP = {"name": "", "address": "", "port": "", "sni": "", "host": "", "remark": ""}
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")


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


def transform(link, op):
    """لینک vmess/vless/trojan/ss را با تنظیمات اپراتور تغییر می‌دهد."""
    link = link.strip()
    if "://" not in link:
        raise ValueError("فرمت لینک نامعتبر است")
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        raw = link[8:].strip()
        try:
            j = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
        except Exception:
            raise ValueError("vmess نامعتبر است")
        if op["address"]:
            j["add"] = op["address"]
        if op["port"]:
            j["port"] = str(op["port"])
        if op["sni"]:
            j["sni"] = op["sni"]
        if op["host"]:
            j["host"] = op["host"]
        if op["remark"]:
            j["ps"] = op["remark"]
        out = json.dumps(j, ensure_ascii=False, separators=(",", ":"))
        return "vmess://" + base64.b64encode(out.encode()).decode()
    if scheme in ("vless", "trojan", "ss"):
        u = urlsplit(link)
        userinfo, at, hp = u.netloc.rpartition("@")
        if not at:
            raise ValueError("فرمت لینک پشتیبانی نمی‌شود")
        host, port = split_hostport(hp)
        if op["address"]:
            host = op["address"]
        if op["port"]:
            port = str(op["port"])
        q = parse_qsl(u.query, keep_blank_values=True)
        for key, val in (("sni", op["sni"]), ("host", op["host"])):
            if val:
                q = [(k, v) for k, v in q if k != key] + [(key, val)]
        frag = quote(op["remark"]) if op["remark"] else u.fragment
        return urlunsplit((u.scheme, f"{userinfo}@{join_hostport(host, port)}",
                           u.path, urlencode(q, quote_via=quote), frag))
    raise ValueError("فقط vmess / vless / trojan / ss پشتیبانی می‌شود")


def clean_op(form, i):
    op = {k: (form.get(f"op{i}_{k}") or "").strip() for k in EMPTY_OP}
    for k in ("address", "sni", "host"):
        if op[k] and not HOST_RE.match(op[k]):
            raise ValueError(f"مقدار «{k}» اپراتور {i + 1} نامعتبر است")
    if op["port"] and not (op["port"].isdigit() and 1 <= int(op["port"]) <= 65535):
        raise ValueError(f"پورت اپراتور {i + 1} نامعتبر است")
    if len(op["remark"]) > 80 or len(op["name"]) > 40 or "\n" in op["remark"]:
        raise ValueError(f"نام یا remark اپراتور {i + 1} نامعتبر است")
    return op


def build_configs():
    tpl = get_setting("template", "")
    ops = get_setting("ops", [dict(EMPTY_OP), dict(EMPTY_OP)])
    res = []
    for i, op in enumerate(ops):
        try:
            link = transform(tpl, op) if tpl else ""
            err = None if tpl else "هنوز کانفیگی ثبت نشده"
        except ValueError as e:
            link, err = "", str(e)
        res.append({"name": op["name"] or f"اپراتور {i + 1}", "link": link, "err": err})
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
        f"default-src 'none'; style-src 'nonce-{n}'; script-src 'nonce-{n}'; "
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
    return render_template("configs.html", name=u["name"], cfgs=build_configs())


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


@app.route(A)
@admin_required
def admin_home():
    users = db().execute("select * from users order by id desc").fetchall()
    ops = get_setting("ops", [dict(EMPTY_OP), dict(EMPTY_OP)])
    return render_template("admin.html", users=users, ops=ops,
                           tpl=get_setting("template", ""), cfgs=build_configs(),
                           now=int(time.time()))


@app.route(A + "/save", methods=["POST"])
@admin_required
def admin_save():
    tpl = (request.form.get("template") or "").strip()
    try:
        if "\n" in tpl or not tpl:
            raise ValueError("فقط یک لینک (در یک خط) وارد کنید")
        ops = [clean_op(request.form, i) for i in (0, 1)]
        for op in ops:
            transform(tpl, op)
    except ValueError as e:
        flash(str(e), "err")
        return redirect(A)
    set_setting("template", tpl)
    set_setting("ops", ops)
    flash("ذخیره شد.", "ok")
    return redirect(A)


@app.route(A + "/user_add", methods=["POST"])
@admin_required
def user_add():
    name = (request.form.get("name") or "").strip()[:60]
    custom = norm_code(request.form.get("code"))
    days = (request.form.get("days") or "").strip()
    if not name:
        flash("نام کاربر لازم است.", "err")
        return redirect(A)
    if custom and len(custom) < 10:
        flash("کد دلخواه باید حداقل ۱۰ حرف/عدد باشد.", "err")
        return redirect(A)
    code = custom or gen_code()
    exp = int(time.time()) + int(days) * 86400 if days.isdigit() and int(days) > 0 else None
    try:
        db().execute("insert into users(name,code_hash,expires_at,created) values(?,?,?,?)",
                     (name, code_hash(norm_code(code)), exp, int(time.time())))
        db().commit()
    except sqlite3.IntegrityError:
        flash("این کد قبلاً استفاده شده.", "err")
        return redirect(A)
    flash(f"کاربر {name} ساخته شد. کد ورود: {code}  (فقط همین یک بار نمایش داده می‌شود)", "ok")
    return redirect(A)


@app.route(A + "/user/<int:uid>/<action>", methods=["POST"])
@admin_required
def user_action(uid, action):
    d = db()
    if action == "toggle":
        d.execute("update users set active=1-active where id=?", (uid,))
    elif action == "delete":
        d.execute("delete from users where id=?", (uid,))
    elif action == "regen":
        code = gen_code()
        d.execute("update users set code_hash=? where id=?", (code_hash(norm_code(code)), uid))
        flash(f"کد جدید: {code}  (فقط همین یک بار نمایش داده می‌شود)", "ok")
    else:
        abort(404)
    d.commit()
    return redirect(A)


# ---------------------------------------------------------------- قالب‌ها

T = {}
T["base.html"] = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{% block title %}پنل{% endblock %}</title>
<style nonce="{{ nonce }}">
body{font-family:Tahoma,sans-serif;background:#f3f4f6;margin:0;color:#111}
.w{max-width:760px;margin:0 auto;padding:16px}
.card{background:#fff;border-radius:10px;padding:16px;margin:12px 0;box-shadow:0 1px 3px #0002}
input,textarea{width:100%;box-sizing:border-box;padding:9px;margin:4px 0 10px;border:1px solid #ccc;border-radius:6px;font-size:15px}
textarea{direction:ltr;font-family:monospace;font-size:13px}
button{background:#2563eb;color:#fff;border:0;border-radius:6px;padding:9px 16px;font-size:15px;cursor:pointer}
button.s{background:#6b7280}button.d{background:#dc2626}
.msg{padding:10px;border-radius:6px;margin:10px 0;word-break:break-all}
.ok{background:#dcfce7}.err{background:#fee2e2}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:6px;border-bottom:1px solid #eee;text-align:right}
form.i{display:inline}.g{display:grid;grid-template-columns:1fr 1fr;gap:0 10px}
fieldset{border:1px solid #ddd;border-radius:8px;margin:10px 0}small{color:#555}
</style></head><body><div class="w">
{% with m = get_flashed_messages(with_categories=true) %}{% for c,t in m %}<div class="msg {{ c }}">{{ t }}</div>{% endfor %}{% endwith %}
{% block body %}{% endblock %}</div></body></html>"""

T["index.html"] = """{% extends "base.html" %}{% block body %}
<div class="card"><h2>ورود</h2><form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf() }}">
<label>کد ورود</label><input name="code" dir="ltr" required autofocus>
<button>ورود</button></form></div>{% endblock %}"""

T["configs.html"] = """{% extends "base.html" %}{% block body %}
<div class="card"><b>سلام {{ name }}</b>
<form method="post" action="/logout" class="i"><input type="hidden" name="csrf" value="{{ csrf() }}"> <button class="s">خروج</button></form></div>
{% for c in cfgs %}<div class="card"><h3>{{ c.name }}</h3>
{% if c.err %}<div class="msg err">{{ c.err }}</div>{% else %}
<textarea id="c{{ loop.index }}" rows="4" readonly>{{ c.link }}</textarea>
<button data-copy="c{{ loop.index }}">کپی</button>{% endif %}</div>{% endfor %}
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
<form method="post" action="{{ A }}/logout" class="i"><input type="hidden" name="csrf" value="{{ csrf() }}"> <button class="s">خروج</button></form></div>

<div class="card"><h3>کانفیگ اصلی و تنظیم اپراتورها</h3>
<form method="post" action="{{ A }}/save"><input type="hidden" name="csrf" value="{{ csrf() }}">
<label>لینک کانفیگ (vless / vmess / trojan / ss)</label>
<textarea name="template" rows="4" required>{{ tpl }}</textarea>
<small>فیلدهای خالی = بدون تغییر نسبت به کانفیگ اصلی</small>
{% for i in (0,1) %}<fieldset><legend>اپراتور {{ i+1 }}</legend><div class="g">
<div><label>نام نمایشی</label><input name="op{{ i }}_name" value="{{ ops[i].name }}"></div>
<div><label>Remark (نام کانفیگ)</label><input name="op{{ i }}_remark" value="{{ ops[i].remark }}"></div>
<div><label>Address (IP/دامنه)</label><input dir="ltr" name="op{{ i }}_address" value="{{ ops[i].address }}"></div>
<div><label>Port</label><input dir="ltr" name="op{{ i }}_port" value="{{ ops[i].port }}"></div>
<div><label>SNI</label><input dir="ltr" name="op{{ i }}_sni" value="{{ ops[i].sni }}"></div>
<div><label>Host header</label><input dir="ltr" name="op{{ i }}_host" value="{{ ops[i].host }}"></div>
</div></fieldset>{% endfor %}
<button>ذخیره</button></form></div>

<div class="card"><h3>پیش‌نمایش</h3>
{% for c in cfgs %}<b>{{ c.name }}</b>{% if c.err %}<div class="msg err">{{ c.err }}</div>{% else %}
<textarea rows="3" readonly>{{ c.link }}</textarea>{% endif %}{% endfor %}</div>

<div class="card"><h3>افزودن کاربر</h3>
<form method="post" action="{{ A }}/user_add" autocomplete="off"><input type="hidden" name="csrf" value="{{ csrf() }}">
<div class="g"><div><label>نام کاربر</label><input name="name" required></div>
<div><label>مدت اعتبار (روز، اختیاری)</label><input name="days" dir="ltr"></div></div>
<label>کد ورود دلخواه (اختیاری، حداقل ۱۰ حرف/عدد؛ خالی = ساخت خودکار)</label><input name="code" dir="ltr">
<button>افزودن</button></form></div>

<div class="card"><h3>کاربران ({{ users|length }})</h3><table>
<tr><th>نام</th><th>وضعیت</th><th>انقضا</th><th>آخرین ورود</th><th></th></tr>
{% for u in users %}<tr><td>{{ u.name }}</td>
<td>{% if not u.active %}غیرفعال{% elif u.expires_at and u.expires_at < now %}منقضی{% else %}فعال{% endif %}</td>
<td>{{ (u.expires_at|int|timestamp) if u.expires_at else '-' }}</td>
<td>{{ (u.last_login|int|timestamp) if u.last_login else '-' }}</td>
<td>{% for a,l,c in (('toggle','فعال/غیرفعال','s'),('regen','کد جدید','s'),('delete','حذف','d')) %}
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
