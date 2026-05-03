"""
Flask Web UI for Secure Password Manager — Full Workflow (Modules 1-4)
Run:  python app.py   →   http://127.0.0.1:5000
"""
import os, json, sys, codecs
sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
from flask import Flask, request, render_template_string, redirect, url_for, session, flash

from pwm.vault import (
    create_vault, add_credential, retrieve_credential,
    list_credentials, update_credential, delete_credential
)
from pwm.elgamal import init as generate_elgamal_params
from pwm.signatures import sign_and_save_vault, verify_and_open_vault
from pwm.dh_export import (
    generate_dh_params, generate_dh_keypair, sign_dh_public, verify_dh_public,
    build_export_package, consume_export_package, load_dh_params, save_dh_params
)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─── Helpers ──────────────────────────────────────────────────────────────────
def vault_path():
    return f"{session['user']}_vault.json"

def priv_path(user=None):
    return f"{user or session['user']}_private.json"

def pub_path(user=None):
    return f"{user or session['user']}_public.json"

def _load_key(path, key_field):
    if not os.path.exists(path): return None, None, None
    with open(path) as f:
        d = json.load(f)
    return d[key_field], d["Prime"], d["Primitive Root"]

def load_private(path): return _load_key(path, "privateKey")
def load_public(path):  return _load_key(path, "publicKey")

def sign_vault_now():
    pk, p, a = load_private(priv_path())
    if pk: sign_and_save_vault(vault_path(), pk, p, a)

def load_or_generate_dh_params():
    if not os.path.exists("pwm/dh_params.json"):
        q, alpha = generate_dh_params(512)
        if not os.path.exists("pwm"): os.makedirs("pwm")
        save_dh_params(q, alpha, "pwm/dh_params.json")
    return load_dh_params("pwm/dh_params.json")

# ─── HTML ─────────────────────────────────────────────────────────────────────
PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Password Manager</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0f0f1a;color:#e0e0e8;min-height:100vh}
nav{background:rgba(20,20,40,.85);backdrop-filter:blur(12px);border-bottom:1px solid rgba(255,255,255,.06);padding:16px 32px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:10}
nav .logo{font-size:22px;font-weight:700;background:linear-gradient(135deg,#7c5cfc,#00d4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
nav .pill{margin-left:auto;background:rgba(124,92,252,.15);border:1px solid rgba(124,92,252,.3);padding:6px 16px;border-radius:20px;font-size:13px;color:#a78bfa}
nav a.lo{color:#f87171;text-decoration:none;font-size:13px;margin-left:12px}
.container{max-width:820px;margin:40px auto;padding:0 20px}
.card{background:rgba(22,22,42,.7);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:28px;margin-bottom:24px;transition:box-shadow .2s}
.card:hover{box-shadow:0 0 30px rgba(124,92,252,.08)}
.card h2{font-size:18px;font-weight:600;margin-bottom:16px;color:#c4b5fd}
form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:#9ca3af;flex:1;min-width:140px}
input[type=text],input[type=password]{background:#1a1a2e;border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:10px 12px;color:#e0e0e8;font-size:14px;outline:none;transition:border .2s}
input:focus{border-color:#7c5cfc}
button{background:linear-gradient(135deg,#7c5cfc,#6d28d9);color:#fff;border:none;border-radius:8px;padding:10px 20px;font-size:14px;font-weight:500;cursor:pointer;transition:opacity .2s,transform .1s}
button:hover{opacity:.9;transform:translateY(-1px)} button:active{transform:translateY(0)}
.btn-red{background:linear-gradient(135deg,#ef4444,#b91c1c)}
.btn-teal{background:linear-gradient(135deg,#14b8a6,#0d9488)}
.btn-amber{background:linear-gradient(135deg,#f59e0b,#d97706)}
table{width:100%;border-collapse:collapse;margin-top:12px}
th{text-align:left;padding:10px 12px;color:#9ca3af;font-size:12px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid rgba(255,255,255,.06)}
td{padding:10px 12px;font-size:14px;border-bottom:1px solid rgba(255,255,255,.04)}
tr:hover td{background:rgba(124,92,252,.04)}
.mono{font-family:'Courier New',monospace;color:#a5f3fc;letter-spacing:.3px}
.flash{padding:12px 18px;border-radius:8px;margin-bottom:18px;font-size:14px}
.flash.ok{background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.25);color:#6ee7b7}
.flash.err{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.25);color:#fca5a5}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{width:380px}
.login-box h1{font-size:28px;font-weight:700;text-align:center;margin-bottom:8px;background:linear-gradient(135deg,#7c5cfc,#00d4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.login-box p.sub{text-align:center;color:#6b7280;font-size:13px;margin-bottom:28px}
.login-box form{flex-direction:column} .login-box label{width:100%} .login-box button{width:100%;margin-top:6px}
.or{text-align:center;color:#6b7280;font-size:12px;margin:8px 0}
.empty{text-align:center;padding:32px;color:#6b7280} .empty span{font-size:36px;display:block;margin-bottom:8px}
.note{font-size:12px;color:#6b7280;margin-top:8px}
details{margin-top:12px} details summary{cursor:pointer;color:#a78bfa;font-size:13px}
</style>
</head>
<body>
{% if not session.get('user') %}
<div class="login-wrap"><div class="card login-box">
  <h1>🔐 Vault</h1><p class="sub">Secure Password Manager</p>
  {% for m in get_flashed_messages(with_categories=true) %}
    <div class="flash {{ 'ok' if m[0]=='success' else 'err' }}">{{ m[1] }}</div>
  {% endfor %}
  <form method="POST" action="/login">
    <label>Username <input type="text" name="user" required></label>
    <label>Master Password <input type="password" name="pw" required></label>
    <button type="submit">Unlock Vault</button>
  </form>
  <p class="or">— or —</p>
  <form method="POST" action="/create">
    <label>New Username <input type="text" name="user" required></label>
    <label>Master Password <input type="password" name="pw" required></label>
    <button class="btn-teal" type="submit">Create New Vault + Keys</button>
  </form>
  <p class="note">Creating a vault also generates your ElGamal key pair (Module 1).</p>
</div></div>
{% else %}
<nav>
  <span class="logo">🔐 Vault</span>
  <span class="pill">{{ session['user'] }}</span>
  <a class="lo" href="/logout">Sign out</a>
</nav>
<div class="container">
  {% for m in get_flashed_messages(with_categories=true) %}
    <div class="flash {{ 'ok' if m[0]=='success' else 'err' }}">{{ m[1] }}</div>
  {% endfor %}

  <!-- Add credential -->
  <div class="card"><h2>➕ Add Credential</h2>
    <form method="POST" action="/add">
      <label>Website <input type="text" name="site" required></label>
      <label>Username <input type="text" name="uname" required></label>
      <label>Password <input type="text" name="pword" required></label>
      <button type="submit">Add</button>
    </form>
  </div>

  <!-- Credentials list -->
  <div class="card"><h2>📋 Your Credentials</h2>
    {% if creds %}
    <table>
      <tr><th>Website</th><th>Username</th><th>Password</th><th></th></tr>
      {% for c in creds %}
      <tr>
        <td>{{ c.website }}</td><td>{{ c.username }}</td><td class="mono">{{ c.password }}</td>
        <td><form method="POST" action="/delete" style="display:inline">
          <input type="hidden" name="site" value="{{ c.website }}">
          <input type="hidden" name="uname" value="{{ c.username }}">
          <button class="btn-red" style="padding:5px 12px;font-size:12px">✕</button>
        </form></td>
      </tr>
      {% endfor %}
    </table>
    {% else %}<div class="empty"><span>🗄️</span>No credentials yet.</div>{% endif %}
  </div>

  <!-- Update -->
  <div class="card"><h2>✏️ Update Password</h2>
    <form method="POST" action="/update">
      <label>Website <input type="text" name="site" required></label>
      <label>Username <input type="text" name="uname" required></label>
      <label>New Password <input type="text" name="new_pword" required></label>
      <button type="submit">Update</button>
    </form>
  </div>

  <!-- Export -->
  <div class="card"><h2>📤 Export Vault (Module 4)</h2>
    <details><summary>Step 1 — Generate DH Offer</summary>
      <form method="POST" action="/export-init" style="margin-top:10px">
        <button class="btn-amber" type="submit">Generate DH Offer</button>
      </form>
      <p class="note">Creates {{ session['user'] }}_dh_offer.json for the recipient.</p>
    </details>
    <details><summary>Step 2 — Finalize Export</summary>
      <form method="POST" action="/export-finalize" style="margin-top:10px">
        <label>Peer's DH Offer File <input type="text" name="peer_offer" placeholder="e.g. bob_dh_offer.json" required></label>
        <label>Peer's ElGamal Public Key File <input type="text" name="peer_pub" placeholder="e.g. bob_public.json" required></label>
        <button class="btn-amber" type="submit">Build Export Package</button>
      </form>
    </details>
  </div>

  <!-- Import -->
  <div class="card"><h2>📥 Import Vault (Module 4)</h2>
    <form method="POST" action="/import-vault">
      <label>Export Package File <input type="text" name="export_file" placeholder="e.g. alice_vault_export.json" required></label>
      <label>Sender's ElGamal Public Key <input type="text" name="sender_pub" placeholder="e.g. alice_public.json" required></label>
      <button class="btn-teal" type="submit">Import</button>
    </form>
    <p class="note">You will need your own DH offer generated first (Step 1 above).</p>
  </div>
</div>
{% endif %}
</body></html>
"""

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    creds = []
    if session.get("user") and session.get("pw"):
        try:
            creds = list_credentials(vault_path(), session["pw"])
        except Exception:
            creds = []
    return render_template_string(PAGE, creds=creds)

@app.route("/login", methods=["POST"])
def login():
    user = request.form["user"].strip()
    pw   = request.form["pw"]
    path = f"{user}_vault.json"
    if not os.path.exists(path):
        flash("Vault not found. Create one first.", "error")
        return redirect(url_for("index"))
    try:
        # Module 3: verify signature before opening
        pp = pub_path(user)
        if os.path.exists(pp):
            pub, p, a = load_public(pp)
            if pub:
                verify_and_open_vault(path, pub, p, a)
        list_credentials(path, pw)  # test password
        session["user"] = user
        session["pw"]   = pw
        flash(f"Welcome back, {user}! Vault signature verified ✓", "success")
    except PermissionError as e:
        flash(f"TAMPER DETECTED — {e}", "error")
    except Exception:
        flash("Wrong password or corrupted vault.", "error")
    return redirect(url_for("index"))

@app.route("/create", methods=["POST"])
def create():
    user = request.form["user"].strip()
    pw   = request.form["pw"]
    path = f"{user}_vault.json"
    if os.path.exists(path):
        flash("Vault already exists. Log in instead.", "error")
        return redirect(url_for("index"))
    try:
        # Module 2: create vault
        create_vault(path, pw)
        # Module 1: generate ElGamal keys
        pp = priv_path(user)
        if not os.path.exists(pp):
            bits = int(os.environ.get("KEY_SIZE", 512))
            q, a, pub, priv = generate_elgamal_params(bits)
            with open(pub_path(user), "w") as f:
                json.dump({"Prime": q, "Primitive Root": a, "publicKey": pub}, f, indent=4)
            with open(pp, "w") as f:
                json.dump({"Prime": q, "Primitive Root": a, "privateKey": priv}, f, indent=4)
        # Module 3: sign vault
        pk, p, alpha = load_private(pp)
        sign_and_save_vault(path, pk, p, alpha)
        session["user"] = user
        session["pw"]   = pw
        flash(f"Vault + ElGamal keys created for {user} ✓", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("index"))

@app.route("/add", methods=["POST"])
def add():
    try:
        add_credential(vault_path(), session["pw"],
                       request.form["site"], request.form["uname"], request.form["pword"])
        sign_vault_now()  # Module 3
        flash("Credential added & vault re-signed ✓", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("index"))

@app.route("/update", methods=["POST"])
def update():
    try:
        r = update_credential(vault_path(), session["pw"],
                              request.form["site"], request.form["uname"], request.form["new_pword"])
        if r is None:
            flash("Entry not found.", "error")
        else:
            sign_vault_now()  # Module 3
            flash("Password updated & vault re-signed ✓", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("index"))

@app.route("/delete", methods=["POST"])
def delete():
    try:
        r = delete_credential(vault_path(), session["pw"],
                              request.form["site"], request.form["uname"])
        if r is None:
            flash("Entry not found.", "error")
        else:
            sign_vault_now()  # Module 3
            flash("Credential deleted & vault re-signed ✓", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("index"))

# ── Module 4: Export ──────────────────────────────────────────────────────────
@app.route("/export-init", methods=["POST"])
def export_init():
    user = session["user"]
    try:
        q, alpha = load_or_generate_dh_params()
        dh_priv, dh_pub = generate_dh_keypair(q, alpha)
        with open(f"{user}_dh_priv.key", "w") as f:
            f.write(str(dh_priv))
        el_priv, el_q, el_alpha = load_private(priv_path())
        sig = sign_dh_public(dh_pub, el_priv, el_q, el_alpha)
        offer = {"dh_pub": hex(dh_pub), "signature": sig}
        with open(f"{user}_dh_offer.json", "w") as f:
            json.dump(offer, f, indent=2)
        flash(f"DH Offer saved → {user}_dh_offer.json ✓", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("index"))

@app.route("/export-finalize", methods=["POST"])
def export_finalize():
    user = session["user"]
    try:
        peer_offer_file = request.form["peer_offer"]
        peer_pub_file   = request.form["peer_pub"]
        q, alpha = load_or_generate_dh_params()
        with open(peer_offer_file) as f: peer_offer = json.load(f)
        peer_dh_pub = int(peer_offer["dh_pub"], 16)
        peer_sig    = peer_offer["signature"]
        peer_pub, peer_p, peer_a = load_public(peer_pub_file)
        if not verify_dh_public(peer_dh_pub, peer_sig, peer_pub, peer_p, peer_a):
            flash("Peer DH signature INVALID — aborting!", "error")
            return redirect(url_for("index"))
        with open(f"{user}_dh_priv.key") as f: dh_priv = int(f.read().strip())
        dh_pub = pow(alpha, dh_priv, q)
        el_priv, el_q, el_a = load_private(priv_path())
        el_pub, _, _ = load_public(pub_path())
        pkg = build_export_package(
            vault_path=vault_path(), master_password=session["pw"],
            my_dh_priv=dh_priv, my_dh_pub=dh_pub, peer_dh_pub=peer_dh_pub,
            my_elgamal_priv=el_priv, my_elgamal_pub=el_pub,
            q=q, alpha=alpha, elgamal_p=el_q, elgamal_alpha=el_a
        )
        out = f"{user}_vault_export.json"
        with open(out, "w") as f: json.dump(pkg, f, indent=2)
        flash(f"Export package saved → {out} ✓", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("index"))

@app.route("/import-vault", methods=["POST"])
def import_vault():
    user = session["user"]
    try:
        export_file    = request.form["export_file"]
        sender_pub_file = request.form["sender_pub"]
        q, alpha = load_or_generate_dh_params()
        with open(export_file) as f: pkg = json.load(f)
        with open(f"{user}_dh_priv.key") as f: dh_priv = int(f.read().strip())
        sender_pub, s_p, s_a = load_public(sender_pub_file)
        consume_export_package(
            package=pkg, my_dh_priv=dh_priv, peer_elgamal_pub=sender_pub,
            new_master_password=session["pw"], output_vault_path=vault_path(),
            q=q, alpha=alpha, peer_elgamal_p=s_p, peer_elgamal_alpha=s_a
        )
        sign_vault_now()  # re-sign with our own key
        flash("Vault imported & signed with your key ✓", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
