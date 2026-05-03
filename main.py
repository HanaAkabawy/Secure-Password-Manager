import sys
import getpass
import json
import os

from pwm.vault import (
    create_vault, add_credential, retrieve_credential,
    list_credentials, update_credential, delete_credential
)
from pwm.dh_export import (
    generate_dh_keypair, sign_dh_public, verify_dh_public,
    build_export_package, consume_export_package, load_dh_params, save_dh_params,
    generate_dh_params
)
from pwm.elgamal import init as generate_elgamal_params

# ── paths ────────────────────────────────────────────────────────────────────

def user_path(user, filename):
    d = os.path.join("users", user)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, filename)

def load_dh():
    path = "pwm/dh_params.json"
    if not os.path.exists(path):
        print("  Generating DH parameters (first run, one moment)...")
        q, alpha = generate_dh_params(512)
        os.makedirs("pwm", exist_ok=True)
        save_dh_params(q, alpha, path)
    return load_dh_params(path)

def load_pub(path):
    if not os.path.exists(path):
        return 0, 0, 0
    with open(path) as f:
        d = json.load(f)
    return d["publicKey"], d["Prime"], d["Primitive Root"]

def load_priv(path):
    if not os.path.exists(path):
        return 0, 0, 0
    with open(path) as f:
        d = json.load(f)
    return d["privateKey"], d["Prime"], d["Primitive Root"]

# ── display helpers ───────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def header(user=None):
    print()
    print("  --- Password Manager ---")
    if user:
        print(f"  Logged in as: {user}")
    print()

def pause():
    input("\n  Press Enter to continue...")

def ask(prompt):
    return input(f"  {prompt}").strip()

def secret(prompt):
    return getpass.getpass(f"  {prompt}")

def ok(msg):
    print(f"\n  [+] {msg}")

def err(msg):
    print(f"\n  [!] {msg}")

# ── menus ─────────────────────────────────────────────────────────────────────

MAIN_MENU = [
    ("Initialize new user",          "init_user"),
    ("Login",                        "login"),
    ("Exit",                         "exit"),
]

VAULT_MENU = [
    ("Add credential",               "add"),
    ("Get credential",               "get"),
    ("List all sites",               "list"),
    ("Update credential",            "update"),
    ("Delete credential",            "delete"),
    ("Export vault to another user", "export"),
    ("Import vault from a user",     "import_vault"),
    ("Logout",                       "logout"),
]

def print_menu(items):
    for i, (label, _) in enumerate(items, 1):
        print(f"  {i}) {label}")
    print()

def choose(items):
    print_menu(items)
    raw = ask("Choose an option: ")
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(items):
            return items[idx][1]
    err("Invalid option.")
    return None

# ── actions ───────────────────────────────────────────────────────────────────

def init_user():
    clear(); header()
    username = ask("Username: ")
    if not username:
        return
    path = user_path(username, "vault.json")
    if os.path.exists(path):
        err(f"User '{username}' already exists. Choose Login instead.")
        pause(); return

    pw = secret("Master Password: ")
    pw2 = secret("Confirm Password: ")
    if pw != pw2:
        err("Passwords do not match."); pause(); return

    create_vault(path, pw)
    ok(f"Vault created for '{username}'.")
    pause()


def login():
    clear(); header()
    username = ask("Username: ")
    if not username:
        return None, None
    path = user_path(username, "vault.json")
    if not os.path.exists(path):
        err(f"No vault found for '{username}'. Initialize first.")
        pause(); return None, None

    pw = secret("Master Password: ")
    try:
        list_credentials(path, pw)
        ok(f"Welcome back, {username}!")
        pause()
        return username, pw
    except Exception:
        err("Wrong password or corrupted vault.")
        pause()
        return None, None


def do_add(user, pw):
    clear(); header(user)
    print("  -- Add Credential --\n")
    site  = ask("Site/App name : ")
    uname = ask("Username      : ")
    passw = secret("Password      : ")
    if not site or not uname or not passw:
        err("All fields required."); pause(); return
    add_credential(user_path(user, "vault.json"), pw, site, uname, passw)
    pause()


def do_get(user, pw):
    clear(); header(user)
    print("  -- Get Credential --\n")
    site = ask("Site/App name: ")
    matches = retrieve_credential(user_path(user, "vault.json"), pw, site)
    if not matches:
        err(f"No credentials found for '{site}'.")
    else:
        print()
        for m in matches:
            print(f"  Site     : {m['website']}")
            print(f"  Username : {m['username']}")
            print(f"  Password : {m['password']}")
            print()
    pause()


def do_list(user, pw):
    clear(); header(user)
    print("  -- All Credentials --\n")
    creds = list_credentials(user_path(user, "vault.json"), pw)
    if not creds:
        print("  Vault is empty.")
    else:
        width = max(len(c["website"]) for c in creds)
        print(f"  {'Site':<{width}}   Username")
        print(f"  {'-'*width}   {'-'*20}")
        for c in creds:
            print(f"  {c['website']:<{width}}   {c['username']}")
    pause()


def do_update(user, pw):
    clear(); header(user)
    print("  -- Update Credential --\n")
    site  = ask("Site/App name    : ")
    uname = ask("Username         : ")
    passw = secret("New Password     : ")
    update_credential(user_path(user, "vault.json"), pw, site, uname, passw)
    pause()


def do_delete(user, pw):
    clear(); header(user)
    print("  -- Delete Credential --\n")
    site  = ask("Site/App name: ")
    uname = ask("Username     : ")
    confirm = ask(f"Delete '{site}' / '{uname}'? (yes/no): ")
    if confirm.lower() != "yes":
        print("  Cancelled."); pause(); return
    delete_credential(user_path(user, "vault.json"), pw, site, uname)
    pause()


def ensure_elgamal(user):
    pub_path  = user_path(user, "elgamal_pub.json")
    priv_path = user_path(user, "elgamal_priv.json")
    if not os.path.exists(priv_path):
        print("  Generating ElGamal keys (one moment)...")
        bits = int(os.environ.get("TEST_KEY_SIZE", 1024))
        q, a, pub, priv = generate_elgamal_params(bits)
        with open(pub_path, "w") as f:
            json.dump({"Prime": q, "Primitive Root": a, "publicKey": pub}, f, indent=4)
        with open(priv_path, "w") as f:
            json.dump({"Prime": q, "Primitive Root": a, "privateKey": priv}, f, indent=4)
    return pub_path, priv_path


def do_export(user, pw):
    clear(); header(user)
    print("  -- Export Vault --\n")
    peer = ask("Recipient username: ")
    if not peer:
        pause(); return

    pub_path, priv_path = ensure_elgamal(user)
    q, alpha = load_dh()

    dh_priv, dh_pub = generate_dh_keypair(q, alpha)
    with open(user_path(user, "dh_priv.key"), "w") as f:
        f.write(str(dh_priv))

    elgamal_priv, el_q, el_alpha = load_priv(priv_path)
    elgamal_pub, _, _ = load_pub(pub_path)
    sig = sign_dh_public(dh_pub, elgamal_priv, el_q, el_alpha)

    offer = {"dh_pub": hex(dh_pub), "signature": sig}
    with open(user_path(user, "dh_offer.json"), "w") as f:
        json.dump(offer, f, indent=2)
    ok(f"DH offer saved to users/{user}/dh_offer.json")
    print(f"  Share your ElGamal public key and DH offer with '{peer}'.")
    print(f"  Then ask '{peer}' to run Export so they create their offer too.")

    peer_offer = user_path(peer, "dh_offer.json")
    peer_pub   = user_path(peer, "elgamal_pub.json")
    if not os.path.exists(peer_offer) or not os.path.exists(peer_pub):
        print(f"\n  Waiting: '{peer}' has not created their offer yet.")
        pause(); return

    with open(peer_offer) as f: po = json.load(f)
    peer_dh_pub = int(po["dh_pub"], 16)
    peer_sig    = po["signature"]
    peer_elgamal_pub, peer_el_q, peer_el_alpha = load_pub(peer_pub)

    if not verify_dh_public(peer_dh_pub, peer_sig, peer_elgamal_pub, peer_el_q, peer_el_alpha):
        err("Peer DH offer signature is INVALID. Aborting."); pause(); return

    try:
        pkg = build_export_package(
            vault_path=user_path(user, "vault.json"),
            master_password=pw,
            my_dh_priv=dh_priv,
            my_dh_pub=dh_pub,
            peer_dh_pub=peer_dh_pub,
            my_elgamal_priv=elgamal_priv,
            my_elgamal_pub=elgamal_pub,
            q=q, alpha=alpha,
            elgamal_p=el_q, elgamal_alpha=el_alpha
        )
        export_path = user_path(user, "vault_export.json")
        with open(export_path, "w") as f:
            json.dump(pkg, f, indent=2)
        ok(f"Export package ready at users/{user}/vault_export.json")
        print(f"  Send this file to '{peer}' for import.")
    except Exception as e:
        err(f"Export failed: {e}")
    pause()


def do_import(user, pw):
    clear(); header(user)
    print("  -- Import Vault --\n")
    sender = ask("Sender username: ")
    if not sender:
        pause(); return

    export_file = user_path(sender, "vault_export.json")
    sender_pub  = user_path(sender, "elgamal_pub.json")
    dh_priv_file = user_path(user, "dh_priv.key")

    for f in [export_file, sender_pub, dh_priv_file]:
        if not os.path.exists(f):
            err(f"Missing file: {f}"); pause(); return

    q, alpha = load_dh()
    with open(export_file) as f: pkg = json.load(f)
    with open(dh_priv_file) as f: dh_priv = int(f.read().strip())
    peer_elgamal_pub, peer_el_q, peer_el_alpha = load_pub(sender_pub)

    try:
        consume_export_package(
            package=pkg,
            my_dh_priv=dh_priv,
            peer_elgamal_pub=peer_elgamal_pub,
            new_master_password=pw,
            output_vault_path=user_path(user, "vault.json"),
            q=q, alpha=alpha,
            peer_elgamal_p=peer_el_q,
            peer_elgamal_alpha=peer_el_alpha
        )
        ok("Vault imported successfully.")
    except Exception as e:
        err(f"Import failed: {e}")
    pause()

# ── main loop ─────────────────────────────────────────────────────────────────

def main():
    current_user = None
    current_pw   = None

    while True:
        clear()
        header(current_user)

        if current_user is None:
            action = choose(MAIN_MENU)
            if action == "init_user":
                init_user()
            elif action == "login":
                current_user, current_pw = login()
            elif action == "exit":
                print("\n  Goodbye.\n")
                sys.exit(0)
        else:
            action = choose(VAULT_MENU)
            if action == "add":
                do_add(current_user, current_pw)
            elif action == "get":
                do_get(current_user, current_pw)
            elif action == "list":
                do_list(current_user, current_pw)
            elif action == "update":
                do_update(current_user, current_pw)
            elif action == "delete":
                do_delete(current_user, current_pw)
            elif action == "export":
                do_export(current_user, current_pw)
            elif action == "import_vault":
                do_import(current_user, current_pw)
            elif action == "logout":
                print(f"\n  Logged out of '{current_user}'.")
                current_user = None
                current_pw   = None
                pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Goodbye.\n")
        sys.exit(0)
