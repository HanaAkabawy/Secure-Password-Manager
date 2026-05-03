import sys
import getpass
import json
import os
import cmd
import shlex

from pwm.vault import (
    create_vault, add_credential, retrieve_credential, 
    list_credentials, update_credential, delete_credential
)
from pwm.dh_export import (
    generate_dh_params, generate_dh_keypair, sign_dh_public, verify_dh_public,
    build_export_package, consume_export_package, load_dh_params, save_dh_params
)
from pwm.elgamal import init as generate_elgamal_params

# Helper for organized file structure
def get_user_path(user, filename):
    user_dir = os.path.join("users", user)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    return os.path.join(user_dir, filename)

def load_or_generate_dh_params():
    if not os.path.exists("pwm/dh_params.json"):
        print("Generating DH params (512-bit for testing)...")
        q, alpha = generate_dh_params(512)
        if not os.path.exists("pwm"): os.makedirs("pwm")
        save_dh_params(q, alpha, "pwm/dh_params.json")
    return load_dh_params("pwm/dh_params.json")

def load_public(path):
    if not os.path.exists(path): return 0, 0, 0
    with open(path, "r") as f:
        data = json.load(f)
        return data["publicKey"], data["Prime"], data["Primitive Root"]

def load_private(path):
    if not os.path.exists(path): return 0, 0, 0
    with open(path, "r") as f:
        data = json.load(f)
        return data["privateKey"], data["Prime"], data["Primitive Root"]

class PWMConsole(cmd.Cmd):
    intro = "\n=== Welcome to Secure Password Manager ===\nType 'help' or '?' to list commands.\nType 'login <user>' to sign in, or 'create_vault <user>' to make a new one.\nType 'exit' to quit.\n"
    
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.current_password = None
        self.update_prompt()

    def update_prompt(self):
        if self.current_user:
            self.prompt = f"(PWM - {self.current_user}) > "
        else:
            self.prompt = "(PWM - Not Logged In) > "

    def require_login(self):
        if not self.current_user or not self.current_password:
            print("[-] You must be logged in to use this command. Type 'login <user>'.")
            return False
        return True

    def do_login(self, arg):
        """Sign in to your vault.\nUsage: login <user>"""
        args = shlex.split(arg)
        if len(args) != 1:
            print("Usage: login <user>")
            return
        user = args[0]
        path = get_user_path(user, "vault.json")
        
        if not os.path.exists(path):
            print(f"[-] Vault for '{user}' does not exist. Use 'create_vault {user}' first.")
            return
            
        pw = getpass.getpass(f"Enter Master Password for {user}: ")
        
        try:
            list_credentials(path, pw)
            self.current_user = user
            self.current_password = pw
            self.update_prompt()
            print(f"[+] Successfully logged in as {user}")
        except Exception:
            print("[-] Invalid password or corrupted vault.")

    def do_logout(self, arg):
        """Sign out of the current session.\nUsage: logout"""
        if self.current_user:
            print(f"[+] Logged out of {self.current_user}")
            self.current_user = None
            self.current_password = None
            self.update_prompt()
        else:
            print("[-] You are not logged in.")

    def do_create_vault(self, arg):
        """Create a new encrypted password vault.\nUsage: create_vault <user>"""
        args = shlex.split(arg)
        if len(args) != 1:
            print("Usage: create_vault <user>")
            return
        user = args[0]
        path = get_user_path(user, "vault.json")
        
        if os.path.exists(path):
            print(f"[-] Vault for '{user}' already exists. Please 'login {user}'.")
            return
            
        pw = getpass.getpass("Create Master Password: ")
        pw2 = getpass.getpass("Confirm Master Password: ")
        if pw != pw2:
            print("[-] Passwords do not match.")
            return
            
        create_vault(path, pw)
        print(f"[+] Vault created for {user} at {path}")
        
        self.current_user = user
        self.current_password = pw
        self.update_prompt()
        print(f"[+] Automatically logged in as {user}")

    def do_add(self, arg):
        """Add a new credential to the vault.\nUsage: add <site> <username> <password>"""
        if not self.require_login(): return
        args = shlex.split(arg)
        if len(args) != 3:
            print("Usage: add <site> <username> <password>")
            return
        site, uname, pword = args
        path = get_user_path(self.current_user, "vault.json")
        add_credential(path, self.current_password, site, uname, pword)

    def do_get(self, arg):
        """Retrieve credentials for a specific site.\nUsage: get <site>"""
        if not self.require_login(): return
        args = shlex.split(arg)
        if len(args) != 1:
            print("Usage: get <site>")
            return
        site = args[0]
        path = get_user_path(self.current_user, "vault.json")
        try:
            matches = retrieve_credential(path, self.current_password, site)
            if not matches:
                print(f"[-] No credentials found for site: {site}")
            for m in matches:
                print(f"[+] Site: {m['website']} | User: {m['username']} | Pass: {m['password']}")
        except Exception as e:
            print(f"Error: {e}")

    def do_list(self, arg):
        """List all credentials in the vault.\nUsage: list"""
        if not self.require_login(): return
        path = get_user_path(self.current_user, "vault.json")
        try:
            all_creds = list_credentials(path, self.current_password)
            print(f"\n--- {self.current_user.capitalize()}'s Vault ---")
            if not all_creds:
                print("Vault is empty.")
            for c in all_creds:
                print(f"[{c['website']}] {c['username']}: {c['password']}")
        except Exception as e:
            print(f"Error: {e}")

    def do_update(self, arg):
        """Update an existing credential.\nUsage: update <site> <username> <new_password>"""
        if not self.require_login(): return
        args = shlex.split(arg)
        if len(args) != 3:
            print("Usage: update <site> <username> <new_password>")
            return
        site, uname, new_pword = args
        path = get_user_path(self.current_user, "vault.json")
        update_credential(path, self.current_password, site, uname, new_pword)

    def do_delete(self, arg):
        """Delete a credential from the vault.\nUsage: delete <site> <username>"""
        if not self.require_login(): return
        args = shlex.split(arg)
        if len(args) != 2:
            print("Usage: delete <site> <username>")
            return
        site, uname = args
        path = get_user_path(self.current_user, "vault.json")
        delete_credential(path, self.current_password, site, uname)

    def do_export_init(self, arg):
        """Phase 1: Generate DH keys and create a signed offer.\nUsage: export_init"""
        if not self.require_login(): return
        user = self.current_user
        
        elgamal_priv_path = get_user_path(user, "elgamal_priv.json")
        elgamal_pub_path = get_user_path(user, "elgamal_pub.json")
        
        if not os.path.exists(elgamal_priv_path):
            print("[*] Generating ElGamal keys (this may take a moment)...")
            bits = int(os.environ.get("TEST_KEY_SIZE", 1024))
            q_el, a_el, pub, priv = generate_elgamal_params(bits)
            with open(elgamal_pub_path, "w") as f:
                json.dump({"Prime": q_el, "Primitive Root": a_el, "publicKey": pub}, f, indent=4)
            with open(elgamal_priv_path, "w") as f:
                json.dump({"Prime": q_el, "Primitive Root": a_el, "privateKey": priv}, f, indent=4)
        
        q, alpha = load_or_generate_dh_params()
        dh_priv, dh_pub = generate_dh_keypair(q, alpha)
        
        with open(get_user_path(user, "dh_priv.key"), "w") as f:
            f.write(str(dh_priv))
        
        elgamal_priv, el_q, el_alpha = load_private(elgamal_priv_path)
        sig = sign_dh_public(dh_pub, elgamal_priv, el_q, el_alpha)
        
        offer = {
            "dh_pub": hex(dh_pub),
            "signature": sig
        }
        offer_path = get_user_path(user, "dh_offer.json")
        with open(offer_path, "w") as f:
            json.dump(offer, f, indent=2)
        print(f"[+] DH Offer generated at {offer_path}")

    def do_export_finalize(self, arg):
        """Phase 2: Verify peer's offer and build export package.\nUsage: export_finalize <peer_name>"""
        if not self.require_login(): return
        args = shlex.split(arg)
        if len(args) != 1:
            print("Usage: export_finalize <peer_name>")
            print("Example: export_finalize bob (will look for users/bob/dh_offer.json)")
            return
        peer_name = args[0]
        user = self.current_user
        
        peer_offer_file = get_user_path(peer_name, "dh_offer.json")
        peer_elgamal_pub_file = get_user_path(peer_name, "elgamal_pub.json")
        
        vault_path = get_user_path(user, "vault.json")
        elgamal_priv_path = get_user_path(user, "elgamal_priv.json")
        elgamal_pub_path = get_user_path(user, "elgamal_pub.json")
        dh_priv_path = get_user_path(user, "dh_priv.key")
        
        if not os.path.exists(peer_offer_file):
            print(f"Error: Peer offer file {peer_offer_file} not found.")
            return
            
        q, alpha = load_or_generate_dh_params()
        
        with open(peer_offer_file) as f: peer_offer = json.load(f)
        peer_dh_pub = int(peer_offer["dh_pub"], 16)
        peer_sig = peer_offer["signature"]
        
        peer_elgamal_pub, peer_el_q, peer_el_alpha = load_public(peer_elgamal_pub_file)
        
        try:
            if not verify_dh_public(peer_dh_pub, peer_sig, peer_elgamal_pub, peer_el_q, peer_el_alpha):
                print("[-] Peer DH offer signature is INVALID. Aborting.")
                return
        except Exception as e:
            print(f"[-] Verification Error: {e}")
            return
            
        with open(dh_priv_path) as f: dh_priv = int(f.read().strip())
        
        dh_pub = pow(alpha, dh_priv, q)
        elgamal_priv, el_q, el_alpha = load_private(elgamal_priv_path)
        elgamal_pub, _, _ = load_public(elgamal_pub_path)
        
        try:
            pkg = build_export_package(
                vault_path=vault_path,
                master_password=self.current_password,
                my_dh_priv=dh_priv,
                my_dh_pub=dh_pub,
                peer_dh_pub=peer_dh_pub,
                my_elgamal_priv=elgamal_priv,
                my_elgamal_pub=elgamal_pub,
                q=q,
                alpha=alpha,
                elgamal_p=el_q,
                elgamal_alpha=el_alpha
            )
            
            export_path = get_user_path(user, "vault_export.json")
            with open(export_path, "w") as f:
                json.dump(pkg, f, indent=2)
            print(f"[+] Export package created at {export_path}")
        except Exception as e:
            print(f"Error building package: {e}")

    def do_import_vault(self, arg):
        """Phase 3: Verify and import a received vault package.\nUsage: import_vault <sender_name>"""
        if not self.require_login(): return
        args = shlex.split(arg)
        if len(args) != 1:
            print("Usage: import_vault <sender_name>")
            print("Example: import_vault alice (will look for users/alice/vault_export.json)")
            return
        sender_name = args[0]
        user = self.current_user
        
        export_file = get_user_path(sender_name, "vault_export.json")
        sender_elgamal_pub_file = get_user_path(sender_name, "elgamal_pub.json")
        
        dh_priv_path = get_user_path(user, "dh_priv.key")
        out_vault_path = get_user_path(user, "vault.json")
        
        if not os.path.exists(export_file):
            print(f"Error: Export package {export_file} not found.")
            return
            
        q, alpha = load_or_generate_dh_params()
        
        with open(export_file) as f: pkg = json.load(f)
        with open(dh_priv_path) as f: dh_priv = int(f.read().strip())
        
        sender_elgamal_pub, peer_el_q, peer_el_alpha = load_public(sender_elgamal_pub_file)
        
        print(f"[*] Importing vault. You will define a new password for the local copy.")
        pw = get_password()
        
        try:
            consume_export_package(
                package=pkg,
                my_dh_priv=dh_priv,
                peer_elgamal_pub=sender_elgamal_pub,
                new_master_password=self.current_password,
                output_vault_path=out_vault_path,
                q=q,
                alpha=alpha,
                peer_elgamal_p=peer_el_q,
                peer_elgamal_alpha=peer_el_alpha
            )
            print(f"[+] Vault successfully imported & merged to {out_vault_path}")
        except Exception as e:
            print(f"[-] Import failed: {e}")

    def do_exit(self, arg):
        """Exit the Secure Password Manager."""
        print("Goodbye!")
        return True

    def do_EOF(self, arg):
        """Exit using Ctrl-D"""
        print("\nGoodbye!")
        return True

if __name__ == "__main__":
    try:
        PWMConsole().cmdloop()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)
