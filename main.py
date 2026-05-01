import sys
import getpass
import json
import os
from pwm.vault import (
    create_vault, add_credential, retrieve_credential, 
    list_credentials, update_credential, delete_credential
)
from pwm.dh_export import (
    generate_dh_params, generate_dh_keypair, sign_dh_public, verify_dh_public,
    build_export_package, consume_export_package, load_dh_params, save_dh_params
)
from pwm._mock_elgamal import load_public, load_private, generate_keypair

def get_password():
    return getpass.getpass("Enter Master Password: ")

def load_or_generate_dh_params():
    if not os.path.exists("pwm/dh_params.json"):
        print("Generating DH params (512-bit for testing)...")
        q, alpha = generate_dh_params(512)
        if not os.path.exists("pwm"): os.makedirs("pwm")
        save_dh_params(q, alpha, "pwm/dh_params.json")
    return load_dh_params("pwm/dh_params.json")

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py [create-vault|add|get|list|update|delete|export-init|export-finalize|import] [arguments]")
        return

    command = sys.argv[1]

    try:
        if command == "create-vault":
            user = sys.argv[2]
            path = f"{user}_vault.json"
            pw = get_password()
            create_vault(path, pw)
            print(f"Vault created for {user} at {path}")

        elif command == "add":
            user, site, uname, pword = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
            path = f"{user}_vault.json"
            pw = get_password()
            add_credential(path, pw, site, uname, pword)

        elif command == "get":
            user, site = sys.argv[2], sys.argv[3]
            path = f"{user}_vault.json"
            pw = get_password()
            matches = retrieve_credential(path, pw, site)
            for m in matches:
                print(f"Site: {m['website']} | User: {m['username']} | Pass: {m['password']}")

        elif command == "list":
            user = sys.argv[2]
            path = f"{user}_vault.json"
            pw = get_password()
            all_creds = list_credentials(path, pw)
            print(f"\n--- {user.capitalize()}'s Vault ---")
            for c in all_creds:
                print(f"[{c['website']}] {c['username']}: {c['password']}")

        elif command == "update":
            user, site, uname, new_pword = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
            path = f"{user}_vault.json"
            pw = get_password()
            update_credential(path, pw, site, uname, new_pword)

        elif command == "delete":
            user, site, uname = sys.argv[2], sys.argv[3], sys.argv[4]
            path = f"{user}_vault.json"
            pw = get_password()
            delete_credential(path, pw, site, uname)

        elif command == "export-init":
            user = sys.argv[2]
            elgamal_priv_path = f"{user}_elgamal_priv.key"
            if not os.path.exists(elgamal_priv_path):
                pub, priv = generate_keypair()
                with open(f"{user}_elgamal_pub.key", "w") as f: f.write(pub)
                with open(elgamal_priv_path, "w") as f: f.write(priv)
            
            q, alpha = load_or_generate_dh_params()
            dh_priv, dh_pub = generate_dh_keypair(q, alpha)
            
            # Save ephemeral private key locally
            with open(f"{user}_dh_priv.key", "w") as f:
                f.write(str(dh_priv))
            
            elgamal_priv = load_private(elgamal_priv_path)
            sig = sign_dh_public(dh_pub, elgamal_priv)
            
            offer = {
                "dh_pub": hex(dh_pub),
                "signature": sig.hex()
            }
            with open(f"{user}_dh_offer.json", "w") as f:
                json.dump(offer, f, indent=2)
            print(f"DH Offer generated for {user} at {user}_dh_offer.json")

        elif command == "export-finalize":
            user = sys.argv[2]
            peer_offer_file = sys.argv[3]
            peer_elgamal_pub_file = sys.argv[4]
            
            vault_path = f"{user}_vault.json"
            elgamal_priv_path = f"{user}_elgamal_priv.key"
            elgamal_pub_path = f"{user}_elgamal_pub.key"
            dh_priv_path = f"{user}_dh_priv.key"
            
            with open(peer_offer_file) as f: peer_offer = json.load(f)
            peer_dh_pub = int(peer_offer["dh_pub"], 16)
            peer_sig = bytes.fromhex(peer_offer["signature"])
            
            peer_elgamal_pub = load_public(peer_elgamal_pub_file)
            
            if not verify_dh_public(peer_dh_pub, peer_sig, peer_elgamal_pub):
                print("Peer DH offer signature is INVALID. Aborting.")
                return
                
            q, alpha = load_or_generate_dh_params()
            with open(dh_priv_path) as f: dh_priv = int(f.read().strip())
            
            # Compute our own DH public to include in package
            dh_pub = pow(alpha, dh_priv, q)
            elgamal_priv = load_private(elgamal_priv_path)
            elgamal_pub = load_public(elgamal_pub_path)
            
            pw = get_password()
            
            pkg = build_export_package(
                vault_path=vault_path,
                master_password=pw,
                my_dh_priv=dh_priv,
                my_dh_pub=dh_pub,
                peer_dh_pub=peer_dh_pub,
                my_elgamal_priv=elgamal_priv,
                my_elgamal_pub=elgamal_pub,
                q=q,
                alpha=alpha
            )
            with open(f"{user}_vault_export.json", "w") as f:
                json.dump(pkg, f, indent=2)
            print(f"Export package created: {user}_vault_export.json")

        elif command == "import":
            user = sys.argv[2]
            export_file = sys.argv[3]
            sender_elgamal_pub_file = sys.argv[4]
            
            elgamal_priv_path = f"{user}_elgamal_priv.key"
            dh_priv_path = f"{user}_dh_priv.key"
            out_vault_path = f"{user}_vault.json"
            
            q, alpha = load_or_generate_dh_params()
            
            with open(export_file) as f: pkg = json.load(f)
            with open(dh_priv_path) as f: dh_priv = int(f.read().strip())
            
            sender_elgamal_pub = load_public(sender_elgamal_pub_file)
            elgamal_priv = load_private(elgamal_priv_path)
            
            print(f"Importing vault. You will define a new password for the local copy.")
            pw = get_password()
            
            consume_export_package(
                package=pkg,
                my_dh_priv=dh_priv,
                peer_elgamal_pub=sender_elgamal_pub,
                new_master_password=pw,
                output_vault_path=out_vault_path,
                my_elgamal_priv=elgamal_priv,
                q=q
            )
            print(f"Vault successfully imported to {out_vault_path}")

        else:
            print(f"Unknown command: {command}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()