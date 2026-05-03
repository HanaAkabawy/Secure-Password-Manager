
import sys
import argparse
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
from pwm.elgamal import init as generate_elgamal_params

def get_password():
    return getpass.getpass("Enter Master Password: ")

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

def handle_create_vault(args):
    path = f"{args.user}_vault.json"
    pw = get_password()
    create_vault(path, pw)
    print(f"Vault created for {args.user} at {path}")

def handle_add(args):
    path = f"{args.user}_vault.json"
    pw = get_password()
    add_credential(path, pw, args.site, args.username, args.password)

def handle_get(args):
    path = f"{args.user}_vault.json"
    pw = get_password()
    matches = retrieve_credential(path, pw, args.site)
    if not matches:
        print(f"No credentials found for site: {args.site}")
    for m in matches:
        print(f"Site: {m['website']} | User: {m['username']} | Pass: {m['password']}")

def handle_list(args):
    path = f"{args.user}_vault.json"
    pw = get_password()
    all_creds = list_credentials(path, pw)
    print(f"\n--- {args.user.capitalize()}'s Vault ---")
    if not all_creds:
        print("Vault is empty.")
    for c in all_creds:
        print(f"[{c['website']}] {c['username']}: {c['password']}")

def handle_update(args):
    path = f"{args.user}_vault.json"
    pw = get_password()
    update_credential(path, pw, args.site, args.username, args.new_password)

def handle_delete(args):
    path = f"{args.user}_vault.json"
    pw = get_password()
    delete_credential(path, pw, args.site, args.username)

def handle_export_init(args):
    user = args.user
    elgamal_priv_path = f"{user}_elgamal_priv.json"
    elgamal_pub_path = f"{user}_elgamal_pub.json"
    
    if not os.path.exists(elgamal_priv_path):
        bits = int(os.environ.get("TEST_KEY_SIZE", 1024))
        q_el, a_el, pub, priv = generate_elgamal_params(bits)
        with open(elgamal_pub_path, "w") as f:
            json.dump({"Prime": q_el, "Primitive Root": a_el, "publicKey": pub}, f, indent=4)
        with open(elgamal_priv_path, "w") as f:
            json.dump({"Prime": q_el, "Primitive Root": a_el, "privateKey": priv}, f, indent=4)
    
    q, alpha = load_or_generate_dh_params()
    dh_priv, dh_pub = generate_dh_keypair(q, alpha)
    
    with open(f"{user}_dh_priv.key", "w") as f:
        f.write(str(dh_priv))
    
    elgamal_priv, el_q, el_alpha = load_private(elgamal_priv_path)
    sig = sign_dh_public(dh_pub, elgamal_priv, el_q, el_alpha)
    
    offer = {
        "dh_pub": hex(dh_pub),
        "signature": sig
    }
    offer_path = f"{user}_dh_offer.json"
    with open(offer_path, "w") as f:
        json.dump(offer, f, indent=2)
    print(f"DH Offer generated for {user} at {offer_path}")

def handle_export_finalize(args):
    user = args.user
    peer_offer_file = args.peer_offer_file
    peer_elgamal_pub_file = args.peer_elgamal_pub_file
    
    vault_path = f"{user}_vault.json"
    elgamal_priv_path = f"{user}_elgamal_priv.json"
    elgamal_pub_path = f"{user}_elgamal_pub.json"
    dh_priv_path = f"{user}_dh_priv.key"
    
    if not os.path.exists(vault_path):
        print(f"Error: Vault {vault_path} not found.")
        return
    if not os.path.exists(peer_offer_file):
        print(f"Error: Peer offer file {peer_offer_file} not found.")
        return
        
    q, alpha = load_or_generate_dh_params()
    
    with open(peer_offer_file) as f: peer_offer = json.load(f)
    peer_dh_pub = int(peer_offer["dh_pub"], 16)
    peer_sig = peer_offer["signature"]
    
    peer_elgamal_pub, peer_el_q, peer_el_alpha = load_public(peer_elgamal_pub_file)
    
    if not verify_dh_public(peer_dh_pub, peer_sig, peer_elgamal_pub, peer_el_q, peer_el_alpha):
        print("Peer DH offer signature is INVALID. Aborting.")
        return
        
    with open(dh_priv_path) as f: dh_priv = int(f.read().strip())
    
    dh_pub = pow(alpha, dh_priv, q)
    elgamal_priv, el_q, el_alpha = load_private(elgamal_priv_path)
    elgamal_pub, _, _ = load_public(elgamal_pub_path)
    
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
        alpha=alpha,
        elgamal_p=el_q,
        elgamal_alpha=el_alpha
    )
    
    export_path = f"{user}_vault_export.json"
    with open(export_path, "w") as f:
        json.dump(pkg, f, indent=2)
    print(f"Export package created: {export_path}")

def handle_import(args):
    user = args.user
    export_file = args.export_file
    sender_elgamal_pub_file = args.sender_elgamal_pub_file
    
    dh_priv_path = f"{user}_dh_priv.key"
    out_vault_path = f"{user}_vault.json"
    
    if not os.path.exists(export_file):
        print(f"Error: Export package {export_file} not found.")
        return
        
    q, alpha = load_or_generate_dh_params()
    
    with open(export_file) as f: pkg = json.load(f)
    with open(dh_priv_path) as f: dh_priv = int(f.read().strip())
    
    sender_elgamal_pub, peer_el_q, peer_el_alpha = load_public(sender_elgamal_pub_file)
    
    print(f"Importing vault. You will define a new password for the local copy.")
    pw = get_password()
    
    consume_export_package(
        package=pkg,
        my_dh_priv=dh_priv,
        peer_elgamal_pub=sender_elgamal_pub,
        new_master_password=pw,
        output_vault_path=out_vault_path,
        q=q,
        alpha=alpha,
        peer_elgamal_p=peer_el_q,
        peer_elgamal_alpha=peer_el_alpha
    )
    print(f"Vault successfully imported to {out_vault_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Secure Password Manager CLI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)
    
    # create-vault
    parser_create = subparsers.add_parser("create-vault", help="Create a new encrypted password vault")
    parser_create.add_argument("user", help="Username for the vault owner")
    parser_create.set_defaults(func=handle_create_vault)
    
    # add
    parser_add = subparsers.add_parser("add", help="Add a new credential to the vault")
    parser_add.add_argument("user", help="Username of the vault owner")
    parser_add.add_argument("site", help="Website or Service name")
    parser_add.add_argument("username", help="Login username for the site")
    parser_add.add_argument("password", help="Password for the site")
    parser_add.set_defaults(func=handle_add)
    
    # get
    parser_get = subparsers.add_parser("get", help="Retrieve credentials for a specific site")
    parser_get.add_argument("user", help="Username of the vault owner")
    parser_get.add_argument("site", help="Website or Service name to retrieve")
    parser_get.set_defaults(func=handle_get)
    
    # list
    parser_list = subparsers.add_parser("list", help="List all credentials in the vault")
    parser_list.add_argument("user", help="Username of the vault owner")
    parser_list.set_defaults(func=handle_list)
    
    # update
    parser_update = subparsers.add_parser("update", help="Update an existing credential")
    parser_update.add_argument("user", help="Username of the vault owner")
    parser_update.add_argument("site", help="Website or Service name")
    parser_update.add_argument("username", help="Login username for the site")
    parser_update.add_argument("new_password", help="New password to store")
    parser_update.set_defaults(func=handle_update)
    
    # delete
    parser_delete = subparsers.add_parser("delete", help="Delete a credential from the vault")
    parser_delete.add_argument("user", help="Username of the vault owner")
    parser_delete.add_argument("site", help="Website or Service name")
    parser_delete.add_argument("username", help="Login username for the site")
    parser_delete.set_defaults(func=handle_delete)
    
    # export-init
    parser_export_init = subparsers.add_parser("export-init", help="Phase 1: Generate DH keys and create a signed offer")
    parser_export_init.add_argument("user", help="Username of the vault owner")
    parser_export_init.set_defaults(func=handle_export_init)
    
    # export-finalize
    parser_export_finalize = subparsers.add_parser("export-finalize", help="Phase 2: Verify peer's offer and build export package")
    parser_export_finalize.add_argument("user", help="Username of the vault owner")
    parser_export_finalize.add_argument("peer_offer_file", help="Path to peer's DH offer JSON file")
    parser_export_finalize.add_argument("peer_elgamal_pub_file", help="Path to peer's ElGamal public key JSON file")
    parser_export_finalize.set_defaults(func=handle_export_finalize)
    
    # import
    parser_import = subparsers.add_parser("import", help="Phase 3: Verify and import a received vault package")
    parser_import.add_argument("user", help="Username of the vault owner receiving the package")
    parser_import.add_argument("export_file", help="Path to the exported vault package JSON file")
    parser_import.add_argument("sender_elgamal_pub_file", help="Path to the sender's ElGamal public key JSON file")
    parser_import.set_defaults(func=handle_import)

    try:
        args = parser.parse_args()
        args.func(args)
    except Exception as e:
        print(f"\n[!] Error executing command: {e}")

if __name__ == "__main__":
    main()
