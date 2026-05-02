import sys
import os
import getpass
import json

# Add parent directory to path to import main
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import main

# Mock getpass to return a fixed password based on the user
def mock_getpass(prompt=""):
    if "alice" in sys.argv:
        return "alice_pass"
    elif "bob" in sys.argv:
        return "bob_pass"
    return "password123"

getpass.getpass = mock_getpass

def run_command(*args):
    print(f"\n--- Running: python main.py {' '.join(args)} ---")
    sys.argv = ['main.py'] + list(args)
    os.environ["TEST_KEY_SIZE"] = "256"
    main.main()

def cleanup():
    files_to_remove = [
        "alice_vault.json", "alice_elgamal_pub.json", "alice_elgamal_priv.json",
        "alice_dh_priv.key", "alice_dh_offer.json", "alice_vault_export.json",
        "bob_vault.json", "bob_elgamal_pub.json", "bob_elgamal_priv.json",
        "bob_dh_priv.key", "bob_dh_offer.json", "pwm/dh_params.json"
    ]
    for f in files_to_remove:
        if os.path.exists(f):
            os.remove(f)

def test_e2e():
    cleanup()
    
    print("=== STARTING END TO END TEST ===")
    
    # 1. Alice creates vault and adds credentials
    run_command("create-vault", "alice")
    run_command("add", "alice", "facebook.com", "alice_fb", "fb_secret")
    run_command("add", "alice", "gmail.com", "alice_mail", "mail_secret")
    
    # 2. Bob creates a vault
    run_command("create-vault", "bob")
    
    # 3. Alice initiates export (generates DH offer)
    run_command("export-init", "alice")
    
    # 4. Bob initiates export (generates DH offer to trade)
    run_command("export-init", "bob")
    
    # 5. Alice finalizes export (reads Bob's offer, creates export package)
    run_command("export-finalize", "alice", "bob_dh_offer.json", "bob_elgamal_pub.json")
    
    # 6. Bob imports Alice's vault
    run_command("import", "bob", "alice_vault_export.json", "alice_elgamal_pub.json")
    
    # 7. Bob lists credentials to verify
    print("\n--- Verifying Bob's Imported Vault ---")
    with open("bob_vault.json") as f:
        print(f"Bob's vault structure: {list(json.load(f).keys())}")
    
    run_command("list", "bob")
    
    print("\n=== E2E TEST COMPLETED SUCCESSFULLY ===")
    cleanup()

if __name__ == "__main__":
    test_e2e()
