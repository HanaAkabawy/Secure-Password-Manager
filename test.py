import sys
import getpass
from vault import (
    create_vault, add_credential, retrieve_credential, 
    list_credentials, update_credential, delete_credential
)

def get_password():
    return getpass.getpass("Enter Master Password: ")

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py [create-vault|add|get|list|update|delete] [arguments]")
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

        else:
            print(f"Unknown command: {command}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()